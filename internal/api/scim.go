package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/badoux/checkmail"
	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/ctxkey"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

const (
	scimBasePath          = "/scim/v2"
	scimResourceTypeUser  = "User"
	scimResourceTypeGroup = "Group"

	scimClaimSub           = "sub"
	scimClaimEmail         = "email"
	scimClaimEmailVerified = "email_verified"
)

var (
	errMissingSSOProvider = errors.New("scim: request has no SSO provider")

	scimRequestKey       = ctxkey.New[*http.Request]("scim_request")
	scimTokenKey         = ctxkey.New[*models.SCIMToken]("scim_token")
	scimGroupSnapshotKey = ctxkey.New[*scimGroupSnapshot]("scim_group_snapshot")

	scimUserSchemas = core.Schemas{
		core.NewSchema(core.SchemaUser).With(core.UserAttributes()...),
		core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...),
	}
	scimGroupSchemas = newSCIMGroupSchemas()

	scimUserCreateProjection = newSCIMUserCreateProjection()

	scimCommonSortKeys = map[string]models.SCIMSortKey{
		"id":                models.SCIMSortByID,
		"meta.created":      models.SCIMSortByCreatedAt,
		"meta.lastmodified": models.SCIMSortByUpdatedAt,
	}
)

type scimAuditEvent struct {
	actor      *models.User
	action     models.AuditAction
	providerID uuid.UUID
	traits     map[string]any
}

type scimLister[Row, Resource any] struct {
	schemas core.Schemas
	name    string
	find    func(*storage.Connection, uuid.UUID, models.SCIMQuery) ([]Row, int, error)
	render  func(*storage.Connection, uuid.UUID, []Row, protocol.Projection) ([]Resource, error)
}

func (l scimLister[Row, Resource]) list(ctx context.Context, db *storage.Connection, query *protocol.SearchRequest) ([]Resource, int, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return nil, 0, err
	}
	search, err := scimSearch(query, l.schemas, l.name)
	if err != nil {
		return nil, 0, err
	}
	rows, total, err := l.find(db, providerID, search)
	if err != nil {
		return nil, 0, err
	}
	resources, err := l.render(db, providerID, rows, protocol.ProjectionFrom(ctx))
	if err != nil {
		return nil, 0, err
	}
	return resources, total, nil
}

func scimRenderOne[Row, Resource any](render func([]Row) ([]Resource, error), row Row) (Resource, error) {
	var zero Resource
	resources, err := render([]Row{row})
	if err != nil {
		return zero, err
	}
	return resources[0], nil
}

type scimDocument struct {
	id        uuid.UUID
	resource  []byte
	createdAt time.Time
	updatedAt time.Time
}

func scimCompose[R core.Resource](r R, resourceType core.ResourceTypeName, location string, doc scimDocument) error {
	if err := json.Unmarshal(doc.resource, r); err != nil {
		return err
	}
	common := r.Common()
	common.ID = doc.id.String()
	common.Meta = scimMeta(resourceType, location+"/"+common.ID, doc.createdAt, doc.updatedAt)
	return nil
}

func (a *API) newSCIMServer(validate server.TokenValidator, limit func(http.Handler) http.Handler) *server.Server {
	requireToken := server.RequireBearerToken(validate)
	authenticate := func(next http.Handler) http.Handler {
		if limit != nil {
			next = limit(next)
		}
		return requireToken(next)
	}
	return server.New(scimBasePath,
		core.NewServiceProviderConfig().Filtering(protocol.DefaultLimits.MaxCount).Patching().Sorting().Versioning(),
		server.WithBaseURL(scimBaseURL(a.config)),
		server.ErrorHandler(scimLogError),
		server.WithResource(server.NewResource[*core.User](scimResourceTypeUser, "/Users", core.SchemaUser, scimUserSchemas.Base().Attributes...).
			WithExtension(core.SchemaEnterpriseUser, scimUserSchemas.Extensions()[0].Attributes...).
			WithRepository(&scimUserRepository{api: a})),
		server.WithResource(server.NewResource[*core.Group](scimResourceTypeGroup, "/Groups", core.SchemaGroup, scimGroupSchemas.Base().Attributes...).
			WithRepository(&scimGroupRepository{api: a})),
		server.WithAuthentication(core.NewOAuthBearerToken().AsPrimary(), authenticate),
	)
}

func newSCIMGroupSchemas() core.Schemas {
	attributes := core.GroupAttributes()
	for _, attribute := range attributes {
		for _, sub := range attribute.SubAttributes {
			switch sub.Name {
			case "type":
				sub.Suggesting(scimResourceTypeUser)
			case "$ref":
				sub.Referencing(scimResourceTypeUser)
			}
		}
	}
	return core.Schemas{core.NewSchema(core.SchemaGroup).With(attributes...)}
}

func newSCIMTokenValidator(db *storage.Connection) server.TokenValidator {
	return func(ctx context.Context, candidate string) (context.Context, error) {
		token, err := models.AuthenticateSCIMToken(db.WithContext(ctx), candidate)
		if models.IsNotFoundError(err) {
			return ctx, server.ErrInvalidToken
		}
		if err != nil {
			return ctx, err
		}
		return scimTokenKey.WithValue(ctx, token), nil
	}
}

func (a *API) withSCIMRequest(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	ctx := scimRequestKey.WithValue(req.Context(), req)
	return scimGroupSnapshotKey.WithValue(ctx, &scimGroupSnapshot{}), nil
}

func (a *API) auditSCIM(tx *storage.Connection, r *http.Request, event scimAuditEvent) error {
	return a.auditSCIMEvents(tx, r, []scimAuditEvent{event})
}

func (a *API) auditSCIMEvents(tx *storage.Connection, r *http.Request, events []scimAuditEvent) error {
	ipAddress := utilities.GetIPAddress(r)
	for _, event := range events {
		event.traits["sso_provider_id"] = event.providerID
		event.traits["outcome"] = "success"
		if err := models.NewAuditLogEntry(a.config.AuditLog, r, tx, event.actor, event.action, ipAddress, event.traits); err != nil {
			return err
		}
	}
	return nil
}

func scimBaseURL(config *conf.GlobalConfiguration) string {
	return strings.TrimRight(config.API.ExternalURL, "/") + scimBasePath
}

func scimLogError(r *http.Request, err error) {
	observability.GetLogEntry(r).Entry.WithError(err).Error("scim: request failed")
}

func scimSearch(query *protocol.SearchRequest, schemas core.Schemas, name string) (models.SCIMQuery, error) {
	search := models.SCIMQuery{Offset: query.Offset(), Limit: query.Count}
	if query.Filter != "" {
		criteria, err := protocol.Filter(schemas, query.Filter, scimEqFilter{name: name})
		if err != nil {
			return search, err
		}
		search.Filter = criteria
	}
	if query.SortBy == "" {
		return search, nil
	}
	parent, attribute, err := query.SortAttribute(schemas)
	if err != nil {
		return search, err
	}
	key := parent.Name
	if attribute != parent {
		key += "." + attribute.Name
	}
	lower := strings.ToLower(key)
	by, ok := scimCommonSortKeys[lower]
	if !ok && lower == strings.ToLower(name) {
		by, ok = models.SCIMSortByName, true
	}
	if !ok {
		return search, scimerrors.ErrInvalidValue(fmt.Sprintf(`"sortBy" must be one of "id", %q, "meta.created" or "meta.lastModified"`, name))
	}
	search.Order = models.SCIMOrder{By: by, Descending: query.Descending()}
	return search, nil
}

func scimEncode(resource core.Resource, drop ...string) ([]byte, error) {
	fields, err := core.NewObject(resource)
	if err != nil {
		return nil, err
	}
	for _, key := range drop {
		fields.Remove(key)
	}
	return json.Marshal(fields)
}

func scimTarget(ctx context.Context, id, version string) (models.SCIMTarget, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return models.SCIMTarget{}, err
	}
	resourceID, err := uuid.FromString(id)
	if err != nil {
		return models.SCIMTarget{}, errSCIMNotFound()
	}
	updatedAt, err := scimParseVersion(version)
	if err != nil {
		return models.SCIMTarget{}, err
	}
	return models.SCIMTarget{ProviderID: providerID, ID: resourceID, UpdatedAt: updatedAt}, nil
}

func scimProviderID(ctx context.Context) (uuid.UUID, error) {
	token := scimTokenKey.Value(ctx)
	if token == nil || token.SSOProviderID == uuid.Nil {
		return uuid.Nil, errMissingSSOProvider
	}
	return token.SSOProviderID, nil
}

func scimProviderType(providerID uuid.UUID) string {
	return "sso:" + providerID.String()
}

func scimRequest(ctx context.Context) (*http.Request, error) {
	r := scimRequestKey.Value(ctx)
	if r == nil {
		return nil, apierrors.NewInternalServerError("SCIM request missing from context")
	}
	return r.WithContext(ctx), nil
}

func scimMeta(resourceType core.ResourceTypeName, location string, created, updated time.Time) core.Meta {
	return core.Meta{
		ResourceType: resourceType,
		Created:      created.UTC(),
		LastModified: updated.UTC(),
		Location:     location,
		Version:      scimVersion(updated),
	}
}

func scimVersion(updatedAt time.Time) string {
	return `W/"` + strconv.FormatInt(updatedAt.UnixMicro(), 10) + `"`
}

func scimParseVersion(version string) (*time.Time, error) {
	if version == "" {
		return nil, nil
	}
	micros, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(version, `W/"`), `"`), 10, 64)
	if err != nil {
		return nil, errSCIMStale()
	}
	updatedAt := time.UnixMicro(micros)
	return &updatedAt, nil
}

func scimActor(r *http.Request) *models.User {
	prefix := ""
	if token := scimTokenKey.Value(r.Context()); token != nil {
		prefix = token.Prefix
	}
	return &models.User{Email: storage.NullString("scim:" + prefix)}
}

func scimMemberTraits(groupID, scimUserID uuid.UUID, userID *uuid.UUID) map[string]any {
	traits := map[string]any{
		"scim_group_id": groupID,
		"scim_user_id":  scimUserID,
	}
	if userID != nil {
		traits["user_id"] = *userID
	}
	return traits
}

type scimEqFilter struct {
	name string
}

func (f scimEqFilter) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (models.SCIMFilter, error) {
	text, isString := value.(string)
	isEquals := op == filter.OpEquals
	isTopLevel := attribute.Parent == nil
	if !isEquals || !isTopLevel || !isString {
		return f.unsupported()
	}
	switch attribute.Definition.Name {
	case f.name:
		return models.SCIMFilter{Name: &text}, nil
	case "externalId":
		return models.SCIMFilter{ExternalID: &text}, nil
	}
	return f.unsupported()
}

func (f scimEqFilter) Present(*protocol.Attribute) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f scimEqFilter) And(models.SCIMFilter, models.SCIMFilter) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f scimEqFilter) Or(models.SCIMFilter, models.SCIMFilter) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f scimEqFilter) Not(models.SCIMFilter) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f scimEqFilter) ValuePath(*protocol.Attribute, func() (models.SCIMFilter, error)) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f scimEqFilter) unsupported() (models.SCIMFilter, error) {
	return models.SCIMFilter{}, scimerrors.ErrInvalidFilter(fmt.Sprintf(`only "%s eq" and "externalId eq" filters are supported`, f.name))
}

type scimGroupRepository struct {
	api *API
}

type scimGroupSnapshot struct {
	version string
	members []uuid.UUID
}

func (s *scimGroupRepository) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.Group, int, error) {
	return scimLister[models.SCIMGroup, *core.Group]{
		schemas: scimGroupSchemas,
		name:    "displayName",
		find:    models.FindSCIMGroups,
		render:  s.render,
	}.list(ctx, s.api.db.WithContext(ctx), query)
}

func (s *scimGroupRepository) Read(ctx context.Context, id string) (*core.Group, error) {
	target, err := scimTarget(ctx, id, "")
	if err != nil {
		return nil, err
	}
	db := s.api.db.WithContext(ctx)
	row, err := models.FindSCIMGroup(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, scimError(err)
	}
	projection := protocol.ProjectionFrom(ctx)
	group, err := s.renderOne(db, target.ProviderID, row, projection)
	if err != nil {
		return nil, err
	}
	if snapshot := scimGroupSnapshotKey.Value(ctx); snapshot != nil && projection.Returns("members") {
		if snapshot.members, err = scimMemberIDs(group.Members); err != nil {
			return nil, err
		}
		snapshot.version = group.Meta.Version
	}
	return group, nil
}

func (s *scimGroupRepository) Create(ctx context.Context, group *core.Group) (*core.Group, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return nil, err
	}
	return s.save(ctx, group, func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, models.AuditAction, error) {
		row, err := models.CreateSCIMGroup(tx, providerID, resource)
		return row, models.SCIMGroupCreatedAction, err
	})
}

func (s *scimGroupRepository) Update(ctx context.Context, group *core.Group) (*core.Group, error) {
	target, err := scimTarget(ctx, group.ID, group.Meta.Version)
	if err != nil {
		return nil, err
	}
	merge := s.mergeable(ctx, group.Meta.Version)
	return s.save(ctx, group, func(tx *storage.Connection, resource []byte) (*models.SCIMGroup, models.AuditAction, error) {
		if merge {
			if row, err := models.LockUnchangedSCIMGroup(tx, target.ProviderID, target.ID, resource); err != nil || row != nil {
				return row, "", err
			}
		}
		row, changed, err := models.ReplaceSCIMGroupIfChanged(tx, target, resource)
		if !changed {
			return row, "", err
		}
		return row, models.SCIMGroupUpdatedAction, err
	})
}

func (s *scimGroupRepository) Delete(ctx context.Context, group *core.Group) error {
	target, err := scimTarget(ctx, group.ID, group.Meta.Version)
	if err != nil {
		return err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return err
	}
	return scimError(s.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		return s.delete(tx, r, target)
	}))
}

func (s *scimGroupRepository) save(ctx context.Context, group *core.Group, write func(*storage.Connection, []byte) (*models.SCIMGroup, models.AuditAction, error)) (*core.Group, error) {
	members, err := scimMemberIDs(group.Members)
	if err != nil {
		return nil, err
	}
	attributes := *group
	attributes.Members = nil
	resource, err := scimEncode(&attributes, "id", "meta", "members")
	if err != nil {
		return nil, err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	var row *models.SCIMGroup
	var change models.SCIMGroupMemberChange
	err = s.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		var action models.AuditAction
		var terr error
		if row, action, terr = write(tx, resource); terr != nil {
			return terr
		}
		if row, change, terr = s.memberReplacer(ctx, group.Meta.Version, action)(tx, row, members); terr != nil {
			return terr
		}
		events, terr := s.memberEvents(tx, r, row, change)
		if terr != nil {
			return terr
		}
		return s.api.auditSCIMEvents(tx, r, append(s.groupEvents(r, action, row, group.DisplayName), events...))
	})
	if err != nil {
		return nil, scimError(err)
	}
	return s.compose(*row, scimMembers(scimBaseURL(s.api.config), change.Members))
}

func (s *scimGroupRepository) memberReplacer(ctx context.Context, version string, action models.AuditAction) func(*storage.Connection, *models.SCIMGroup, []uuid.UUID) (*models.SCIMGroup, models.SCIMGroupMemberChange, error) {
	snapshot := scimGroupSnapshotKey.Value(ctx)
	if snapshot == nil || version == "" || snapshot.version != version {
		return models.ReplaceSCIMGroupMembers
	}
	return func(tx *storage.Connection, row *models.SCIMGroup, members []uuid.UUID) (*models.SCIMGroup, models.SCIMGroupMemberChange, error) {
		if action == "" && scimVersion(row.UpdatedAt) != snapshot.version && s.mergeable(ctx, version) {
			return models.MergeSCIMGroupMembers(tx, row, snapshot.members, members)
		}
		return models.ReplaceSCIMGroupMembersFrom(tx, row, snapshot.members, members)
	}
}

func (s *scimGroupRepository) mergeable(ctx context.Context, version string) bool {
	r := scimRequestKey.Value(ctx)
	snapshot := scimGroupSnapshotKey.Value(ctx)
	return r != nil && r.Method == http.MethodPatch && r.Header.Get("If-Match") == "" && snapshot != nil && version != "" && snapshot.version == version
}

func (s *scimGroupRepository) delete(tx *storage.Connection, r *http.Request, target models.SCIMTarget) error {
	removed, err := models.FindSCIMGroupMemberIDs(tx, target.ID)
	if err != nil {
		return err
	}
	row, err := models.DeleteSCIMGroup(tx, target)
	if err != nil {
		return err
	}
	var resource struct {
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(row.Resource, &resource); err != nil {
		return err
	}
	events, err := s.memberEvents(tx, r, row, models.SCIMGroupMemberChange{Removed: removed})
	if err != nil {
		return err
	}
	return s.api.auditSCIMEvents(tx, r, append(events, s.groupEvents(r, models.SCIMGroupDeletedAction, row, resource.DisplayName)...))
}

func (s *scimGroupRepository) render(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMGroup, projection protocol.Projection) ([]*core.Group, error) {
	members, err := s.members(tx, providerID, rows, projection)
	if err != nil {
		return nil, err
	}
	groups := make([]*core.Group, 0, len(rows))
	for _, row := range rows {
		group, err := s.compose(row, members[row.ID])
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (s *scimGroupRepository) renderOne(tx *storage.Connection, providerID uuid.UUID, row *models.SCIMGroup, projection protocol.Projection) (*core.Group, error) {
	return scimRenderOne(func(rows []models.SCIMGroup) ([]*core.Group, error) {
		return s.render(tx, providerID, rows, projection)
	}, *row)
}

func (s *scimGroupRepository) members(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMGroup, projection protocol.Projection) (map[uuid.UUID][]core.Member, error) {
	members := map[uuid.UUID][]core.Member{}
	if !projection.Returns("members") {
		return members, nil
	}
	ids := make([]uuid.UUID, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	memberships, err := models.FindSCIMMembershipsByGroup(tx, providerID, ids)
	if err != nil {
		return nil, err
	}
	counts := make(map[uuid.UUID]int, len(rows))
	for _, m := range memberships {
		counts[m.GroupID]++
	}
	base := scimBaseURL(s.api.config)
	for _, m := range memberships {
		if members[m.GroupID] == nil {
			members[m.GroupID] = make([]core.Member, 0, counts[m.GroupID])
		}
		members[m.GroupID] = append(members[m.GroupID], scimMember(base, m.SCIMUserID))
	}
	return members, nil
}

func (s *scimGroupRepository) compose(row models.SCIMGroup, members []core.Member) (*core.Group, error) {
	group := &core.Group{}
	doc := scimDocument{id: row.ID, resource: row.Resource, createdAt: row.CreatedAt, updatedAt: row.UpdatedAt}
	if err := scimCompose(group, scimResourceTypeGroup, scimBaseURL(s.api.config)+"/Groups", doc); err != nil {
		return nil, err
	}
	group.Schemas = []core.SchemaURI{core.SchemaGroup}
	group.Members = members
	return group, nil
}

func (s *scimGroupRepository) groupEvents(r *http.Request, action models.AuditAction, row *models.SCIMGroup, displayName string) []scimAuditEvent {
	if action == "" {
		return nil
	}
	return []scimAuditEvent{{
		actor:      scimActor(r),
		action:     action,
		providerID: row.SSOProviderID,
		traits: map[string]any{
			"scim_group_id": row.ID,
			"display_name":  displayName,
		},
	}}
}

func (s *scimGroupRepository) memberEvents(tx *storage.Connection, r *http.Request, row *models.SCIMGroup, change models.SCIMGroupMemberChange) ([]scimAuditEvent, error) {
	links, err := models.FindSCIMUserLinks(tx, slices.Concat(change.Added, change.Removed))
	if err != nil {
		return nil, err
	}
	actor := scimActor(r)
	events := make([]scimAuditEvent, 0, len(change.Added)+len(change.Removed))
	appendEvents := func(action models.AuditAction, ids []uuid.UUID) {
		for _, id := range ids {
			var userID *uuid.UUID
			if linked, ok := links[id]; ok {
				userID = &linked
			}
			events = append(events, scimAuditEvent{
				actor:      actor,
				action:     action,
				providerID: row.SSOProviderID,
				traits:     scimMemberTraits(row.ID, id, userID),
			})
		}
	}
	appendEvents(models.SCIMGroupMemberAddedAction, change.Added)
	appendEvents(models.SCIMGroupMemberRemovedAction, change.Removed)
	return events, nil
}

func scimMembers(base string, scimUserIDs []uuid.UUID) []core.Member {
	members := make([]core.Member, len(scimUserIDs))
	for i, scimUserID := range scimUserIDs {
		members[i] = scimMember(base, scimUserID)
	}
	return members
}

func scimMember(base string, scimUserID uuid.UUID) core.Member {
	id := scimUserID.String()
	return core.Member{Value: id, Ref: base + "/Users/" + id, Type: scimResourceTypeUser}
}

func scimMemberIDs(members []core.Member) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, len(members))
	for _, member := range members {
		id, err := uuid.FromString(member.Value)
		if err != nil {
			return nil, errSCIMMemberNotFound()
		}
		ids = append(ids, id)
	}
	return ids, nil
}

type scimUserRepository struct {
	api *API
}

type scimUserChange struct {
	r        *http.Request
	target   models.SCIMTarget
	resource []byte
	user     *core.User
}

func (s *scimUserRepository) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.User, int, error) {
	return scimLister[models.SCIMUser, *core.User]{
		schemas: scimUserSchemas,
		name:    "userName",
		find:    models.FindSCIMUsers,
		render:  s.render,
	}.list(ctx, s.api.db.WithContext(ctx), query)
}

func (s *scimUserRepository) Read(ctx context.Context, id string) (*core.User, error) {
	target, err := scimTarget(ctx, id, "")
	if err != nil {
		return nil, err
	}
	db := s.api.db.WithContext(ctx)
	row, err := models.FindSCIMUser(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, scimError(err)
	}
	return s.renderOne(db, target.ProviderID, row, protocol.ProjectionFrom(ctx))
}

func (s *scimUserRepository) Create(ctx context.Context, user *core.User) (*core.User, error) {
	providerID, err := scimProviderID(ctx)
	if err != nil {
		return nil, err
	}
	resource, err := scimUserResource(user)
	if err != nil {
		return nil, err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	db := s.api.db.WithContext(ctx)
	if err := s.beforeProvision(r, db, providerID, user); err != nil {
		return nil, err
	}

	change := scimUserChange{r: r, target: models.SCIMTarget{ProviderID: providerID}, resource: resource, user: user}
	return s.save(db, change, scimUserCreateProjection, func(tx *storage.Connection) (*models.SCIMUser, *models.User, models.AuditAction, error) {
		return s.create(tx, change)
	})
}

func (s *scimUserRepository) Update(ctx context.Context, user *core.User) (*core.User, error) {
	target, err := scimTarget(ctx, user.ID, user.Meta.Version)
	if err != nil {
		return nil, err
	}
	resource, err := scimUserResource(user)
	if err != nil {
		return nil, err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return nil, err
	}
	db := s.api.db.WithContext(ctx)
	existing, err := models.FindSCIMUser(db, target.ProviderID, target.ID)
	if err != nil {
		return nil, scimError(err)
	}
	if existing.UserID == nil {
		if err := s.beforeProvision(r, db, target.ProviderID, user); err != nil {
			return nil, err
		}
	}

	change := scimUserChange{r: r, target: target, resource: resource, user: user}
	return s.save(db, change, protocol.Projection{}, func(tx *storage.Connection) (*models.SCIMUser, *models.User, models.AuditAction, error) {
		return s.replace(tx, change, existing)
	})
}

func (s *scimUserRepository) Delete(ctx context.Context, user *core.User) error {
	target, err := scimTarget(ctx, user.ID, user.Meta.Version)
	if err != nil {
		return err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return err
	}
	return scimError(s.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		return s.delete(tx, r, target)
	}))
}

func (s *scimUserRepository) create(tx *storage.Connection, change scimUserChange) (*models.SCIMUser, *models.User, models.AuditAction, error) {
	row, err := models.CreateSCIMUser(tx, change.target.ProviderID, change.resource)
	if err != nil {
		return nil, nil, "", err
	}
	created, err := s.provisionAuthUser(tx, row, change.user)
	return row, created, models.SCIMUserCreatedAction, err
}

func (s *scimUserRepository) replace(tx *storage.Connection, change scimUserChange, old *models.SCIMUser) (*models.SCIMUser, *models.User, models.AuditAction, error) {
	row, changed, err := s.replaceRow(tx, change.target, old, change.resource)
	if err != nil || !changed {
		return row, nil, "", err
	}
	created, err := s.syncAuthUser(tx, change, old, row)
	if err != nil {
		return nil, nil, "", err
	}
	return row, created, scimUserAuditAction(old, row), nil
}

func (s *scimUserRepository) save(db *storage.Connection, change scimUserChange, projection protocol.Projection, write func(*storage.Connection) (*models.SCIMUser, *models.User, models.AuditAction, error)) (*core.User, error) {
	var (
		saved   *core.User
		created *models.User
	)
	err := db.Transaction(func(tx *storage.Connection) error {
		row, user, action, terr := write(tx)
		if terr != nil {
			return terr
		}
		created = user
		if action != "" {
			event := scimAuditEvent{actor: scimActor(change.r), action: action, providerID: row.SSOProviderID, traits: scimUserTraits(row)}
			if terr = s.api.auditSCIM(tx, change.r, event); terr != nil {
				return terr
			}
		}
		saved, terr = s.renderOne(tx, change.target.ProviderID, row, projection)
		return terr
	})
	if err != nil {
		return nil, scimError(err)
	}
	s.runAfterUserCreatedHook(change.r, db, created)
	return saved, nil
}

func (s *scimUserRepository) render(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMUser, projection protocol.Projection) ([]*core.User, error) {
	groups, err := s.groupMemberships(tx, providerID, rows, projection)
	if err != nil {
		return nil, err
	}
	base := scimBaseURL(s.api.config)
	users := make([]*core.User, 0, len(rows))
	for _, row := range rows {
		user := &core.User{}
		doc := scimDocument{id: row.ID, resource: row.Resource, createdAt: row.CreatedAt, updatedAt: row.UpdatedAt}
		if err := scimCompose(user, scimResourceTypeUser, base+"/Users", doc); err != nil {
			return nil, err
		}
		user.Active = &row.Active
		user.Schemas = []core.SchemaURI{core.SchemaUser}
		if user.EnterpriseUser != nil {
			user.Schemas = append(user.Schemas, core.SchemaEnterpriseUser)
		}
		user.Groups = groups[row.ID]
		users = append(users, user)
	}
	return users, nil
}

func (s *scimUserRepository) groupMemberships(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMUser, projection protocol.Projection) (map[uuid.UUID][]core.GroupMembership, error) {
	groups := map[uuid.UUID][]core.GroupMembership{}
	if !projection.Returns("groups") {
		return groups, nil
	}
	ids := make([]uuid.UUID, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	memberships, err := models.FindSCIMMembershipsByUser(tx, providerID, ids)
	if err != nil {
		return nil, err
	}
	base := scimBaseURL(s.api.config)
	for _, m := range memberships {
		id := m.GroupID.String()
		groups[m.SCIMUserID] = append(groups[m.SCIMUserID], core.GroupMembership{
			Value:   id,
			Ref:     base + "/Groups/" + id,
			Display: m.Display,
			Type:    "direct",
		})
	}
	return groups, nil
}

func newSCIMUserCreateProjection() protocol.Projection {
	projection, err := protocol.ParseProjection(url.Values{"excludedAttributes": {"groups"}}, scimUserSchemas)
	if err != nil {
		panic(err)
	}
	return projection
}

func (s *scimUserRepository) renderOne(tx *storage.Connection, providerID uuid.UUID, row *models.SCIMUser, projection protocol.Projection) (*core.User, error) {
	return scimRenderOne(func(rows []models.SCIMUser) ([]*core.User, error) {
		return s.render(tx, providerID, rows, projection)
	}, *row)
}

func (s *scimUserRepository) delete(tx *storage.Connection, r *http.Request, target models.SCIMTarget) error {
	row, err := models.DeleteSCIMUser(tx, target)
	if err != nil {
		return err
	}
	if row.UserID != nil {
		if err := models.Logout(tx, *row.UserID); err != nil {
			return err
		}
	}
	events, err := scimUserRemovalEvents(tx, scimActor(r), row)
	if err != nil {
		return err
	}
	return s.api.auditSCIMEvents(tx, r, events)
}

func (s *scimUserRepository) replaceRow(tx *storage.Connection, target models.SCIMTarget, old *models.SCIMUser, resource []byte) (*models.SCIMUser, bool, error) {
	if old.UserID != nil {
		return models.ReplaceSCIMUserIfChanged(tx, target, resource)
	}
	row, err := models.ReplaceSCIMUser(tx, target, resource)
	return row, err == nil, err
}

func (s *scimUserRepository) syncAuthUser(tx *storage.Connection, change scimUserChange, old, row *models.SCIMUser) (*models.User, error) {
	if old.UserID == nil {
		if scimUserEmail(change.user) == "" {
			return nil, errSCIMEmailRequired()
		}
		return s.provisionAuthUser(tx, row, change.user)
	}

	linked, err := models.FindUserByID(tx, *old.UserID)
	if err != nil {
		return nil, err
	}
	if err := s.renameIdentity(tx, change, old); err != nil {
		return nil, err
	}
	if err := s.changeEmail(tx, change, linked); err != nil {
		return nil, err
	}
	if old.Active && !row.Active {
		return nil, models.Logout(tx, linked.ID)
	}
	return nil, nil
}

func (s *scimUserRepository) renameIdentity(tx *storage.Connection, change scimUserChange, old *models.SCIMUser) error {
	userID := *old.UserID
	providerID := change.target.ProviderID
	user := change.user
	from, err := scimUserName(old.Resource)
	if err != nil || from == user.UserName {
		return err
	}
	data := map[string]any{scimClaimSub: user.UserName}
	if email := scimUserEmail(user); email != "" {
		data[scimClaimEmail] = email
	}
	err = models.RenameSCIMIdentity(tx, models.SCIMIdentityRename{
		UserID:   userID,
		Provider: scimProviderType(providerID),
		From:     from,
		To:       user.UserName,
		Data:     data,
	})
	if errors.Is(err, models.SCIMIdentityNotFoundError{}) {
		observability.GetLogEntry(change.r).Entry.WithField("user_id", userID).WithField("sso_provider_id", providerID).Warn("scim: identity not found, rename skipped")
		return nil
	}
	return err
}

func (s *scimUserRepository) changeEmail(tx *storage.Connection, change scimUserChange, linked *models.User) error {
	user, providerID := change.user, change.target.ProviderID
	email := scimUserEmail(user)
	if email == "" || strings.EqualFold(email, linked.GetEmail()) {
		return nil
	}
	if err := models.ChangeSCIMIdentityEmail(tx, models.SCIMIdentityEmailChange{
		UserID:   linked.ID,
		Provider: scimProviderType(providerID),
		Subject:  user.UserName,
		Email:    email,
	}); err != nil {
		return err
	}
	if err := linked.SetEmail(tx, strings.ToLower(email)); err != nil {
		return err
	}
	if err := linked.ClearAllPendingTokens(tx); err != nil {
		return err
	}
	return linked.UpdateUserMetaData(tx, map[string]any{scimClaimEmail: email})
}

func scimUserResource(user *core.User) ([]byte, error) {
	resource, err := scimEncode(user, "id", "meta", "password", "groups")
	if err != nil {
		return nil, err
	}
	if err := scimValidatePrimaryEmail(user); err != nil {
		return nil, err
	}
	return resource, nil
}

func scimUserEmail(user *core.User) string {
	if email := scimPrimaryEmail(user.Emails); email != "" {
		return email
	}
	if isEmailAddress(user.UserName) {
		return user.UserName
	}
	return ""
}

func scimValidatePrimaryEmail(user *core.User) error {
	if email := scimPrimaryEmail(user.Emails); email != "" && !isEmailAddress(email) {
		return errSCIMEmailInvalid()
	}
	return nil
}

func isEmailAddress(value string) bool {
	return len(value) <= 255 && checkmail.ValidateFormat(value) == nil
}

func scimPrimaryEmail(emails []core.Email) string {
	for _, email := range emails {
		if email.Primary != nil && *email.Primary {
			return email.Value
		}
	}
	if len(emails) > 0 {
		return emails[0].Value
	}
	return ""
}

func scimIdentityData(user *core.User) map[string]any {
	return map[string]any{
		scimClaimSub:           user.UserName,
		scimClaimEmail:         scimUserEmail(user),
		scimClaimEmailVerified: true,
	}
}

func scimUserName(resource []byte) (string, error) {
	var r struct {
		UserName string `json:"userName"`
	}
	if err := json.Unmarshal(resource, &r); err != nil {
		return "", err
	}
	return r.UserName, nil
}

func scimUserTraits(row *models.SCIMUser) map[string]any {
	traits := map[string]any{
		"scim_user_id": row.ID,
		"user_name":    row.UserName,
		"active":       row.Active,
	}
	if row.UserID != nil {
		traits["user_id"] = *row.UserID
	}
	return traits
}

func scimUserAuditAction(before, after *models.SCIMUser) models.AuditAction {
	switch {
	case before.Active && !after.Active:
		return models.SCIMUserDeactivatedAction
	case !before.Active && after.Active:
		return models.SCIMUserReactivatedAction
	}
	return models.SCIMUserUpdatedAction
}
