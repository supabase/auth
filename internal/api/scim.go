package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	scimRequestKey       = ctxkey.New[*http.Request]("scim_request")
	scimTokenKey         = ctxkey.New[*models.SCIMToken]("scim_token")
	scimGroupSnapshotKey = ctxkey.New[*scimGroupSnapshot]("scim_group_snapshot")

	scimUserSchemas = core.Schemas{
		core.NewSchema(core.SchemaUser).With(core.UserAttributes()...),
		core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...),
	}
	scimGroupSchemas = core.Schemas{core.NewSchema(core.SchemaGroup).With(core.GroupAttributes()...)}

	scimUnstored = strings.Fields("id meta password groups members")

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

func scimFirst[R any](resources []R, err error) (R, error) {
	if err != nil {
		var zero R
		return zero, err
	}
	return resources[0], nil
}

func scimDelete(ctx context.Context, db *storage.Connection, resource core.Resource, remove func(*storage.Connection, *http.Request, models.SCIMTarget) error) error {
	common := resource.Common()
	target, err := scimTarget(ctx, common.ID, common.Meta.Version)
	if err != nil {
		return err
	}
	r, err := scimRequest(ctx)
	if err != nil {
		return err
	}
	return scimError(db.Transaction(func(tx *storage.Connection) error {
		return remove(tx, r, target)
	}))
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
	common.Meta = core.Meta{
		ResourceType: resourceType,
		Created:      doc.createdAt.UTC(),
		LastModified: doc.updatedAt.UTC(),
		Location:     location + "/" + common.ID,
		Version:      scimVersion(doc.updatedAt),
	}
	return nil
}

func (a *API) newSCIMServer(validate server.TokenValidator, limit func(http.Handler) http.Handler) *server.Server {
	authenticate := func(next http.Handler) http.Handler {
		return server.RequireBearerToken(validate)(limit(next))
	}
	return server.New(scimBasePath,
		core.NewServiceProviderConfig().Filtering(protocol.DefaultLimits.MaxCount).Patching().Sorting().Versioning(),
		server.WithBaseURL(scimBaseURL(a.config)),
		server.ErrorHandler(func(r *http.Request, err error) {
			observability.GetLogEntry(r).Entry.WithError(err).Error("scim: request failed")
		}),
		server.WithResource(server.NewResource[*core.User](scimResourceTypeUser, "/Users", core.SchemaUser, scimUserSchemas.Base().Attributes...).
			WithExtension(core.SchemaEnterpriseUser, scimUserSchemas.Extensions()[0].Attributes...).
			WithRepository(&scimUserRepository{api: a})),
		server.WithResource(server.NewResource[*core.Group](scimResourceTypeGroup, "/Groups", core.SchemaGroup, scimGroupSchemas.Base().Attributes...).
			WithRepository(&scimGroupRepository{api: a})),
		server.WithAuthentication(core.NewOAuthBearerToken().AsPrimary(), authenticate),
	)
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
	event.traits["sso_provider_id"] = event.providerID
	event.traits["outcome"] = "success"
	return models.NewAuditLogEntry(a.config.AuditLog, r, tx, event.actor, event.action, utilities.GetIPAddress(r), event.traits)
}

func scimBaseURL(config *conf.GlobalConfiguration) string {
	return strings.TrimRight(config.API.ExternalURL, "/") + scimBasePath
}

func scimSearch(query *protocol.SearchRequest, schemas core.Schemas, name string) (models.SCIMQuery, error) {
	search := models.SCIMQuery{Offset: query.Offset(), Limit: query.Count}
	if query.Filter != "" {
		criteria, err := protocol.Filter(schemas, query.Filter, scimSQLFilter{schemas: schemas, name: name})
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

func scimEncode(resource core.Resource) ([]byte, error) {
	fields, err := core.NewObject(resource)
	if err != nil {
		return nil, err
	}
	for _, key := range scimUnstored {
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
	target := models.SCIMTarget{ProviderID: providerID, ID: resourceID}
	if version == "" {
		return target, nil
	}
	micros, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(version, `W/"`), `"`), 10, 64)
	if err != nil {
		return models.SCIMTarget{}, errSCIMStale()
	}
	updatedAt := time.UnixMicro(micros)
	target.UpdatedAt = &updatedAt
	return target, nil
}

func scimProviderID(ctx context.Context) (uuid.UUID, error) {
	token := scimTokenKey.Value(ctx)
	if token == nil || token.SSOProviderID == uuid.Nil {
		return uuid.Nil, errors.New("scim: request has no SSO provider")
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

func scimVersion(updatedAt time.Time) string {
	return `W/"` + strconv.FormatInt(updatedAt.UnixMicro(), 10) + `"`
}

func scimActor(r *http.Request) *models.User {
	prefix := ""
	if token := scimTokenKey.Value(r.Context()); token != nil {
		prefix = token.Prefix
	}
	return &models.User{Email: storage.NullString("scim:" + prefix)}
}

type scimSQLFilter struct {
	schemas core.Schemas
	name    string
}

func (f scimSQLFilter) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (models.SCIMFilter, error) {
	column := attribute.Parent == nil && attribute.Path.SubAttribute == ""
	switch {
	case op != filter.OpEquals || value == nil:
		return f.unsupported()
	case column && attribute.Definition.Name == f.name:
		return models.SCIMFilter{Attribute: models.SCIMAttributeName, Value: value}, nil
	case column && attribute.Definition.Name == "externalId":
		return models.SCIMFilter{Attribute: models.SCIMAttributeExternalID, Value: value}, nil
	case column && attribute.Definition.Name == "active":
		return models.SCIMFilter{Attribute: models.SCIMAttributeActive, Value: value}, nil
	}
	return f.match(attribute, value)
}

func (f scimSQLFilter) Present(*protocol.Attribute) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f scimSQLFilter) And(left, right models.SCIMFilter) (models.SCIMFilter, error) {
	return models.SCIMFilter{And: append(scimTerms(left, left.And), scimTerms(right, right.And)...)}, nil
}

func (f scimSQLFilter) Or(left, right models.SCIMFilter) (models.SCIMFilter, error) {
	return models.SCIMFilter{Or: append(scimTerms(left, left.Or), scimTerms(right, right.Or)...)}, nil
}

func (f scimSQLFilter) Not(models.SCIMFilter) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f scimSQLFilter) ValuePath(attribute *protocol.Attribute, valueFilter func() (models.SCIMFilter, error)) (models.SCIMFilter, error) {
	parent := attribute.Definition
	if slices.Contains(scimUnstored, parent.Name) {
		return f.unsupported()
	}
	inner, err := valueFilter()
	if err != nil {
		return inner, err
	}
	terms := scimTerms(inner, inner.Or)
	for i, term := range terms {
		element := map[string]any{}
		if !scimMerge(element, term) {
			return f.unsupported()
		}
		terms[i] = models.SCIMFilter{Match: f.wrap(attribute.Path, parent, element)}
	}
	if len(terms) == 1 {
		return terms[0], nil
	}
	return models.SCIMFilter{Or: terms}, nil
}

func (f scimSQLFilter) match(attribute *protocol.Attribute, value any) (models.SCIMFilter, error) {
	definition, path := attribute.Definition, attribute.Path
	if definition.CaseExact || definition.Type == core.TypeBinary || definition.Type == core.TypeDateTime {
		return f.unsupported()
	}
	term := map[string]any{definition.Name: value}
	if attribute.Parent != nil {
		return models.SCIMFilter{Match: term}, nil
	}
	parent, _ := f.schemas.Resolve(core.SchemaURI(path.URI), path.Name, "")
	if parent == nil || slices.Contains(scimUnstored, parent.Name) {
		return f.unsupported()
	}
	if parent != definition {
		return models.SCIMFilter{Match: f.wrap(path, parent, term)}, nil
	}
	return models.SCIMFilter{Match: f.extension(path, term)}, nil
}

func (f scimSQLFilter) wrap(path filter.AttrPath, parent *core.Attribute, term map[string]any) map[string]any {
	var nested any = term
	if parent.MultiValued {
		nested = []any{term}
	}
	return f.extension(path, map[string]any{parent.Name: nested})
}

func (f scimSQLFilter) extension(path filter.AttrPath, term map[string]any) map[string]any {
	schema := f.schemas.Lookup(core.SchemaURI(path.URI))
	if !f.schemas.IsExtension(schema) {
		return term
	}
	return map[string]any{string(schema.ID): term}
}

func (f scimSQLFilter) unsupported() (models.SCIMFilter, error) {
	return models.SCIMFilter{}, scimerrors.ErrInvalidFilter(`only "eq" filters joined by "and" or "or" are supported`)
}

func scimTerms(filter models.SCIMFilter, terms []models.SCIMFilter) []models.SCIMFilter {
	if len(terms) > 0 {
		return terms
	}
	return []models.SCIMFilter{filter}
}

func scimMerge(element map[string]any, term models.SCIMFilter) bool {
	if term.Match == nil {
		return len(term.And) > 0 && !slices.ContainsFunc(term.And, func(t models.SCIMFilter) bool { return !scimMerge(element, t) })
	}
	for key, value := range term.Match {
		if existing, ok := element[key]; ok && existing != value {
			return false
		}
		element[key] = value
	}
	return true
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
	members, err := s.members(db, target.ProviderID, []models.SCIMGroup{*row}, projection)
	if err != nil {
		return nil, err
	}
	group, err := s.compose(*row, members[row.ID])
	if err != nil {
		return nil, err
	}
	if snapshot := scimGroupSnapshotKey.Value(ctx); snapshot != nil && projection.Returns("members") {
		snapshot.members, snapshot.version = members[row.ID], group.Meta.Version
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
		if err != nil || !changed {
			return row, "", err
		}
		return row, models.SCIMGroupUpdatedAction, nil
	})
}

func (s *scimGroupRepository) Delete(ctx context.Context, group *core.Group) error {
	return scimDelete(ctx, s.api.db.WithContext(ctx), group, s.delete)
}

func (s *scimGroupRepository) save(ctx context.Context, group *core.Group, write func(*storage.Connection, []byte) (*models.SCIMGroup, models.AuditAction, error)) (*core.Group, error) {
	members, err := scimMemberIDs(group.Members)
	if err != nil {
		return nil, err
	}
	resource, err := scimEncode(&core.Group{Base: group.Base, DisplayName: group.DisplayName})
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
		if action = scimGroupAction(action, change); action == "" {
			return nil
		}
		return s.api.auditSCIM(tx, r, scimGroupEvent(r, action, row, group.DisplayName))
	})
	if err != nil {
		return nil, scimError(err)
	}
	return s.compose(*row, change.Members)
}

func (s *scimGroupRepository) memberReplacer(ctx context.Context, version string, action models.AuditAction) func(*storage.Connection, *models.SCIMGroup, []uuid.UUID) (*models.SCIMGroup, models.SCIMGroupMemberChange, error) {
	snapshot := scimGroupSnapshotKey.Value(ctx)
	if snapshot == nil || version == "" || snapshot.version != version {
		return models.ReplaceSCIMGroupMembers
	}
	return func(tx *storage.Connection, row *models.SCIMGroup, members []uuid.UUID) (*models.SCIMGroup, models.SCIMGroupMemberChange, error) {
		concurrent := scimVersion(row.UpdatedAt) != snapshot.version
		if action == "" && concurrent && s.mergeable(ctx, version) {
			return models.MergeSCIMGroupMembers(tx, row, snapshot.members, members)
		}
		return models.ReplaceSCIMGroupMembersFrom(tx, row, snapshot.members, members)
	}
}

func (s *scimGroupRepository) mergeable(ctx context.Context, version string) bool {
	r := scimRequestKey.Value(ctx)
	snapshot := scimGroupSnapshotKey.Value(ctx)
	blindPatch := r != nil && r.Method == http.MethodPatch && (r.Header.Get("If-Match") == "" || r.Header.Get("If-Match") == "*")
	sameVersion := snapshot != nil && version != "" && snapshot.version == version
	return blindPatch && sameVersion
}

func (s *scimGroupRepository) delete(tx *storage.Connection, r *http.Request, target models.SCIMTarget) error {
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
	return s.api.auditSCIM(tx, r, scimGroupEvent(r, models.SCIMGroupDeletedAction, row, resource.DisplayName))
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

func (s *scimGroupRepository) members(tx *storage.Connection, providerID uuid.UUID, rows []models.SCIMGroup, projection protocol.Projection) (map[uuid.UUID][]uuid.UUID, error) {
	members := map[uuid.UUID][]uuid.UUID{}
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
	for _, m := range memberships {
		members[m.GroupID] = append(members[m.GroupID], m.SCIMUserID)
	}
	return members, nil
}

func (s *scimGroupRepository) compose(row models.SCIMGroup, scimUserIDs []uuid.UUID) (*core.Group, error) {
	base := scimBaseURL(s.api.config)
	group := &core.Group{}
	doc := scimDocument{id: row.ID, resource: row.Resource, createdAt: row.CreatedAt, updatedAt: row.UpdatedAt}
	if err := scimCompose(group, scimResourceTypeGroup, base+"/Groups", doc); err != nil {
		return nil, err
	}
	group.Schemas = []core.SchemaURI{core.SchemaGroup}
	group.Members = make([]core.Member, len(scimUserIDs))
	for i, scimUserID := range scimUserIDs {
		id := scimUserID.String()
		group.Members[i] = core.Member{Value: id, Ref: base + "/Users/" + id, Type: scimResourceTypeUser}
	}
	return group, nil
}

func scimGroupAction(action models.AuditAction, change models.SCIMGroupMemberChange) models.AuditAction {
	if action == "" && change.Changed() {
		return models.SCIMGroupUpdatedAction
	}
	return action
}

func scimGroupEvent(r *http.Request, action models.AuditAction, row *models.SCIMGroup, displayName string) scimAuditEvent {
	traits := map[string]any{"scim_group_id": row.ID, "display_name": displayName}
	return scimAuditEvent{actor: scimActor(r), action: action, providerID: row.SSOProviderID, traits: traits}
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
	r      *http.Request
	target models.SCIMTarget
	user   *core.User
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
	return scimFirst(s.render(db, target.ProviderID, []models.SCIMUser{*row}, protocol.ProjectionFrom(ctx)))
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

	change := scimUserChange{r: r, target: models.SCIMTarget{ProviderID: providerID}, user: user}
	return s.save(db, change, func(tx *storage.Connection) (*models.SCIMUser, *models.User, models.AuditAction, error) {
		row, err := models.CreateSCIMUser(tx, providerID, resource)
		if err != nil {
			return nil, nil, "", err
		}
		created, err := s.provisionAuthUser(tx, row, user)
		return row, created, models.SCIMUserCreatedAction, err
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

	change := scimUserChange{r: r, target: target, user: user}
	return s.save(db, change, func(tx *storage.Connection) (*models.SCIMUser, *models.User, models.AuditAction, error) {
		return s.replace(tx, change, existing, resource)
	})
}

func (s *scimUserRepository) Delete(ctx context.Context, user *core.User) error {
	return scimDelete(ctx, s.api.db.WithContext(ctx), user, s.delete)
}

func (s *scimUserRepository) replace(tx *storage.Connection, change scimUserChange, old *models.SCIMUser, resource []byte) (*models.SCIMUser, *models.User, models.AuditAction, error) {
	if old.UserID == nil {
		row, err := models.ReplaceSCIMUser(tx, change.target, resource)
		if err != nil {
			return nil, nil, "", err
		}
		created, err := s.provisionAuthUser(tx, row, change.user)
		return row, created, models.SCIMUserUpdatedAction, err
	}
	row, changed, err := models.ReplaceSCIMUserIfChanged(tx, change.target, resource)
	if err != nil || !changed {
		return row, nil, "", err
	}
	return row, nil, models.SCIMUserUpdatedAction, s.syncAuthUser(tx, change, old, row)
}

func (s *scimUserRepository) save(db *storage.Connection, change scimUserChange, write func(*storage.Connection) (*models.SCIMUser, *models.User, models.AuditAction, error)) (*core.User, error) {
	var saved *core.User
	var created *models.User
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
		saved, terr = scimFirst(s.render(tx, change.target.ProviderID, []models.SCIMUser{*row}, protocol.Projection{}))
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
	event, err := scimUserRemovalEvent(tx, scimActor(r), row)
	if err != nil {
		return err
	}
	return s.api.auditSCIM(tx, r, event)
}

func (s *scimUserRepository) syncAuthUser(tx *storage.Connection, change scimUserChange, old, row *models.SCIMUser) error {
	linked, err := models.FindUserByID(tx, *old.UserID)
	if err != nil {
		return err
	}
	if err := s.renameIdentity(tx, change, old); err != nil {
		return err
	}
	if err := s.changeEmail(tx, change, linked); err != nil {
		return err
	}
	if old.Active && !row.Active {
		return models.Logout(tx, linked.ID)
	}
	return nil
}

func (s *scimUserRepository) renameIdentity(tx *storage.Connection, change scimUserChange, old *models.SCIMUser) error {
	userID := *old.UserID
	providerID := change.target.ProviderID
	user := change.user
	var stored struct {
		UserName string `json:"userName"`
	}
	if err := json.Unmarshal(old.Resource, &stored); err != nil || stored.UserName == user.UserName {
		return err
	}
	data := map[string]any{scimClaimSub: user.UserName}
	if email := scimUserEmail(user); email != "" {
		data[scimClaimEmail] = email
	}
	err := models.RenameSCIMIdentity(tx, models.SCIMIdentityRename{
		UserID:   userID,
		Provider: scimProviderType(providerID),
		From:     stored.UserName,
		To:       user.UserName,
		Data:     data,
	})
	if models.IsNotFoundError(err) {
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
	resource, err := scimEncode(user)
	if err != nil {
		return nil, err
	}
	if email := scimPrimaryEmail(user.Emails); email != "" && !isEmailAddress(email) {
		return nil, errSCIMEmailInvalid()
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
