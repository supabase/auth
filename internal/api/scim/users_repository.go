package scim

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

var errMissingSSOProvider = errors.New("scim: request has no SSO provider")

type userRepository struct {
	db          *storage.Connection
	provisioner Provisioner
	location    string
	schemas     []*core.Schema
}

func NewUserRepository(config *conf.GlobalConfiguration, db *storage.Connection, provisioner Provisioner) server.Repository[*core.User] {
	return &userRepository{
		db:          db,
		provisioner: provisioner,
		location:    BaseURL(config) + "/Users/",
		schemas:     []*core.Schema{core.NewSchema(core.SchemaUser).With(userAttributes()...)},
	}
}

func (r *userRepository) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.User, int, error) {
	providerID, err := providerFrom(ctx)
	if err != nil {
		return nil, 0, err
	}

	criteria := models.SCIMUserFilter{}
	if query.Filter != "" {
		if criteria, err = protocol.Filter(r.schemas, query.Filter, userFilter{}); err != nil {
			return nil, 0, err
		}
	}

	rows, total, err := models.FindSCIMUsers(r.db.WithContext(ctx), providerID, criteria, query.Offset(), query.Count)
	if err != nil {
		return nil, 0, err
	}

	users := make([]*core.User, 0, len(rows))
	for i := range rows {
		user, err := r.toUser(&rows[i])
		if err != nil {
			return nil, 0, err
		}
		users = append(users, user)
	}
	return users, total, nil
}

func (r *userRepository) Get(ctx context.Context, id string) (*core.User, error) {
	providerID, err := providerFrom(ctx)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.FromString(id)
	if err != nil {
		return nil, errUserNotFound()
	}

	row, err := models.FindSCIMUser(r.db.WithContext(ctx), providerID, userID)
	if err != nil {
		return nil, translate(err)
	}
	return r.toUser(row)
}

func (r *userRepository) Create(ctx context.Context, user *core.User) (*core.User, error) {
	providerID, err := providerFrom(ctx)
	if err != nil {
		return nil, err
	}
	input, err := toInput(user)
	if err != nil {
		return nil, err
	}

	row, err := r.provisioner.CreateUser(ctx, providerID, input)
	if err != nil {
		return nil, translate(err)
	}
	return r.toUser(row)
}

func (r *userRepository) Replace(ctx context.Context, user *core.User) (*core.User, error) {
	providerID, err := providerFrom(ctx)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.FromString(user.ResourceID())
	if err != nil {
		return nil, errUserNotFound()
	}
	updatedAt, err := parseVersion(user.GetMeta().Version)
	if err != nil {
		return nil, err
	}
	input, err := toInput(user)
	if err != nil {
		return nil, err
	}

	row, err := r.provisioner.ReplaceUser(ctx, providerID, userID, input, updatedAt)
	if err != nil {
		return nil, translate(err)
	}
	return r.toUser(row)
}

func (r *userRepository) Delete(ctx context.Context, id, _ string) error {
	providerID, err := providerFrom(ctx)
	if err != nil {
		return err
	}
	userID, err := uuid.FromString(id)
	if err != nil {
		return errUserNotFound()
	}
	return translate(r.provisioner.DeleteUser(ctx, providerID, userID))
}

func (r *userRepository) toUser(row *models.SCIMUser) (*core.User, error) {
	user := &core.User{}
	if err := json.Unmarshal(row.Resource, user); err != nil {
		return nil, err
	}
	active := row.Active
	user.Active = &active
	user.SetID(row.ID.String())
	user.SetSchemas([]core.SchemaURI{core.SchemaUser})
	user.SetMeta(core.Meta{
		ResourceType: "User",
		Created:      row.CreatedAt.UTC(),
		LastModified: row.UpdatedAt.UTC(),
		Location:     r.location + row.ID.String(),
		Version:      version(row.UpdatedAt),
	})
	return user, nil
}

func toResource(user *core.User) ([]byte, error) {
	encoded, err := json.Marshal(user) // #nosec G117
	if err != nil {
		return nil, err
	}
	resource := map[string]any{}
	if err := json.Unmarshal(encoded, &resource); err != nil {
		return nil, err
	}
	delete(resource, "id")
	delete(resource, "meta")
	delete(resource, "password")
	return json.Marshal(resource)
}

func version(updatedAt time.Time) string {
	return `W/"` + strconv.FormatInt(updatedAt.UnixMicro(), 10) + `"`
}

func parseVersion(version string) (*time.Time, error) {
	if version == "" {
		return nil, nil
	}
	micros, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(version, `W/"`), `"`), 10, 64)
	if err != nil {
		return nil, errStale()
	}
	updatedAt := time.UnixMicro(micros)
	return &updatedAt, nil
}

func providerFrom(ctx context.Context) (uuid.UUID, error) {
	providerID, ok := SSOProviderID(ctx)
	if !ok || providerID == uuid.Nil {
		return uuid.Nil, errMissingSSOProvider
	}
	return providerID, nil
}

func errStale() error {
	return scimerrors.ErrPreconditionFailed("resource has changed on the server")
}

func errUserNotFound() error {
	return scimerrors.ErrNotFound("Resource not found")
}

func translate(err error) error {
	switch {
	case err == nil:
		return nil
	case models.IsNotFoundError(err):
		return errUserNotFound()
	case errors.Is(err, models.SCIMUserStaleError{}):
		return errStale()
	case errors.Is(err, models.SCIMUserConflictError{}):
		return scimerrors.ErrUniqueness(`"userName" and "externalId" must be unique`)
	}
	return err
}

type userFilter struct{}

func (userFilter) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (models.SCIMUserFilter, error) {
	text, ok := value.(string)
	if op != filter.OpEquals || attribute.Parent != nil || !ok {
		return unsupportedFilter()
	}
	switch attribute.Definition.Name {
	case "userName":
		return models.SCIMUserFilter{UserName: &text}, nil
	case "externalId":
		return models.SCIMUserFilter{ExternalID: &text}, nil
	}
	return unsupportedFilter()
}

func (userFilter) Present(*protocol.Attribute) (models.SCIMUserFilter, error) {
	return unsupportedFilter()
}

func (userFilter) And(models.SCIMUserFilter, models.SCIMUserFilter) (models.SCIMUserFilter, error) {
	return unsupportedFilter()
}

func (userFilter) Or(models.SCIMUserFilter, models.SCIMUserFilter) (models.SCIMUserFilter, error) {
	return unsupportedFilter()
}

func (userFilter) Not(models.SCIMUserFilter) (models.SCIMUserFilter, error) {
	return unsupportedFilter()
}

func (userFilter) ValuePath(*protocol.Attribute, func() (models.SCIMUserFilter, error)) (models.SCIMUserFilter, error) {
	return unsupportedFilter()
}

func unsupportedFilter() (models.SCIMUserFilter, error) {
	return models.SCIMUserFilter{}, scimerrors.ErrInvalidFilter(`only "userName eq" and "externalId eq" filters are supported`)
}
