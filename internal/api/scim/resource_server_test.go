package scim

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
)

type fakeUserService struct {
	getResult    *core.User
	getErr       error
	createResult *core.User
	createErr    error
	createCalled bool
	listItems    []*core.User
	listTotal    int
	listErr      error
}

func (f *fakeUserService) Get(ctx context.Context, id string) (*core.User, error) {
	return f.getResult, f.getErr
}

func (f *fakeUserService) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.User, int, error) {
	return f.listItems, f.listTotal, f.listErr
}

func (f *fakeUserService) Create(ctx context.Context, item *core.User) (*core.User, error) {
	f.createCalled = true
	if f.createResult != nil {
		return f.createResult, f.createErr
	}
	return item, f.createErr
}

func (f *fakeUserService) Replace(ctx context.Context, id string, item *core.User) (*core.User, error) {
	return item, nil
}

func (f *fakeUserService) Delete(ctx context.Context, id string) error {
	return nil
}

func newFakeServer(svc Service[*core.User]) *ResourceServer[*core.User] {
	return NewResourceServer(protocol.DefaultLimits, svc, ResourceSpec[*core.User]{
		Path:     "/Users",
		Schema:   newUserSchema(testExternalURL + BasePath),
		New:      func() *core.User { return new(core.User) },
		Validate: validateUser,
		Location: func(u *core.User) string { return u.Meta.Location },
	})
}

func TestResourceServer(t *testing.T) {
	t.Run("ByID", func(t *testing.T) {
		t.Run("returns 404 when the id is not a uuid", func(t *testing.T) {
			svc := &fakeUserService{getResult: &core.User{}}
			r := requestWithURLParam("/Users/not-a-uuid", "id", "not-a-uuid")
			w := httptest.NewRecorder()

			require.NoError(t, newFakeServer(svc).ByID(w, r))

			assert.Equal(t, http.StatusNotFound, w.Code)
			assert.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		})

		t.Run("returns 404 when the service reports the resource is missing", func(t *testing.T) {
			svc := &fakeUserService{getErr: ErrNotFound}
			id := uuid.Must(uuid.NewV4()).String()
			r := requestWithURLParam("/Users/"+id, "id", id)
			w := httptest.NewRecorder()

			require.NoError(t, newFakeServer(svc).ByID(w, r))

			assert.Equal(t, http.StatusNotFound, w.Code)
		})
	})

	t.Run("Create", func(t *testing.T) {
		t.Run("returns the validation error without calling the service", func(t *testing.T) {
			svc := &fakeUserService{}
			body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"]}`
			r := httptest.NewRequest(http.MethodPost, BasePath+"/Users", strings.NewReader(body))
			w := httptest.NewRecorder()

			require.NoError(t, newFakeServer(svc).Create(w, r))

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidValue))
			assert.False(t, svc.createCalled)
		})

		t.Run("sets the Location header from the created resource", func(t *testing.T) {
			location := testExternalURL + BasePath + "/Users/abc"
			svc := &fakeUserService{createResult: &core.User{Meta: core.Meta{Location: location}}}
			body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bjensen"}`
			r := httptest.NewRequest(http.MethodPost, BasePath+"/Users", strings.NewReader(body))
			w := httptest.NewRecorder()

			require.NoError(t, newFakeServer(svc).Create(w, r))

			assert.Equal(t, http.StatusCreated, w.Code)
			assert.Equal(t, location, w.Header().Get("Location"))
			assert.True(t, svc.createCalled)
		})
	})

	t.Run("List", func(t *testing.T) {
		t.Run("reports the total the service returns", func(t *testing.T) {
			svc := &fakeUserService{
				listItems: []*core.User{{UserName: "a"}, {UserName: "b"}},
				listTotal: 7,
			}
			r := httptest.NewRequest(http.MethodGet, BasePath+"/Users", nil)
			w := httptest.NewRecorder()

			require.NoError(t, newFakeServer(svc).List(w, r))

			require.Equal(t, http.StatusOK, w.Code)
			body := listed[*core.User](t, w)
			assert.Equal(t, 7, body.TotalResults)
			assert.Len(t, body.Resources, 2)
		})
	})
}
