package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

type SCIMTestSuite struct {
	suite.Suite
	API         *API
	Config      *conf.GlobalConfiguration
	SCIMToken   string
	SSOProvider *models.SSOProvider
}

func TestSCIM(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &SCIMTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *SCIMTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)
	ts.SCIMToken = "test-scim-token-12345"
	ts.SSOProvider = ts.createSSOProviderWithSCIM()
}

func (ts *SCIMTestSuite) createSSOProviderWithSCIM() *models.SSOProvider {
	provider := &models.SSOProvider{}
	require.NoError(ts.T(), ts.API.db.Create(provider))
	require.NoError(ts.T(), provider.SetSCIMToken(context.Background(), ts.SCIMToken))
	require.NoError(ts.T(), ts.API.db.Update(provider))
	require.NoError(ts.T(), ts.API.db.Reload(provider))
	return provider
}

func (ts *SCIMTestSuite) makeSCIMRequest(method, path string, body interface{}) *http.Request {
	var reqBody *bytes.Buffer
	if body != nil {
		jsonBody, err := json.Marshal(body)
		require.NoError(ts.T(), err)
		reqBody = bytes.NewBuffer(jsonBody)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, "http://localhost"+path, reqBody)
	req.Header.Set("Authorization", "Bearer "+ts.SCIMToken)
	req.Header.Set("Content-Type", "application/scim+json")
	return req
}

func (ts *SCIMTestSuite) createSCIMUser(userName, email string) *SCIMUserResponse {
	body := map[string]interface{}{
		"schemas":  []string{SCIMSchemaUser},
		"userName": userName,
		"emails": []map[string]interface{}{
			{"value": email, "primary": true, "type": "work"},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Users", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusCreated, w.Code, "Failed to create SCIM user: %s", w.Body.String())

	var result SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))
	return &result
}

func (ts *SCIMTestSuite) createSCIMUserWithName(userName, email, givenName, familyName string) *SCIMUserResponse {
	body := map[string]interface{}{
		"schemas":  []string{SCIMSchemaUser},
		"userName": userName,
		"name": map[string]interface{}{
			"givenName":  givenName,
			"familyName": familyName,
			"formatted":  givenName + " " + familyName,
		},
		"emails": []map[string]interface{}{
			{"value": email, "primary": true, "type": "work"},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Users", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusCreated, w.Code, "Failed to create SCIM user: %s", w.Body.String())

	var result SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))
	return &result
}

func (ts *SCIMTestSuite) createSCIMUserWithExternalID(userName, email, externalID string) *SCIMUserResponse {
	body := map[string]interface{}{
		"schemas":    []string{SCIMSchemaUser},
		"userName":   userName,
		"externalId": externalID,
		"emails": []map[string]interface{}{
			{"value": email, "primary": true, "type": "work"},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Users", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusCreated, w.Code, "Failed to create SCIM user: %s", w.Body.String())

	var result SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))
	return &result
}

func (ts *SCIMTestSuite) createSCIMGroup(displayName string) *SCIMGroupResponse {
	body := map[string]interface{}{
		"schemas":     []string{SCIMSchemaGroup},
		"displayName": displayName,
	}

	req := ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Groups", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusCreated, w.Code, "Failed to create SCIM group: %s", w.Body.String())

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))
	return &result
}

func (ts *SCIMTestSuite) createSCIMGroupWithExternalID(displayName, externalID string) *SCIMGroupResponse {
	body := map[string]interface{}{
		"schemas":     []string{SCIMSchemaGroup},
		"displayName": displayName,
		"externalId":  externalID,
	}

	req := ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Groups", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusCreated, w.Code, "Failed to create SCIM group: %s", w.Body.String())

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))
	return &result
}

func (ts *SCIMTestSuite) createSCIMGroupWithMembers(displayName string, memberIDs []string) *SCIMGroupResponse {
	members := make([]map[string]interface{}, len(memberIDs))
	for i, id := range memberIDs {
		members[i] = map[string]interface{}{"value": id}
	}

	body := map[string]interface{}{
		"schemas":     []string{SCIMSchemaGroup},
		"displayName": displayName,
		"members":     members,
	}

	req := ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Groups", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusCreated, w.Code, "Failed to create SCIM group: %s", w.Body.String())

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))
	return &result
}

func (ts *SCIMTestSuite) assertSCIMError(w *httptest.ResponseRecorder, expectedStatus int) {
	require.Equal(ts.T(), expectedStatus, w.Code)

	var errorResp map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errorResp))

	schemas, ok := errorResp["schemas"].([]interface{})
	require.True(ts.T(), ok, "SCIM error should have schemas field")
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), "urn:ietf:params:scim:api:messages:2.0:Error", schemas[0])

	_, ok = errorResp["detail"].(string)
	require.True(ts.T(), ok, "SCIM error should have detail field")

	// SCIM status is a string per RFC 7644
	status, ok := errorResp["status"].(string)
	require.True(ts.T(), ok, "SCIM error should have status field")
	require.Equal(ts.T(), fmt.Sprintf("%d", expectedStatus), status)
}

func (ts *SCIMTestSuite) assertSCIMListResponse(w *httptest.ResponseRecorder, expectedTotal int) *SCIMListResponse {
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMListResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaListResponse, result.Schemas[0])
	require.Equal(ts.T(), expectedTotal, result.TotalResults)
	require.GreaterOrEqual(ts.T(), result.StartIndex, 1)

	return &result
}
func (ts *SCIMTestSuite) TestSCIMProviderSetup() {
	require.NotNil(ts.T(), ts.SSOProvider)
	require.True(ts.T(), ts.SSOProvider.IsSCIMEnabled())
}

func (ts *SCIMTestSuite) TestSCIMTokenValidation() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *SCIMTestSuite) TestSCIMInvalidToken() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	req.Header.Set("Content-Type", "application/scim+json")
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMError(w, http.StatusUnauthorized)
}

func (ts *SCIMTestSuite) TestSCIMMissingToken() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/scim/v2/Users", nil)
	req.Header.Set("Content-Type", "application/scim+json")
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMError(w, http.StatusUnauthorized)
}

func (ts *SCIMTestSuite) TestSCIMEmptyUserList() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	result := ts.assertSCIMListResponse(w, 0)
	require.Len(ts.T(), result.Resources, 0)
}

func (ts *SCIMTestSuite) TestSCIMEmptyGroupList() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	result := ts.assertSCIMListResponse(w, 0)
	require.Len(ts.T(), result.Resources, 0)
}

func (ts *SCIMTestSuite) TestSCIMCreateUser() {
	user := ts.createSCIMUser("testuser", "testuser@example.com")

	require.NotEmpty(ts.T(), user.ID)
	require.Equal(ts.T(), "testuser", user.UserName)
	require.True(ts.T(), user.Active)
	require.Len(ts.T(), user.Emails, 1)
	require.Equal(ts.T(), "testuser@example.com", user.Emails[0].Value)
}

func (ts *SCIMTestSuite) TestSCIMCreateGroup() {
	group := ts.createSCIMGroup("Test Group")

	require.NotEmpty(ts.T(), group.ID)
	require.Equal(ts.T(), "Test Group", group.DisplayName)
}

func (ts *SCIMTestSuite) TestSCIMServiceProviderConfig() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	schemas, ok := result["schemas"].([]interface{})
	require.True(ts.T(), ok)
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig", schemas[0])

	patch, ok := result["patch"].(map[string]interface{})
	require.True(ts.T(), ok)
	require.True(ts.T(), patch["supported"].(bool))

	filter, ok := result["filter"].(map[string]interface{})
	require.True(ts.T(), ok)
	require.True(ts.T(), filter["supported"].(bool))
}

func (ts *SCIMTestSuite) TestSCIMResourceTypes() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/ResourceTypes", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMListResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Equal(ts.T(), 2, result.TotalResults)
	require.Len(ts.T(), result.Resources, 2)
}

func (ts *SCIMTestSuite) TestSCIMSchemas() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Schemas", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMListResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Equal(ts.T(), 2, result.TotalResults)
	require.Len(ts.T(), result.Resources, 2)
}

func (ts *SCIMTestSuite) TestSCIMGetUserNotFound() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users/00000000-0000-0000-0000-000000000000", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMError(w, http.StatusNotFound)
}

func (ts *SCIMTestSuite) TestSCIMGetGroupNotFound() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups/00000000-0000-0000-0000-000000000000", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMError(w, http.StatusNotFound)
}

func (ts *SCIMTestSuite) TestSCIMCreateUserWithName() {
	user := ts.createSCIMUserWithName("jdoe", "john.doe@example.com", "John", "Doe")

	require.NotEmpty(ts.T(), user.ID)
	require.Equal(ts.T(), "jdoe", user.UserName)
	require.NotNil(ts.T(), user.Name)
	require.Equal(ts.T(), "John", user.Name.GivenName)
	require.Equal(ts.T(), "Doe", user.Name.FamilyName)
	require.Equal(ts.T(), "John Doe", user.Name.Formatted)
}

func (ts *SCIMTestSuite) TestSCIMCreateUserWithExternalID() {
	user := ts.createSCIMUserWithExternalID("extuser", "ext@example.com", "ext-12345")

	require.NotEmpty(ts.T(), user.ID)
	require.Equal(ts.T(), "extuser", user.UserName)
	require.Equal(ts.T(), "ext-12345", user.ExternalID)
}

func (ts *SCIMTestSuite) TestSCIMGetUser() {
	created := ts.createSCIMUser("getuser", "getuser@example.com")

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users/"+created.ID, nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Equal(ts.T(), created.ID, result.ID)
	require.Equal(ts.T(), "getuser", result.UserName)
}

func (ts *SCIMTestSuite) TestSCIMGetGroup() {
	created := ts.createSCIMGroup("Get Group")

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups/"+created.ID, nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Equal(ts.T(), created.ID, result.ID)
	require.Equal(ts.T(), "Get Group", result.DisplayName)
}

func (ts *SCIMTestSuite) TestSCIMListUsersWithData() {
	ts.createSCIMUser("user1", "user1@example.com")
	ts.createSCIMUser("user2", "user2@example.com")
	ts.createSCIMUser("user3", "user3@example.com")

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	result := ts.assertSCIMListResponse(w, 3)
	require.Len(ts.T(), result.Resources, 3)
}

func (ts *SCIMTestSuite) TestSCIMListGroupsWithData() {
	ts.createSCIMGroup("Group 1")
	ts.createSCIMGroup("Group 2")

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	result := ts.assertSCIMListResponse(w, 2)
	require.Len(ts.T(), result.Resources, 2)
}

func (ts *SCIMTestSuite) TestSCIMDeleteUser() {
	user := ts.createSCIMUser("deleteuser", "deleteuser@example.com")

	require.True(ts.T(), user.Active)

	req := ts.makeSCIMRequest(http.MethodDelete, "/scim/v2/Users/"+user.ID, nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users/"+user.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))
	require.False(ts.T(), result.Active, "Deprovisioned user should have active=false")

	req = ts.makeSCIMRequest(http.MethodDelete, "/scim/v2/Users/"+user.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMError(w, http.StatusNotFound)
}

func (ts *SCIMTestSuite) TestSCIMDeleteGroup() {
	group := ts.createSCIMGroup("Delete Group")

	req := ts.makeSCIMRequest(http.MethodDelete, "/scim/v2/Groups/"+group.ID, nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups/"+group.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMError(w, http.StatusNotFound)
}

func (ts *SCIMTestSuite) TestSCIMCreateGroupWithMembers() {
	user1 := ts.createSCIMUser("member1", "member1@example.com")
	user2 := ts.createSCIMUser("member2", "member2@example.com")

	group := ts.createSCIMGroupWithMembers("Team Group", []string{user1.ID, user2.ID})

	require.NotEmpty(ts.T(), group.ID)
	require.Equal(ts.T(), "Team Group", group.DisplayName)
	require.Len(ts.T(), group.Members, 2)
}

func (ts *SCIMTestSuite) TestSCIMContentTypeHeader() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), "application/scim+json", w.Header().Get("Content-Type"))
}

func (ts *SCIMTestSuite) TestSCIMCreateUserMissingUserName() {
	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaUser},
		"emails": []map[string]interface{}{
			{"value": "test@example.com", "primary": true},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Users", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMError(w, http.StatusBadRequest)
}

func (ts *SCIMTestSuite) TestSCIMCreateGroupMissingDisplayName() {
	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaGroup},
	}

	req := ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Groups", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMError(w, http.StatusBadRequest)
}

func (ts *SCIMTestSuite) TestSCIMUserPagination() {
	for i := 0; i < 5; i++ {
		ts.createSCIMUser(fmt.Sprintf("pageuser%d", i), fmt.Sprintf("pageuser%d@example.com", i))
	}

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users?startIndex=1&count=2", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMListResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Equal(ts.T(), 5, result.TotalResults)
	require.Equal(ts.T(), 2, result.ItemsPerPage)
	require.Len(ts.T(), result.Resources, 2)
}

func (ts *SCIMTestSuite) assertSCIMErrorWithType(w *httptest.ResponseRecorder, expectedStatus int, expectedScimType string) {
	require.Equal(ts.T(), expectedStatus, w.Code)

	var errorResp map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errorResp))

	schemas, ok := errorResp["schemas"].([]interface{})
	require.True(ts.T(), ok, "SCIM error should have schemas field")
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), "urn:ietf:params:scim:api:messages:2.0:Error", schemas[0])

	_, ok = errorResp["detail"].(string)
	require.True(ts.T(), ok, "SCIM error should have detail field")

	status, ok := errorResp["status"].(string)
	require.True(ts.T(), ok, "SCIM error should have status field")
	require.Equal(ts.T(), fmt.Sprintf("%d", expectedStatus), status)

	if expectedScimType != "" {
		scimType, ok := errorResp["scimType"].(string)
		require.True(ts.T(), ok, "SCIM error should have scimType field")
		require.Equal(ts.T(), expectedScimType, scimType)
	}
}

func (ts *SCIMTestSuite) TestSCIMCreateUserAzure() {
	body := map[string]interface{}{
		"schemas":    []string{SCIMSchemaUser},
		"userName":   "maiya@anderson.com",
		"externalId": "543b2f37-3363-4d69-8af7-5fc5dc1fc3f8",
		"name": map[string]interface{}{
			"formatted":  "Kenya",
			"familyName": "Lurline",
			"givenName":  "Ernestina",
		},
		"emails": []map[string]interface{}{
			{"primary": true, "value": "kira_koelpin@thiel.ca"},
		},
		"active": true,
	}

	req := ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Users", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusCreated, w.Code)

	var result SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaUser, result.Schemas[0])
	require.NotEmpty(ts.T(), result.ID)
	require.Equal(ts.T(), "543b2f37-3363-4d69-8af7-5fc5dc1fc3f8", result.ExternalID)
	require.Equal(ts.T(), "maiya@anderson.com", result.UserName)
	require.NotNil(ts.T(), result.Name)
	require.Equal(ts.T(), "Kenya", result.Name.Formatted)
	require.Equal(ts.T(), "Lurline", result.Name.FamilyName)
	require.Equal(ts.T(), "Ernestina", result.Name.GivenName)
	require.Len(ts.T(), result.Emails, 1)
	require.Equal(ts.T(), "kira_koelpin@thiel.ca", result.Emails[0].Value)
	require.True(ts.T(), bool(result.Emails[0].Primary))
	require.True(ts.T(), result.Active)
	require.Equal(ts.T(), "User", result.Meta.ResourceType)
	require.NotNil(ts.T(), result.Meta.Created)
	require.NotNil(ts.T(), result.Meta.LastModified)
	require.Contains(ts.T(), result.Meta.Location, "/scim/v2/Users/"+result.ID)
}

func (ts *SCIMTestSuite) TestSCIMCreateUserDuplicateExternalID() {
	body := map[string]interface{}{
		"schemas":    []string{SCIMSchemaUser},
		"userName":   "elian_huel@cole.com",
		"externalId": "22a77d53-9a54-4c3e-bac7-f0cc9f2be272",
		"name": map[string]interface{}{
			"formatted":  "Teresa",
			"familyName": "Lilly",
			"givenName":  "Eino",
		},
		"emails": []map[string]interface{}{
			{"primary": true, "value": "arno.lynch@crooks.ca"},
		},
		"active": true,
	}

	req := ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Users", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusCreated, w.Code)

	req = ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Users", body)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMErrorWithType(w, http.StatusConflict, "uniqueness")
}

func (ts *SCIMTestSuite) TestSCIMDeleteUserReturns204() {
	user := ts.createSCIMUserWithExternalID("amalia@moore.us", "cade@gulgowski.us", "c51b4421-0bd6-428c-b92e-aab658faeb46")

	require.True(ts.T(), user.Active)

	req := ts.makeSCIMRequest(http.MethodDelete, "/scim/v2/Users/"+user.ID, nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	require.Empty(ts.T(), w.Body.String())
}

func (ts *SCIMTestSuite) TestSCIMDeleteNonExistentUser() {
	nonExistentID := "f1937c5d-cd6d-4151-93b7-dbfb7fb9b31d"

	req := ts.makeSCIMRequest(http.MethodDelete, "/scim/v2/Users/"+nonExistentID, nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMError(w, http.StatusNotFound)
}

func (ts *SCIMTestSuite) TestSCIMDeleteUserTwice() {
	user := ts.createSCIMUserWithExternalID("trudie@jacobs.uk", "oswaldo@marquardt.com", "2423c4dc-e525-4c51-8fa9-a63bce38136f")

	req := ts.makeSCIMRequest(http.MethodDelete, "/scim/v2/Users/"+user.ID, nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	req = ts.makeSCIMRequest(http.MethodDelete, "/scim/v2/Users/"+user.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMError(w, http.StatusNotFound)
}

func (ts *SCIMTestSuite) TestSCIMFilterUserByUserNameExisting() {
	created := ts.createSCIMUserWithExternalID("kenny.sporer@gislason.com", "aliyah@grady.name", "34aee196-7651-4817-a6d8-8a70336466cb")

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users?filter=userName+eq+%22kenny.sporer%40gislason.com%22", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMListResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaListResponse, result.Schemas[0])
	require.Equal(ts.T(), 1, result.TotalResults)
	require.Equal(ts.T(), 1, result.StartIndex)
	require.Equal(ts.T(), 1, result.ItemsPerPage)
	require.Len(ts.T(), result.Resources, 1)

	resource := result.Resources[0].(map[string]interface{})
	require.Equal(ts.T(), created.ID, resource["id"])
	require.Equal(ts.T(), "kenny.sporer@gislason.com", resource["userName"])
	require.Equal(ts.T(), "34aee196-7651-4817-a6d8-8a70336466cb", resource["externalId"])
	require.Equal(ts.T(), true, resource["active"])

	schemas := resource["schemas"].([]interface{})
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), SCIMSchemaUser, schemas[0])

	meta := resource["meta"].(map[string]interface{})
	require.Equal(ts.T(), "User", meta["resourceType"])
	require.NotEmpty(ts.T(), meta["created"])
	require.NotEmpty(ts.T(), meta["lastModified"])
	require.Contains(ts.T(), meta["location"], "/scim/v2/Users/"+created.ID)
}

func (ts *SCIMTestSuite) TestSCIMFilterUserByUserNameNonExistent() {
	ts.createSCIMUser("someuser@example.com", "someuser@example.com")

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users?filter=userName+eq+%22nonexistent%40example.com%22", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMListResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaListResponse, result.Schemas[0])
	require.Equal(ts.T(), 0, result.TotalResults)
	require.Equal(ts.T(), 1, result.StartIndex)
	require.Equal(ts.T(), 0, result.ItemsPerPage)
	require.Len(ts.T(), result.Resources, 0)
}

func (ts *SCIMTestSuite) TestSCIMFilterUserByUserNameCaseInsensitive() {
	created := ts.createSCIMUserWithExternalID("kenny.sporer@gislason.com", "aliyah@grady.name", "case-test-ext-id")

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users?filter=userName+eq+%22KENNY.SPORER%40GISLASON.COM%22", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMListResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaListResponse, result.Schemas[0])
	require.Equal(ts.T(), 1, result.TotalResults)
	require.Equal(ts.T(), 1, result.StartIndex)
	require.Equal(ts.T(), 1, result.ItemsPerPage)
	require.Len(ts.T(), result.Resources, 1)

	resource := result.Resources[0].(map[string]interface{})
	require.Equal(ts.T(), created.ID, resource["id"])
	require.Equal(ts.T(), "kenny.sporer@gislason.com", resource["userName"])
	require.Equal(ts.T(), true, resource["active"])

	schemas := resource["schemas"].([]interface{})
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), SCIMSchemaUser, schemas[0])

	meta := resource["meta"].(map[string]interface{})
	require.Equal(ts.T(), "User", meta["resourceType"])
	require.NotEmpty(ts.T(), meta["created"])
	require.NotEmpty(ts.T(), meta["lastModified"])
	require.Contains(ts.T(), meta["location"], "/scim/v2/Users/"+created.ID)
}

func (ts *SCIMTestSuite) TestSCIMPatchUserUpdateUserName() {
	user := ts.createSCIMUserWithExternalID("nasir@bins.com", "nedra@konopelski.name", "a275970d-3319-4a8c-a86f-dc8af2627c70")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "value": map[string]interface{}{"userName": "pearline@donnelly.us"}},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Users/"+user.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaUser, result.Schemas[0])
	require.Equal(ts.T(), user.ID, result.ID)
	require.Equal(ts.T(), "a275970d-3319-4a8c-a86f-dc8af2627c70", result.ExternalID)
	require.Equal(ts.T(), "pearline@donnelly.us", result.UserName)
	require.True(ts.T(), result.Active)
	require.Equal(ts.T(), "User", result.Meta.ResourceType)
	require.NotNil(ts.T(), result.Meta.Created)
	require.NotNil(ts.T(), result.Meta.LastModified)
	require.Contains(ts.T(), result.Meta.Location, "/scim/v2/Users/"+result.ID)
}

func (ts *SCIMTestSuite) TestSCIMPatchUserDisable() {
	user := ts.createSCIMUserWithExternalID("giovani@marvinwhite.biz", "maxie_botsford@vonrussel.ca", "c2a92a74-436a-4444-bced-a311a4648d66")

	require.True(ts.T(), user.Active)

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "active", "value": false},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Users/"+user.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaUser, result.Schemas[0])
	require.Equal(ts.T(), user.ID, result.ID)
	require.Equal(ts.T(), "c2a92a74-436a-4444-bced-a311a4648d66", result.ExternalID)
	require.Equal(ts.T(), "giovani@marvinwhite.biz", result.UserName)
	require.False(ts.T(), result.Active)
	require.Equal(ts.T(), "User", result.Meta.ResourceType)
	require.NotNil(ts.T(), result.Meta.Created)
	require.NotNil(ts.T(), result.Meta.LastModified)
	require.Contains(ts.T(), result.Meta.Location, "/scim/v2/Users/"+result.ID)

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users/"+user.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var getResult SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&getResult))
	require.False(ts.T(), getResult.Active)
}

func (ts *SCIMTestSuite) TestSCIMPatchUserReplaceEmailPrimaryEqTrue() {
	user := ts.createSCIMUserWithExternalID("pascale_morissette@pollich.co.uk", "nathanael_lubowitz@boganterry.co.uk", "5dd3dba4-0349-473c-b0bd-eef47b227587")

	require.Len(ts.T(), user.Emails, 1)
	require.Equal(ts.T(), "nathanael_lubowitz@boganterry.co.uk", user.Emails[0].Value)

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "emails[primary eq true].value", "value": "kaylie_dietrich@ward.co.uk"},
			{"op": "replace", "value": map[string]interface{}{
				"name.formatted":  "Delphine",
				"name.familyName": "Vita",
				"name.givenName":  "Joanie",
				"active":          true,
				"externalId":      "1be8b986-70fe-40b5-8f63-c33dbbad29d3",
			}},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Users/"+user.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaUser, result.Schemas[0])
	require.Equal(ts.T(), user.ID, result.ID)
	require.Equal(ts.T(), "1be8b986-70fe-40b5-8f63-c33dbbad29d3", result.ExternalID)
	require.Equal(ts.T(), "pascale_morissette@pollich.co.uk", result.UserName)
	require.NotNil(ts.T(), result.Name)
	require.Equal(ts.T(), "Delphine", result.Name.Formatted)
	require.Equal(ts.T(), "Vita", result.Name.FamilyName)
	require.Equal(ts.T(), "Joanie", result.Name.GivenName)
	require.True(ts.T(), result.Active)

	require.Len(ts.T(), result.Emails, 1)
	require.Equal(ts.T(), "kaylie_dietrich@ward.co.uk", result.Emails[0].Value)
	require.True(ts.T(), bool(result.Emails[0].Primary))

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users/"+user.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var getResult SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&getResult))
	require.Len(ts.T(), getResult.Emails, 1)
	require.Equal(ts.T(), "kaylie_dietrich@ward.co.uk", getResult.Emails[0].Value, "Email update was not persisted - reproduces Azure SCIM test 21 failure")
}

func (ts *SCIMTestSuite) TestSCIMPatchUserMultipleOperationsSameAttribute() {
	user := ts.createSCIMUserWithExternalID("casandra_dare@keebler.co.uk", "raul_doyle@dach.co.uk", "48a46062-d787-474a-b60c-1a1c3c70e055")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "remove", "path": "externalId"},
			{"op": "add", "value": map[string]interface{}{"externalId": "717d6020-1ca0-4e2b-ab59-158e10422645"}},
			{"op": "replace", "value": map[string]interface{}{"externalId": "5f3db8ed-c327-4a10-bd0f-a0e93028e5d2"}},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Users/"+user.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaUser, result.Schemas[0])
	require.Equal(ts.T(), user.ID, result.ID)
	require.Equal(ts.T(), "5f3db8ed-c327-4a10-bd0f-a0e93028e5d2", result.ExternalID)
	require.Equal(ts.T(), "casandra_dare@keebler.co.uk", result.UserName)
	require.True(ts.T(), result.Active)
	require.Equal(ts.T(), "User", result.Meta.ResourceType)
	require.NotNil(ts.T(), result.Meta.Created)
	require.NotNil(ts.T(), result.Meta.LastModified)
	require.Contains(ts.T(), result.Meta.Location, "/scim/v2/Users/"+result.ID)
}

func (ts *SCIMTestSuite) TestSCIMPatchUserNotFound() {
	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "active", "value": false},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Users/00000000-0000-0000-0000-000000000000", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMError(w, http.StatusNotFound)
}

func (ts *SCIMTestSuite) TestSCIMPatchUserReEnableUser() {
	user := ts.createSCIMUserWithExternalID("disabled_user@test.com", "disabled_user@test.com", "disable-reenable-test")

	disableBody := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "active", "value": false},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Users/"+user.ID, disableBody)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var disabledResult SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&disabledResult))
	require.False(ts.T(), disabledResult.Active)

	enableBody := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "active", "value": true},
		},
	}

	req = ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Users/"+user.ID, enableBody)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var enabledResult SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&enabledResult))
	require.True(ts.T(), enabledResult.Active)

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users/"+user.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var getResult SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&getResult))
	require.True(ts.T(), getResult.Active)
}

func (ts *SCIMTestSuite) TestSCIMPatchUserUpdateUserNameWithPath() {
	user := ts.createSCIMUserWithExternalID("original_username@test.com", "original_username@test.com", "username-path-test")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "userName", "value": "new_username@test.com"},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Users/"+user.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))
	require.Equal(ts.T(), "new_username@test.com", result.UserName)

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users/"+user.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var getResult SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&getResult))
	require.Equal(ts.T(), "new_username@test.com", getResult.UserName)
}

func (ts *SCIMTestSuite) TestSCIMPatchUserInvalidActiveType() {
	user := ts.createSCIMUser("invalid_active_test@test.com", "invalid_active_test@test.com")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "active", "value": "not_a_boolean"},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Users/"+user.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMErrorWithType(w, http.StatusBadRequest, "invalidValue")
}

func (ts *SCIMTestSuite) TestSCIMCreateGroupAzure() {
	body := map[string]interface{}{
		"schemas":     []string{SCIMSchemaGroup},
		"displayName": "QGKWKSWJWHXE",
		"externalId":  "7dae2322-0f90-42d2-97a1-b8268d2993d3",
	}

	req := ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Groups", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusCreated, w.Code)

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaGroup, result.Schemas[0])
	require.NotEmpty(ts.T(), result.ID)
	require.Equal(ts.T(), "7dae2322-0f90-42d2-97a1-b8268d2993d3", result.ExternalID)
	require.Equal(ts.T(), "QGKWKSWJWHXE", result.DisplayName)
	require.Equal(ts.T(), "Group", result.Meta.ResourceType)
	require.NotNil(ts.T(), result.Meta.Created)
	require.NotNil(ts.T(), result.Meta.LastModified)
	require.Contains(ts.T(), result.Meta.Location, "/scim/v2/Groups/"+result.ID)
}

func (ts *SCIMTestSuite) TestSCIMCreateGroupDuplicateExternalID() {
	body := map[string]interface{}{
		"schemas":     []string{SCIMSchemaGroup},
		"displayName": "SMVGZDBVFFRO",
		"externalId":  "e164812e-d012-4cc3-85dc-9ceb13765d62",
	}

	req := ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Groups", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusCreated, w.Code)

	body["displayName"] = "DIFFERENT_NAME"
	req = ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Groups", body)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMErrorWithType(w, http.StatusConflict, "uniqueness")
}

func (ts *SCIMTestSuite) TestSCIMDeleteGroupReturns204() {
	group := ts.createSCIMGroupWithExternalID("TESTGROUP", "delete-test-ext-id")

	req := ts.makeSCIMRequest(http.MethodDelete, "/scim/v2/Groups/"+group.ID, nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	require.Empty(ts.T(), w.Body.String())
}

func (ts *SCIMTestSuite) TestSCIMDeleteNonExistentGroup() {
	nonExistentID := "a0f1d64e-cf53-45cf-8b4b-ea0d7b9ada90"

	req := ts.makeSCIMRequest(http.MethodDelete, "/scim/v2/Groups/"+nonExistentID, nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMError(w, http.StatusNotFound)
}

func (ts *SCIMTestSuite) TestSCIMDeleteGroupTwice() {
	group := ts.createSCIMGroupWithExternalID("YLKGXWFUUUOH", "69565956-96c5-4951-910d-951bba6d2533")

	req := ts.makeSCIMRequest(http.MethodDelete, "/scim/v2/Groups/"+group.ID, nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	req = ts.makeSCIMRequest(http.MethodDelete, "/scim/v2/Groups/"+group.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMError(w, http.StatusNotFound)
}

func (ts *SCIMTestSuite) TestSCIMGetGroupByIdExcludingMembers() {
	group := ts.createSCIMGroupWithExternalID("YWWBHTHEMMLR", "94631638-0b6c-4b97-a369-aba35a454041")

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups/"+group.ID+"?excludedAttributes=members", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaGroup, result.Schemas[0])
	require.Equal(ts.T(), group.ID, result.ID)
	require.Equal(ts.T(), "94631638-0b6c-4b97-a369-aba35a454041", result.ExternalID)
	require.Equal(ts.T(), "YWWBHTHEMMLR", result.DisplayName)
	require.Equal(ts.T(), "Group", result.Meta.ResourceType)
	require.NotNil(ts.T(), result.Meta.Created)
	require.NotNil(ts.T(), result.Meta.LastModified)
	require.Contains(ts.T(), result.Meta.Location, "/scim/v2/Groups/"+result.ID)
}

func (ts *SCIMTestSuite) TestSCIMPatchUserInvalidUserNameType() {
	user := ts.createSCIMUser("invalid_username_test@test.com", "invalid_username_test@test.com")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "userName", "value": 12345},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Users/"+user.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMErrorWithType(w, http.StatusBadRequest, "invalidValue")
}

func (ts *SCIMTestSuite) TestSCIMPatchUserUnsupportedOp() {
	user := ts.createSCIMUser("unsupported_op_test@test.com", "unsupported_op_test@test.com")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "copy", "path": "userName", "value": "new@test.com"},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Users/"+user.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMErrorWithType(w, http.StatusBadRequest, "invalidSyntax")
}

func (ts *SCIMTestSuite) TestSCIMFilterGroupByDisplayNameExisting() {
	created := ts.createSCIMGroupWithExternalID("YWWBHTHEMMLR", "94631638-0b6c-4b97-a369-aba35a454041")

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups?filter=displayName+eq+%22YWWBHTHEMMLR%22", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMListResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaListResponse, result.Schemas[0])
	require.Equal(ts.T(), 1, result.TotalResults)
	require.Equal(ts.T(), 1, result.StartIndex)
	require.Equal(ts.T(), 1, result.ItemsPerPage)
	require.Len(ts.T(), result.Resources, 1)

	resource := result.Resources[0].(map[string]interface{})
	require.Equal(ts.T(), created.ID, resource["id"])
	require.Equal(ts.T(), "YWWBHTHEMMLR", resource["displayName"])
	require.Equal(ts.T(), "94631638-0b6c-4b97-a369-aba35a454041", resource["externalId"])

	schemas := resource["schemas"].([]interface{})
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), SCIMSchemaGroup, schemas[0])

	meta := resource["meta"].(map[string]interface{})
	require.Equal(ts.T(), "Group", meta["resourceType"])
	require.NotEmpty(ts.T(), meta["created"])
	require.NotEmpty(ts.T(), meta["lastModified"])
	require.Contains(ts.T(), meta["location"], "/scim/v2/Groups/"+created.ID)
}

func (ts *SCIMTestSuite) TestSCIMFilterGroupByDisplayNameExcludingMembers() {
	created := ts.createSCIMGroupWithExternalID("YWWBHTHEMMLR", "94631638-0b6c-4b97-a369-aba35a454041")

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups?excludedAttributes=members&filter=displayName+eq+%22YWWBHTHEMMLR%22", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMListResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaListResponse, result.Schemas[0])
	require.Equal(ts.T(), 1, result.TotalResults)
	require.Equal(ts.T(), 1, result.StartIndex)
	require.Equal(ts.T(), 1, result.ItemsPerPage)
	require.Len(ts.T(), result.Resources, 1)

	resource := result.Resources[0].(map[string]interface{})
	require.Equal(ts.T(), created.ID, resource["id"])
	require.Equal(ts.T(), "YWWBHTHEMMLR", resource["displayName"])
	require.Equal(ts.T(), "94631638-0b6c-4b97-a369-aba35a454041", resource["externalId"])

	_, hasMembers := resource["members"]
	require.False(ts.T(), hasMembers, "Response should exclude members attribute")

	schemas := resource["schemas"].([]interface{})
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), SCIMSchemaGroup, schemas[0])

	meta := resource["meta"].(map[string]interface{})
	require.Equal(ts.T(), "Group", meta["resourceType"])
	require.NotEmpty(ts.T(), meta["created"])
	require.NotEmpty(ts.T(), meta["lastModified"])
	require.Contains(ts.T(), meta["location"], "/scim/v2/Groups/"+created.ID)
}

func (ts *SCIMTestSuite) TestSCIMFilterGroupByDisplayNameNonExistent() {
	ts.createSCIMGroup("SomeExistingGroup")

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups?filter=displayName+eq+%22nonexistente997dccbd8b7_EOKNVHIYLTCZ%22", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMListResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaListResponse, result.Schemas[0])
	require.Equal(ts.T(), 0, result.TotalResults)
	require.Equal(ts.T(), 1, result.StartIndex)
	require.Equal(ts.T(), 0, result.ItemsPerPage)
	require.Len(ts.T(), result.Resources, 0)
}

func (ts *SCIMTestSuite) TestSCIMFilterGroupByDisplayNameCaseInsensitive() {
	created := ts.createSCIMGroupWithExternalID("YWWBHTHEMMLR", "94631638-0b6c-4b97-a369-aba35a454041")

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups?filter=displayName+eq+%22ywwbhthemmlr%22", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMListResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaListResponse, result.Schemas[0])
	require.Equal(ts.T(), 1, result.TotalResults)
	require.Equal(ts.T(), 1, result.StartIndex)
	require.Equal(ts.T(), 1, result.ItemsPerPage)
	require.Len(ts.T(), result.Resources, 1)

	resource := result.Resources[0].(map[string]interface{})
	require.Equal(ts.T(), created.ID, resource["id"])
	require.Equal(ts.T(), "YWWBHTHEMMLR", resource["displayName"])
	require.Equal(ts.T(), "94631638-0b6c-4b97-a369-aba35a454041", resource["externalId"])

	schemas := resource["schemas"].([]interface{})
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), SCIMSchemaGroup, schemas[0])

	meta := resource["meta"].(map[string]interface{})
	require.Equal(ts.T(), "Group", meta["resourceType"])
	require.NotEmpty(ts.T(), meta["created"])
	require.NotEmpty(ts.T(), meta["lastModified"])
	require.Contains(ts.T(), meta["location"], "/scim/v2/Groups/"+created.ID)
}
