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

type scimTestUser struct {
	UserName   string
	Email      string
	GivenName  string
	FamilyName string
	Formatted  string
	ExternalID string
}

type scimTestGroup struct {
	DisplayName string
	ExternalID  string
}

var (
	testUser1  = scimTestUser{UserName: "user1@acme.com", Email: "user1@acme.com"}
	testUser2  = scimTestUser{UserName: "user2@acme.com", Email: "user2@acme.com", GivenName: "Test", FamilyName: "User", Formatted: "Test User"}
	testUser3  = scimTestUser{UserName: "user3@acme.com", Email: "user3@acme.com", ExternalID: "ext-001"}
	testUser4  = scimTestUser{UserName: "user4@acme.com", Email: "user4@acme.com"}
	testUser5  = scimTestUser{UserName: "user5@acme.com", Email: "user5@acme.com"}
	testUser6  = scimTestUser{UserName: "user6@example.com", Email: "user6@example.com"}
	testUser7  = scimTestUser{UserName: "user7@example.com", Email: "user7@example.com"}
	testUser8  = scimTestUser{UserName: "user8@example.com", Email: "user8@example.com"}
	testUser9  = scimTestUser{UserName: "user9@acme.com", Email: "user9@acme.com", GivenName: "Jane", FamilyName: "Doe", Formatted: "Jane Doe", ExternalID: "ext-002"}
	testUser10 = scimTestUser{UserName: "user10@acme.com", Email: "user10@acme.com", GivenName: "John", FamilyName: "Smith", Formatted: "John Smith", ExternalID: "ext-003"}
	testUser11 = scimTestUser{UserName: "user11@acme.com", Email: "user11@acme.com", ExternalID: "ext-004"}
	testUser12 = scimTestUser{UserName: "user12@acme.com", Email: "user12@acme.com", ExternalID: "ext-005"}
	testUser13 = scimTestUser{UserName: "user13@example.com", Email: "user13@example.com", ExternalID: "ext-006"}
	testUser14 = scimTestUser{UserName: "user14@acme.com", Email: "user14@acme.com", ExternalID: "ext-007"}
	testUser15 = scimTestUser{UserName: "user15@acme.com", Email: "user15@acme.com", ExternalID: "ext-008"}
	testUser16 = scimTestUser{UserName: "user16@example.com", Email: "user16@example.com", ExternalID: "ext-009"}

	testGroup1 = scimTestGroup{DisplayName: "Engineering", ExternalID: "grp-001"}
	testGroup2 = scimTestGroup{DisplayName: "Sales", ExternalID: "grp-002"}
	testGroup3 = scimTestGroup{DisplayName: "Marketing", ExternalID: "grp-003"}
	testGroup4 = scimTestGroup{DisplayName: "Platform", ExternalID: "grp-004"}
	testGroup5 = scimTestGroup{DisplayName: "Support", ExternalID: "grp-005"}
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
	user := ts.createSCIMUser(testUser1.UserName, testUser1.Email)

	require.NotEmpty(ts.T(), user.ID)
	require.Equal(ts.T(), testUser1.UserName, user.UserName)
	require.True(ts.T(), user.Active)
	require.Len(ts.T(), user.Emails, 1)
	require.Equal(ts.T(), testUser1.Email, user.Emails[0].Value)
}

func (ts *SCIMTestSuite) TestSCIMCreateGroup() {
	group := ts.createSCIMGroup(testGroup1.DisplayName)

	require.NotEmpty(ts.T(), group.ID)
	require.Equal(ts.T(), testGroup1.DisplayName, group.DisplayName)
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
	user := ts.createSCIMUserWithName(testUser2.UserName, testUser2.Email, testUser2.GivenName, testUser2.FamilyName)

	require.NotEmpty(ts.T(), user.ID)
	require.Equal(ts.T(), testUser2.UserName, user.UserName)
	require.NotNil(ts.T(), user.Name)
	require.Equal(ts.T(), testUser2.GivenName, user.Name.GivenName)
	require.Equal(ts.T(), testUser2.FamilyName, user.Name.FamilyName)
	require.Equal(ts.T(), testUser2.Formatted, user.Name.Formatted)
}

func (ts *SCIMTestSuite) TestSCIMCreateUserWithExternalID() {
	user := ts.createSCIMUserWithExternalID(testUser3.UserName, testUser3.Email, testUser3.ExternalID)

	require.NotEmpty(ts.T(), user.ID)
	require.Equal(ts.T(), testUser3.UserName, user.UserName)
	require.Equal(ts.T(), testUser3.ExternalID, user.ExternalID)
}

func (ts *SCIMTestSuite) TestSCIMGetUser() {
	created := ts.createSCIMUser(testUser4.UserName, testUser4.Email)

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users/"+created.ID, nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Equal(ts.T(), created.ID, result.ID)
	require.Equal(ts.T(), testUser4.UserName, result.UserName)
}

func (ts *SCIMTestSuite) TestSCIMGetGroup() {
	created := ts.createSCIMGroup(testGroup2.DisplayName)

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups/"+created.ID, nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Equal(ts.T(), created.ID, result.ID)
	require.Equal(ts.T(), testGroup2.DisplayName, result.DisplayName)
}

func (ts *SCIMTestSuite) TestSCIMListUsersWithData() {
	ts.createSCIMUser(testUser1.UserName, testUser1.Email)
	ts.createSCIMUser(testUser2.UserName, testUser2.Email)
	ts.createSCIMUser(testUser3.UserName, testUser3.Email)

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	result := ts.assertSCIMListResponse(w, 3)
	require.Len(ts.T(), result.Resources, 3)
}

func (ts *SCIMTestSuite) TestSCIMListGroupsWithData() {
	ts.createSCIMGroup(testGroup1.DisplayName)
	ts.createSCIMGroup(testGroup3.DisplayName)

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	result := ts.assertSCIMListResponse(w, 2)
	require.Len(ts.T(), result.Resources, 2)
}

func (ts *SCIMTestSuite) TestSCIMDeleteUser() {
	user := ts.createSCIMUser(testUser5.UserName, testUser5.Email)

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
	group := ts.createSCIMGroup(testGroup4.DisplayName)

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
	user1 := ts.createSCIMUser(testUser6.UserName, testUser6.Email)
	user2 := ts.createSCIMUser(testUser7.UserName, testUser7.Email)

	group := ts.createSCIMGroupWithMembers(testGroup5.DisplayName, []string{user1.ID, user2.ID})

	require.NotEmpty(ts.T(), group.ID)
	require.Equal(ts.T(), testGroup5.DisplayName, group.DisplayName)
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
		ts.createSCIMUser(fmt.Sprintf("pageuser%d@acme.com", i), fmt.Sprintf("pageuser%d@acme.com", i))
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
		"userName":   testUser9.UserName,
		"externalId": testUser9.ExternalID,
		"name": map[string]interface{}{
			"formatted":  testUser9.Formatted,
			"familyName": testUser9.FamilyName,
			"givenName":  testUser9.GivenName,
		},
		"emails": []map[string]interface{}{
			{"primary": true, "value": testUser9.Email},
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
	require.Equal(ts.T(), testUser9.ExternalID, result.ExternalID)
	require.Equal(ts.T(), testUser9.UserName, result.UserName)
	require.NotNil(ts.T(), result.Name)
	require.Equal(ts.T(), testUser9.Formatted, result.Name.Formatted)
	require.Equal(ts.T(), testUser9.FamilyName, result.Name.FamilyName)
	require.Equal(ts.T(), testUser9.GivenName, result.Name.GivenName)
	require.Len(ts.T(), result.Emails, 1)
	require.Equal(ts.T(), testUser9.Email, result.Emails[0].Value)
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
		"userName":   testUser10.UserName,
		"externalId": testUser10.ExternalID,
		"name": map[string]interface{}{
			"formatted":  testUser10.Formatted,
			"familyName": testUser10.FamilyName,
			"givenName":  testUser10.GivenName,
		},
		"emails": []map[string]interface{}{
			{"primary": true, "value": testUser10.Email},
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
	user := ts.createSCIMUserWithExternalID(testUser11.UserName, testUser11.Email, testUser11.ExternalID)

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
	user := ts.createSCIMUserWithExternalID(testUser12.UserName, testUser12.Email, testUser12.ExternalID)

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
	created := ts.createSCIMUserWithExternalID(testUser13.UserName, testUser13.Email, testUser13.ExternalID)

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users?filter=userName+eq+%22user13%40example.com%22", nil)
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
	require.Equal(ts.T(), testUser13.UserName, resource["userName"])
	require.Equal(ts.T(), testUser13.ExternalID, resource["externalId"])
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
	ts.createSCIMUser(testUser8.UserName, testUser8.Email)

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
	created := ts.createSCIMUserWithExternalID(testUser14.UserName, testUser14.Email, testUser14.ExternalID)

	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users?filter=userName+eq+%22USER14%40ACME.COM%22", nil)
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
	require.Equal(ts.T(), testUser14.UserName, resource["userName"])
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
	user := ts.createSCIMUserWithExternalID(testUser15.UserName, testUser15.Email, testUser15.ExternalID)
	newUserName := "sam.updated@acme.com"

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "value": map[string]interface{}{"userName": newUserName}},
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
	require.Equal(ts.T(), testUser15.ExternalID, result.ExternalID)
	require.Equal(ts.T(), newUserName, result.UserName)
	require.True(ts.T(), result.Active)
	require.Equal(ts.T(), "User", result.Meta.ResourceType)
	require.NotNil(ts.T(), result.Meta.Created)
	require.NotNil(ts.T(), result.Meta.LastModified)
	require.Contains(ts.T(), result.Meta.Location, "/scim/v2/Users/"+result.ID)
}

func (ts *SCIMTestSuite) TestSCIMPatchUserDisable() {
	user := ts.createSCIMUserWithExternalID(testUser16.UserName, testUser16.Email, testUser16.ExternalID)

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
	require.Equal(ts.T(), testUser16.ExternalID, result.ExternalID)
	require.Equal(ts.T(), testUser16.UserName, result.UserName)
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
	origUserName := "patchemail@acme.com"
	origEmail := "patchemail@acme.com"
	newEmail := "updated.email@acme.com"
	user := ts.createSCIMUserWithExternalID(origUserName, origEmail, "ext-patch-email-001")

	require.Len(ts.T(), user.Emails, 1)
	require.Equal(ts.T(), origEmail, user.Emails[0].Value)

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "emails[primary eq true].value", "value": newEmail},
			{"op": "replace", "value": map[string]interface{}{
				"name.formatted":  "Updated Name",
				"name.familyName": "Name",
				"name.givenName":  "Updated",
				"active":          true,
				"externalId":      "ext-patch-email-002",
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
	require.Equal(ts.T(), "ext-patch-email-002", result.ExternalID)
	require.Equal(ts.T(), origUserName, result.UserName)
	require.NotNil(ts.T(), result.Name)
	require.Equal(ts.T(), "Updated Name", result.Name.Formatted)
	require.Equal(ts.T(), "Name", result.Name.FamilyName)
	require.Equal(ts.T(), "Updated", result.Name.GivenName)
	require.True(ts.T(), result.Active)

	require.Len(ts.T(), result.Emails, 1)
	require.Equal(ts.T(), newEmail, result.Emails[0].Value)
	require.True(ts.T(), bool(result.Emails[0].Primary))

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users/"+user.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var getResult SCIMUserResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&getResult))
	require.Len(ts.T(), getResult.Emails, 1)
	require.Equal(ts.T(), newEmail, getResult.Emails[0].Value)
}

func (ts *SCIMTestSuite) TestSCIMPatchUserMultipleOperationsSameAttribute() {
	userName := "multiop@acme.com"
	user := ts.createSCIMUserWithExternalID(userName, userName, "ext-multi-001")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "remove", "path": "externalId"},
			{"op": "add", "value": map[string]interface{}{"externalId": "ext-multi-002"}},
			{"op": "replace", "value": map[string]interface{}{"externalId": "ext-multi-003"}},
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
	require.Equal(ts.T(), "ext-multi-003", result.ExternalID)
	require.Equal(ts.T(), userName, result.UserName)
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

func (ts *SCIMTestSuite) TestSCIMPatchGroupReplaceExternalID() {
	group := ts.createSCIMGroupWithExternalID("SFSNYLFDSMIG", "643a3bd4-43e1-481a-9ea6-bd82d65bbd04")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "value": map[string]interface{}{"externalId": "3d413e4f-7404-45e9-86b9-478c9b6a894a"}},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Groups/"+group.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaGroup, result.Schemas[0])
	require.Equal(ts.T(), group.ID, result.ID)
	require.Equal(ts.T(), "3d413e4f-7404-45e9-86b9-478c9b6a894a", result.ExternalID)
	require.Equal(ts.T(), "SFSNYLFDSMIG", result.DisplayName)
	require.Equal(ts.T(), "Group", result.Meta.ResourceType)
	require.NotNil(ts.T(), result.Meta.Created)
	require.NotNil(ts.T(), result.Meta.LastModified)
	require.Contains(ts.T(), result.Meta.Location, "/scim/v2/Groups/"+result.ID)

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups/"+group.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var getResult SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&getResult))
	require.Equal(ts.T(), "3d413e4f-7404-45e9-86b9-478c9b6a894a", getResult.ExternalID)
}

func (ts *SCIMTestSuite) TestSCIMPatchGroupUpdateDisplayName() {
	group := ts.createSCIMGroupWithExternalID("NUOSLUZYECIZ", "fa01b7f2-ab68-4f97-a211-11f5732d0e15")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "value": map[string]interface{}{"displayName": "YJCESZMOUKCA"}},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Groups/"+group.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaGroup, result.Schemas[0])
	require.Equal(ts.T(), group.ID, result.ID)
	require.Equal(ts.T(), "fa01b7f2-ab68-4f97-a211-11f5732d0e15", result.ExternalID)
	require.Equal(ts.T(), "YJCESZMOUKCA", result.DisplayName)
	require.Equal(ts.T(), "Group", result.Meta.ResourceType)
	require.NotNil(ts.T(), result.Meta.Created)
	require.NotNil(ts.T(), result.Meta.LastModified)
	require.Contains(ts.T(), result.Meta.Location, "/scim/v2/Groups/"+result.ID)

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups/"+group.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var getResult SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&getResult))
	require.Equal(ts.T(), "YJCESZMOUKCA", getResult.DisplayName)
}

func (ts *SCIMTestSuite) TestSCIMPatchGroupAddMember() {
	groupName := "AddMemberGroup"
	groupExtID := "grp-add-001"
	memberEmail := "member1@acme.com"
	group := ts.createSCIMGroupWithExternalID(groupName, groupExtID)
	user := ts.createSCIMUserWithExternalID(memberEmail, memberEmail, "usr-member-001")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "members", "value": []map[string]interface{}{
				{"value": user.ID},
			}},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Groups/"+group.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaGroup, result.Schemas[0])
	require.Equal(ts.T(), group.ID, result.ID)
	require.Equal(ts.T(), groupExtID, result.ExternalID)
	require.Equal(ts.T(), groupName, result.DisplayName)
	require.Len(ts.T(), result.Members, 1)
	require.Equal(ts.T(), user.ID, result.Members[0].Value)
	require.Contains(ts.T(), result.Members[0].Ref, "/scim/v2/Users/"+user.ID)
	require.Equal(ts.T(), memberEmail, result.Members[0].Display)
	require.Equal(ts.T(), "Group", result.Meta.ResourceType)
	require.NotNil(ts.T(), result.Meta.Created)
	require.NotNil(ts.T(), result.Meta.LastModified)
	require.Contains(ts.T(), result.Meta.Location, "/scim/v2/Groups/"+result.ID)

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups/"+group.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var getResult SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&getResult))
	require.Len(ts.T(), getResult.Members, 1)
	require.Equal(ts.T(), user.ID, getResult.Members[0].Value)
}

func (ts *SCIMTestSuite) TestSCIMPatchGroupRemoveMember() {
	groupName := "RemoveMemberGroup"
	groupExtID := "grp-remove-001"
	member1Email := "member2@acme.com"
	member2Email := "member3@acme.com"
	group := ts.createSCIMGroupWithExternalID(groupName, groupExtID)
	user1 := ts.createSCIMUserWithExternalID(member1Email, member1Email, "usr-member-002")
	user2 := ts.createSCIMUserWithExternalID(member2Email, member2Email, "usr-member-003")

	addMembersBody := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "members", "value": []map[string]interface{}{
				{"value": user1.ID},
				{"value": user2.ID},
			}},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Groups/"+group.ID, addMembersBody)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var addResult SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&addResult))
	require.Len(ts.T(), addResult.Members, 2)

	removeMemberBody := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "remove", "path": fmt.Sprintf("members[value eq \"%s\"]", user1.ID)},
		},
	}

	req = ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Groups/"+group.ID, removeMemberBody)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaGroup, result.Schemas[0])
	require.Equal(ts.T(), group.ID, result.ID)
	require.Equal(ts.T(), groupExtID, result.ExternalID)
	require.Equal(ts.T(), groupName, result.DisplayName)
	require.Len(ts.T(), result.Members, 1)
	require.Equal(ts.T(), user2.ID, result.Members[0].Value)
	require.Contains(ts.T(), result.Members[0].Ref, "/scim/v2/Users/"+user2.ID)
	require.Equal(ts.T(), member2Email, result.Members[0].Display)
	require.Equal(ts.T(), "Group", result.Meta.ResourceType)
	require.NotNil(ts.T(), result.Meta.Created)
	require.NotNil(ts.T(), result.Meta.LastModified)
	require.Contains(ts.T(), result.Meta.Location, "/scim/v2/Groups/"+result.ID)

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups/"+group.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var getResult SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&getResult))
	require.Len(ts.T(), getResult.Members, 1)
	require.Equal(ts.T(), user2.ID, getResult.Members[0].Value)
}

func (ts *SCIMTestSuite) TestSCIMPatchGroupMultipleOperationsAddThenRemoveMember() {
	groupName := "MultiOpGroup"
	groupExtID := "grp-multiop-001"
	memberEmail := "member4@acme.com"
	group := ts.createSCIMGroupWithExternalID(groupName, groupExtID)
	user := ts.createSCIMUserWithExternalID(memberEmail, memberEmail, "usr-member-004")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "add", "path": "members", "value": []map[string]interface{}{
				{"value": user.ID},
			}},
			{"op": "remove", "path": fmt.Sprintf("members[value eq \"%s\"]", user.ID)},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Groups/"+group.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))

	require.Len(ts.T(), result.Schemas, 1)
	require.Equal(ts.T(), SCIMSchemaGroup, result.Schemas[0])
	require.Equal(ts.T(), group.ID, result.ID)
	require.Equal(ts.T(), groupExtID, result.ExternalID)
	require.Equal(ts.T(), groupName, result.DisplayName)
	require.Empty(ts.T(), result.Members)
	require.Equal(ts.T(), "Group", result.Meta.ResourceType)
	require.NotNil(ts.T(), result.Meta.Created)
	require.NotNil(ts.T(), result.Meta.LastModified)
	require.Contains(ts.T(), result.Meta.Location, "/scim/v2/Groups/"+result.ID)

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups/"+group.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var getResult SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&getResult))
	require.Empty(ts.T(), getResult.Members)
}

func (ts *SCIMTestSuite) TestSCIMPatchGroupNotFound() {
	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "value": map[string]interface{}{"displayName": "NewName"}},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Groups/00000000-0000-0000-0000-000000000000", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	ts.assertSCIMError(w, http.StatusNotFound)
}

func (ts *SCIMTestSuite) TestSCIMPatchGroupUpdateDisplayNameWithPath() {
	group := ts.createSCIMGroupWithExternalID("ORIGINALNAME", "path-test-ext-id")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "displayName", "value": "NEWDISPLAYNAME"},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Groups/"+group.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))
	require.Equal(ts.T(), "NEWDISPLAYNAME", result.DisplayName)

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups/"+group.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var getResult SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&getResult))
	require.Equal(ts.T(), "NEWDISPLAYNAME", getResult.DisplayName)
}

func (ts *SCIMTestSuite) TestSCIMPatchGroupAddMemberWithAddOp() {
	group := ts.createSCIMGroup("AddOpTestGroup")
	user := ts.createSCIMUser("addop_member@test.com", "addop_member@test.com")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "add", "path": "members", "value": []map[string]interface{}{
				{"value": user.ID},
			}},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Groups/"+group.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))
	require.Len(ts.T(), result.Members, 1)
	require.Equal(ts.T(), user.ID, result.Members[0].Value)

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups/"+group.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var getResult SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&getResult))
	require.Len(ts.T(), getResult.Members, 1)
	require.Equal(ts.T(), user.ID, getResult.Members[0].Value)
}

func (ts *SCIMTestSuite) TestSCIMPatchGroupRemoveAllMembers() {
	user1 := ts.createSCIMUser("remove_all_member1@test.com", "remove_all_member1@test.com")
	user2 := ts.createSCIMUser("remove_all_member2@test.com", "remove_all_member2@test.com")
	group := ts.createSCIMGroupWithMembers("RemoveAllMembersGroup", []string{user1.ID, user2.ID})

	require.Len(ts.T(), group.Members, 2)

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "members", "value": []map[string]interface{}{}},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Groups/"+group.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var result SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&result))
	require.Empty(ts.T(), result.Members)

	req = ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups/"+group.ID, nil)
	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	var getResult SCIMGroupResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&getResult))
	require.Empty(ts.T(), getResult.Members)
}

func (ts *SCIMTestSuite) TestSCIMAuthMissingAuthorizationHeader() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/scim/v2/Users", nil)
	req.Header.Set("Content-Type", "application/scim+json")
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusUnauthorized, w.Code)

	var errorResp map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errorResp))

	schemas, ok := errorResp["schemas"].([]interface{})
	require.True(ts.T(), ok, "SCIM error should have schemas field")
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), "urn:ietf:params:scim:api:messages:2.0:Error", schemas[0])

	detail, ok := errorResp["detail"].(string)
	require.True(ts.T(), ok, "SCIM error should have detail field")
	require.NotEmpty(ts.T(), detail)

	status, ok := errorResp["status"].(string)
	require.True(ts.T(), ok, "SCIM error should have status field as string per RFC 7644")
	require.Equal(ts.T(), "401", status)
}

func (ts *SCIMTestSuite) TestSCIMAuthInvalidBearerToken() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer completely-invalid-token-xyz")
	req.Header.Set("Content-Type", "application/scim+json")
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusUnauthorized, w.Code)

	var errorResp map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errorResp))

	schemas, ok := errorResp["schemas"].([]interface{})
	require.True(ts.T(), ok, "SCIM error should have schemas field")
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), "urn:ietf:params:scim:api:messages:2.0:Error", schemas[0])

	detail, ok := errorResp["detail"].(string)
	require.True(ts.T(), ok, "SCIM error should have detail field")
	require.NotEmpty(ts.T(), detail)

	status, ok := errorResp["status"].(string)
	require.True(ts.T(), ok, "SCIM error should have status field as string per RFC 7644")
	require.Equal(ts.T(), "401", status)
}

func (ts *SCIMTestSuite) TestSCIMAuthMalformedAuthorizationHeader() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	req.Header.Set("Content-Type", "application/scim+json")
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusUnauthorized, w.Code)

	var errorResp map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errorResp))

	schemas, ok := errorResp["schemas"].([]interface{})
	require.True(ts.T(), ok, "SCIM error should have schemas field")
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), "urn:ietf:params:scim:api:messages:2.0:Error", schemas[0])

	status, ok := errorResp["status"].(string)
	require.True(ts.T(), ok, "SCIM error should have status field")
	require.Equal(ts.T(), "401", status)
}

func (ts *SCIMTestSuite) TestSCIMAuthEmptyBearerToken() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer ")
	req.Header.Set("Content-Type", "application/scim+json")
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusUnauthorized, w.Code)

	var errorResp map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errorResp))

	schemas, ok := errorResp["schemas"].([]interface{})
	require.True(ts.T(), ok, "SCIM error should have schemas field")
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), "urn:ietf:params:scim:api:messages:2.0:Error", schemas[0])

	status, ok := errorResp["status"].(string)
	require.True(ts.T(), ok, "SCIM error should have status field")
	require.Equal(ts.T(), "401", status)
}

func (ts *SCIMTestSuite) TestSCIMErrorInvalidFilterSyntax() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users?filter=invalid+++syntax", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	ts.assertSCIMErrorWithType(w, http.StatusBadRequest, "invalidFilter")
}

func (ts *SCIMTestSuite) TestSCIMErrorInvalidFilterUnclosedQuote() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users?filter=userName+eq+%22unclosed", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	ts.assertSCIMErrorWithType(w, http.StatusBadRequest, "invalidFilter")
}

func (ts *SCIMTestSuite) TestSCIMErrorInvalidFilterUnsupportedAttribute() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users?filter=unsupportedAttr+eq+%22value%22", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	ts.assertSCIMErrorWithType(w, http.StatusBadRequest, "invalidFilter")
}

func (ts *SCIMTestSuite) TestSCIMErrorInvalidFilterGroupUnsupportedAttribute() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups?filter=invalidAttr+eq+%22value%22", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	ts.assertSCIMErrorWithType(w, http.StatusBadRequest, "invalidFilter")
}

func (ts *SCIMTestSuite) TestSCIMErrorInvalidPatchOperationCopy() {
	user := ts.createSCIMUser("patch_copy_op@test.com", "patch_copy_op@test.com")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "copy", "from": "userName", "path": "externalId"},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Users/"+user.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	ts.assertSCIMErrorWithType(w, http.StatusBadRequest, "invalidSyntax")
}

func (ts *SCIMTestSuite) TestSCIMErrorInvalidPatchOperationMove() {
	user := ts.createSCIMUser("patch_move_op@test.com", "patch_move_op@test.com")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
		"Operations": []map[string]interface{}{
			{"op": "move", "from": "userName", "path": "externalId"},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Users/"+user.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	ts.assertSCIMErrorWithType(w, http.StatusBadRequest, "invalidSyntax")
}

func (ts *SCIMTestSuite) TestSCIMErrorInvalidPatchMissingOperations() {
	user := ts.createSCIMUser("patch_missing_ops@test.com", "patch_missing_ops@test.com")

	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaPatchOp},
	}

	req := ts.makeSCIMRequest(http.MethodPatch, "/scim/v2/Users/"+user.ID, body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *SCIMTestSuite) TestSCIMErrorInvalidJSON() {
	req := httptest.NewRequest(http.MethodPost, "http://localhost/scim/v2/Users", bytes.NewBuffer([]byte("{invalid json")))
	req.Header.Set("Authorization", "Bearer "+ts.SCIMToken)
	req.Header.Set("Content-Type", "application/scim+json")
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	ts.assertSCIMErrorWithType(w, http.StatusBadRequest, "invalidSyntax")
}

func (ts *SCIMTestSuite) TestSCIMErrorResponseFormatUsers() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Users/00000000-0000-0000-0000-000000000000", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusNotFound, w.Code)

	var errorResp map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errorResp))

	schemas, ok := errorResp["schemas"].([]interface{})
	require.True(ts.T(), ok, "SCIM error must have schemas field per RFC 7644")
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), "urn:ietf:params:scim:api:messages:2.0:Error", schemas[0])

	detail, ok := errorResp["detail"].(string)
	require.True(ts.T(), ok, "SCIM error must have detail field per RFC 7644")
	require.NotEmpty(ts.T(), detail)

	status, ok := errorResp["status"].(string)
	require.True(ts.T(), ok, "SCIM error status must be a string per RFC 7644")
	require.Equal(ts.T(), "404", status)
}

func (ts *SCIMTestSuite) TestSCIMErrorResponseFormatGroups() {
	req := ts.makeSCIMRequest(http.MethodGet, "/scim/v2/Groups/00000000-0000-0000-0000-000000000000", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusNotFound, w.Code)

	var errorResp map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errorResp))

	schemas, ok := errorResp["schemas"].([]interface{})
	require.True(ts.T(), ok, "SCIM error must have schemas field per RFC 7644")
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), "urn:ietf:params:scim:api:messages:2.0:Error", schemas[0])

	detail, ok := errorResp["detail"].(string)
	require.True(ts.T(), ok, "SCIM error must have detail field per RFC 7644")
	require.NotEmpty(ts.T(), detail)

	status, ok := errorResp["status"].(string)
	require.True(ts.T(), ok, "SCIM error status must be a string per RFC 7644")
	require.Equal(ts.T(), "404", status)
}

func (ts *SCIMTestSuite) TestSCIMErrorSchemaValidationMissingRequiredField() {
	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaUser},
		"emails": []map[string]interface{}{
			{"value": "test@example.com", "primary": true},
		},
	}

	req := ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Users", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusBadRequest, w.Code)

	var errorResp map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errorResp))

	schemas, ok := errorResp["schemas"].([]interface{})
	require.True(ts.T(), ok, "SCIM error should have schemas field")
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), "urn:ietf:params:scim:api:messages:2.0:Error", schemas[0])

	detail, ok := errorResp["detail"].(string)
	require.True(ts.T(), ok, "SCIM error should have detail field")
	require.Contains(ts.T(), detail, "userName")

	status, ok := errorResp["status"].(string)
	require.True(ts.T(), ok, "SCIM error should have status field")
	require.Equal(ts.T(), "400", status)

	scimType, ok := errorResp["scimType"].(string)
	require.True(ts.T(), ok, "SCIM error should have scimType field")
	require.Equal(ts.T(), "invalidSyntax", scimType)
}

func (ts *SCIMTestSuite) TestSCIMErrorGroupSchemaValidationMissingDisplayName() {
	body := map[string]interface{}{
		"schemas": []string{SCIMSchemaGroup},
	}

	req := ts.makeSCIMRequest(http.MethodPost, "/scim/v2/Groups", body)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusBadRequest, w.Code)

	var errorResp map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errorResp))

	schemas, ok := errorResp["schemas"].([]interface{})
	require.True(ts.T(), ok, "SCIM error should have schemas field")
	require.Len(ts.T(), schemas, 1)
	require.Equal(ts.T(), "urn:ietf:params:scim:api:messages:2.0:Error", schemas[0])

	detail, ok := errorResp["detail"].(string)
	require.True(ts.T(), ok, "SCIM error should have detail field")
	require.Contains(ts.T(), detail, "displayName")

	status, ok := errorResp["status"].(string)
	require.True(ts.T(), ok, "SCIM error should have status field")
	require.Equal(ts.T(), "400", status)

	scimType, ok := errorResp["scimType"].(string)
	require.True(ts.T(), ok, "SCIM error should have scimType field")
	require.Equal(ts.T(), "invalidSyntax", scimType)
}
