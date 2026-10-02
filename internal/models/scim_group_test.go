package models

import (
	"fmt"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/storage"
)

type SCIMGroupTestSuite struct {
	suite.Suite
	db       *storage.Connection
	provider *SSOProvider
}

func TestSCIMGroup(t *testing.T) {
	ts := &SCIMGroupTestSuite{db: setupSCIMTestDB(t)}
	defer func() { require.NoError(t, ts.db.Close()) }()
	suite.Run(t, ts)
}

func (ts *SCIMGroupTestSuite) SetupTest() {
	require.NoError(ts.T(), TruncateAll(ts.db))
	ts.provider = ts.createProvider()
}

func (ts *SCIMGroupTestSuite) TestCreate() {
	group, err := CreateSCIMGroup(ts.db, ts.provider.ID, []byte(`{"displayName":"Engineering","externalId":"ext-1"}`))
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), ts.provider.ID, group.SSOProviderID)
	require.Equal(ts.T(), "engineering", group.DisplayName)
	require.Equal(ts.T(), "ext-1", *group.ExternalID)
	require.JSONEq(ts.T(), `{"displayName":"Engineering","externalId":"ext-1"}`, string(group.Resource))
	require.False(ts.T(), group.CreatedAt.IsZero())
}

func (ts *SCIMGroupTestSuite) TestCreateAllowsDuplicateDisplayName() {
	ts.createGroup(ts.provider.ID, "Engineering")
	ts.createGroup(ts.provider.ID, "engineering")
}

func (ts *SCIMGroupTestSuite) TestCreateRejectsDuplicateExternalID() {
	_, err := CreateSCIMGroup(ts.db, ts.provider.ID, []byte(`{"displayName":"A","externalId":"ext-1"}`))
	require.NoError(ts.T(), err)

	_, err = CreateSCIMGroup(ts.db, ts.provider.ID, []byte(`{"displayName":"B","externalId":"ext-1"}`))
	require.ErrorIs(ts.T(), err, SCIMGroupConflictError{})

	other := ts.createProvider()
	_, err = CreateSCIMGroup(ts.db, other.ID, []byte(`{"displayName":"C","externalId":"ext-1"}`))
	require.NoError(ts.T(), err)
}

func (ts *SCIMGroupTestSuite) TestFindIsScopedToProvider() {
	group := ts.createGroup(ts.provider.ID, "Engineering")

	found, err := FindSCIMGroup(ts.db, ts.provider.ID, group.ID)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), group.ID, found.ID)

	other := ts.createProvider()
	_, err = FindSCIMGroup(ts.db, other.ID, group.ID)
	require.ErrorIs(ts.T(), err, SCIMNotFoundError{})
	require.True(ts.T(), IsNotFoundError(err))
}

func (ts *SCIMGroupTestSuite) TestFindGroupsFiltersAndSorts() {
	ts.createGroup(ts.provider.ID, "Beta")
	ts.createGroup(ts.provider.ID, "alpha")
	ts.createGroup(ts.createProvider().ID, "Alpha")

	displayName := "ALPHA"
	groups, total, err := FindSCIMGroups(ts.db, ts.provider.ID, SCIMQuery{Filter: SCIMFilter{Name: &displayName}, Limit: 10})
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), 1, total)
	require.Equal(ts.T(), "alpha", groups[0].DisplayName)

	groups, total, err = FindSCIMGroups(ts.db, ts.provider.ID, SCIMQuery{Order: SCIMOrder{By: SCIMSortByName, Descending: true}, Limit: 10})
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), 2, total)
	require.Equal(ts.T(), "beta", groups[0].DisplayName)
	require.Equal(ts.T(), "alpha", groups[1].DisplayName)

	groups, total, err = FindSCIMGroups(ts.db, ts.provider.ID, SCIMQuery{})
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), 2, total)
	require.Empty(ts.T(), groups)
}

func (ts *SCIMGroupTestSuite) TestReplaceChecksVersion() {
	group := ts.createGroup(ts.provider.ID, "Engineering")

	replaced, changed, err := ReplaceSCIMGroupIfChanged(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: group.ID, UpdatedAt: &group.UpdatedAt}, []byte(`{"displayName":"Platform"}`))
	require.NoError(ts.T(), err)
	require.True(ts.T(), changed)
	require.Equal(ts.T(), "platform", replaced.DisplayName)

	_, _, err = ReplaceSCIMGroupIfChanged(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: group.ID, UpdatedAt: &group.UpdatedAt}, []byte(`{"displayName":"Stale"}`))
	require.ErrorIs(ts.T(), err, SCIMStaleError{})

	_, _, err = ReplaceSCIMGroupIfChanged(ts.db, SCIMTarget{ProviderID: ts.createProvider().ID, ID: group.ID}, []byte(`{"displayName":"Other"}`))
	require.ErrorIs(ts.T(), err, SCIMNotFoundError{})
}

func (ts *SCIMGroupTestSuite) TestEachWriteInATransactionGetsANewVersion() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "alice")

	require.NoError(ts.T(), ts.db.Transaction(func(tx *storage.Connection) error {
		replaced, changed, err := ReplaceSCIMGroupIfChanged(tx, SCIMTarget{ProviderID: ts.provider.ID, ID: group.ID}, []byte(`{"displayName":"Platform"}`))
		require.NoError(ts.T(), err)
		require.True(ts.T(), changed)
		touched, _, err := ReplaceSCIMGroupMembers(tx, replaced, []uuid.UUID{alice.ID})
		require.NoError(ts.T(), err)
		require.True(ts.T(), touched.UpdatedAt.After(replaced.UpdatedAt))
		return nil
	}))
}

func (ts *SCIMGroupTestSuite) TestDeleteRemovesMembers() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	user := ts.createUser(ts.provider.ID, "alice")
	_, _, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{user.ID})
	require.NoError(ts.T(), err)

	_, err = DeleteSCIMGroup(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: group.ID})
	require.NoError(ts.T(), err)

	_, err = FindSCIMGroup(ts.db, ts.provider.ID, group.ID)
	require.ErrorIs(ts.T(), err, SCIMNotFoundError{})
	count, err := ts.db.Q().Where("group_id = ?", group.ID).Count(&SCIMGroupMember{})
	require.NoError(ts.T(), err)
	require.Zero(ts.T(), count)

	_, err = DeleteSCIMGroup(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: group.ID})
	require.ErrorIs(ts.T(), err, SCIMNotFoundError{})
}

func (ts *SCIMGroupTestSuite) TestVersionedWriteToMissingRowIsNotFound() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "alice")

	_, _, err := ReplaceSCIMGroupIfChanged(ts.db, SCIMTarget{ProviderID: ts.createProvider().ID, ID: group.ID, UpdatedAt: &group.UpdatedAt}, []byte(`{"displayName":"Other"}`))
	require.ErrorIs(ts.T(), err, SCIMNotFoundError{})

	_, err = DeleteSCIMGroup(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: group.ID})
	require.NoError(ts.T(), err)
	_, err = DeleteSCIMGroup(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: group.ID, UpdatedAt: &group.UpdatedAt})
	require.ErrorIs(ts.T(), err, SCIMNotFoundError{})

	_, err = DeleteSCIMUser(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: alice.ID})
	require.NoError(ts.T(), err)
	_, err = DeleteSCIMUser(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: alice.ID, UpdatedAt: &alice.UpdatedAt})
	require.ErrorIs(ts.T(), err, SCIMNotFoundError{})
}

func (ts *SCIMGroupTestSuite) TestReplaceMembersDiffs() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "Alice")
	bob := ts.createUser(ts.provider.ID, "bob")
	carol := ts.createUser(ts.provider.ID, "carol")

	_, change, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID, bob.ID, alice.ID})
	require.NoError(ts.T(), err)
	require.ElementsMatch(ts.T(), []uuid.UUID{alice.ID, bob.ID}, change.Added)
	require.Empty(ts.T(), change.Removed)

	_, change, err = ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{bob.ID, carol.ID})
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), []uuid.UUID{carol.ID}, change.Added)
	require.Equal(ts.T(), []uuid.UUID{alice.ID}, change.Removed)

	members, err := FindSCIMMembershipsByGroup(ts.db, ts.provider.ID, []uuid.UUID{group.ID})
	require.NoError(ts.T(), err)
	require.Len(ts.T(), members, 2)
	require.ElementsMatch(ts.T(), []uuid.UUID{bob.ID, carol.ID}, []uuid.UUID{members[0].SCIMUserID, members[1].SCIMUserID})

	_, change, err = ReplaceSCIMGroupMembers(ts.db, group, nil)
	require.NoError(ts.T(), err)
	require.Empty(ts.T(), change.Added)
	require.ElementsMatch(ts.T(), []uuid.UUID{bob.ID, carol.ID}, change.Removed)
}

func (ts *SCIMGroupTestSuite) TestReplaceMembersRejectsOtherProviderUsers() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "alice")
	outsider := ts.createUser(ts.createProvider().ID, "mallory")

	_, _, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID, outsider.ID})
	require.Equal(ts.T(), SCIMGroupMemberNotFoundError{IDs: []uuid.UUID{outsider.ID}}, err)

	members, err := FindSCIMMembershipsByGroup(ts.db, ts.provider.ID, []uuid.UUID{group.ID})
	require.NoError(ts.T(), err)
	require.Empty(ts.T(), members)
}

func (ts *SCIMGroupTestSuite) TestReplaceMembersRejectsDeletedUsers() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "alice")
	_, err := DeleteSCIMUser(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: alice.ID})
	require.NoError(ts.T(), err)

	_, _, err = ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID})
	require.Equal(ts.T(), SCIMGroupMemberNotFoundError{IDs: []uuid.UUID{alice.ID}}, err)

	_, _, err = ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{uuid.Must(uuid.NewV4())})
	require.ErrorAs(ts.T(), err, &SCIMGroupMemberNotFoundError{})
}

func (ts *SCIMGroupTestSuite) TestReplaceMembersDoesNotLockExistingMembers() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "alice")
	bob := ts.createUser(ts.provider.ID, "bob")
	_, _, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID})
	require.NoError(ts.T(), err)

	deleting := ts.beginTx()
	defer func() { _ = deleting.TX.Rollback() }()
	_, err = DeleteSCIMUser(deleting, SCIMTarget{ProviderID: ts.provider.ID, ID: alice.ID})
	require.NoError(ts.T(), err)

	result := make(chan error, 1)
	go func() {
		result <- ts.db.Transaction(func(tx *storage.Connection) error {
			locked, err := FindSCIMGroup(tx, ts.provider.ID, group.ID)
			if err != nil {
				return err
			}
			_, _, err = ReplaceSCIMGroupMembers(tx, locked, []uuid.UUID{alice.ID, bob.ID})
			return err
		})
	}()
	select {
	case err := <-result:
		require.NoError(ts.T(), err)
	case <-time.After(5 * time.Second):
		ts.T().Fatal("group replace waited on a member that was not added")
	}

	require.NoError(ts.T(), RemoveSCIMUserFromGroups(deleting, alice.ID))
	require.NoError(ts.T(), deleting.TX.Commit())

	members, err := FindSCIMMembershipsByGroup(ts.db, ts.provider.ID, []uuid.UUID{group.ID})
	require.NoError(ts.T(), err)
	require.Len(ts.T(), members, 1)
	require.Equal(ts.T(), bob.ID, members[0].SCIMUserID)
}

func (ts *SCIMGroupTestSuite) TestFindMembersHidesDeletedUsers() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "alice")
	_, _, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID})
	require.NoError(ts.T(), err)

	_, err = DeleteSCIMUser(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: alice.ID})
	require.NoError(ts.T(), err)

	members, err := FindSCIMMembershipsByGroup(ts.db, ts.provider.ID, []uuid.UUID{group.ID})
	require.NoError(ts.T(), err)
	require.Empty(ts.T(), members)
}

func (ts *SCIMGroupTestSuite) TestReplaceMembersValidatesOnlyAddedMembers() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "alice")
	bob := ts.createUser(ts.provider.ID, "bob")
	_, _, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID})
	require.NoError(ts.T(), err)
	_, err = DeleteSCIMUser(ts.db, SCIMTarget{ProviderID: ts.provider.ID, ID: alice.ID})
	require.NoError(ts.T(), err)

	_, change, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID, bob.ID})
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), []uuid.UUID{bob.ID}, change.Added)
	require.Empty(ts.T(), change.Removed)

	_, _, err = ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{alice.ID, bob.ID, uuid.Nil})
	require.Equal(ts.T(), SCIMGroupMemberNotFoundError{IDs: []uuid.UUID{uuid.Nil}}, err)
}

func (ts *SCIMGroupTestSuite) TestFindMembershipsByUser() {
	engineering := ts.createGroup(ts.provider.ID, "Engineering")
	admins := ts.createGroup(ts.provider.ID, "Admins")
	alice := ts.createUser(ts.provider.ID, "alice")
	bob := ts.createUser(ts.provider.ID, "bob")
	_, _, err := ReplaceSCIMGroupMembers(ts.db, engineering, []uuid.UUID{alice.ID, bob.ID})
	require.NoError(ts.T(), err)
	_, _, err = ReplaceSCIMGroupMembers(ts.db, admins, []uuid.UUID{alice.ID})
	require.NoError(ts.T(), err)

	groups, err := FindSCIMMembershipsByUser(ts.db, ts.provider.ID, []uuid.UUID{alice.ID, bob.ID})
	require.NoError(ts.T(), err)
	require.Len(ts.T(), groups, 3)

	byUser := map[uuid.UUID][]string{}
	for _, g := range groups {
		byUser[g.SCIMUserID] = append(byUser[g.SCIMUserID], g.Display)
	}
	require.Equal(ts.T(), []string{"Admins", "Engineering"}, byUser[alice.ID])
	require.Equal(ts.T(), []string{"Engineering"}, byUser[bob.ID])

	groups, err = FindSCIMMembershipsByUser(ts.db, ts.createProvider().ID, []uuid.UUID{alice.ID})
	require.NoError(ts.T(), err)
	require.Empty(ts.T(), groups)
}

func (ts *SCIMGroupTestSuite) TestReplaceMembersReturnsMembersInRenderOrder() {
	group := ts.createGroup(ts.provider.ID, "Engineering")
	alice := ts.createUser(ts.provider.ID, "alice")
	bob := ts.createUser(ts.provider.ID, "bob")
	carol := ts.createUser(ts.provider.ID, "carol")
	_, _, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{carol.ID, alice.ID})
	require.NoError(ts.T(), err)

	_, change, err := ReplaceSCIMGroupMembers(ts.db, group, []uuid.UUID{bob.ID, carol.ID, alice.ID, bob.ID})
	require.NoError(ts.T(), err)
	require.Len(ts.T(), change.Members, 3)

	rendered, err := FindSCIMMembershipsByGroup(ts.db, ts.provider.ID, []uuid.UUID{group.ID})
	require.NoError(ts.T(), err)
	ids := make([]uuid.UUID, len(rendered))
	for i, m := range rendered {
		ids[i] = m.SCIMUserID
	}
	require.Equal(ts.T(), ids, change.Members)
}

func (ts *SCIMGroupTestSuite) createProvider() *SSOProvider {
	return createSCIMTestProvider(ts.T(), ts.db)
}

func (ts *SCIMGroupTestSuite) createGroup(providerID uuid.UUID, displayName string) *SCIMGroup {
	group, err := CreateSCIMGroup(ts.db, providerID, []byte(fmt.Sprintf(`{"displayName":%q}`, displayName)))
	require.NoError(ts.T(), err)
	return group
}

func (ts *SCIMGroupTestSuite) createUser(providerID uuid.UUID, userName string) *SCIMUser {
	user, err := CreateSCIMUser(ts.db, providerID, []byte(fmt.Sprintf(`{"userName":%q}`, userName)))
	require.NoError(ts.T(), err)
	return user
}

func (ts *SCIMGroupTestSuite) beginTx() *storage.Connection {
	tx, err := ts.db.NewTransaction()
	require.NoError(ts.T(), err)
	return &storage.Connection{Connection: tx}
}
