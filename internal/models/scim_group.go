package models

import (
	"fmt"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

type SCIMGroup struct {
	ID            uuid.UUID `db:"id"`
	SSOProviderID uuid.UUID `db:"sso_provider_id"`
	Resource      []byte    `db:"resource"`
	DisplayName   string    `db:"display_name"`
	ExternalID    *string   `db:"external_id"`
	CreatedAt     time.Time `db:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
}

const scimGroupColumns = "id, sso_provider_id, resource, display_name, external_id, created_at, updated_at"

func (SCIMGroup) TableName() string {
	return "scim_groups"
}

type SCIMGroupMember struct {
	GroupID    uuid.UUID `db:"group_id"`
	SCIMUserID uuid.UUID `db:"scim_user_id"`
	CreatedAt  time.Time `db:"created_at"`
}

func (SCIMGroupMember) TableName() string {
	return "scim_group_members"
}

type SCIMGroupMembership struct {
	GroupID    uuid.UUID `db:"group_id"`
	SCIMUserID uuid.UUID `db:"scim_user_id"`
	Display    string    `db:"display"`
}

type SCIMGroupMemberChange struct {
	Added   []uuid.UUID
	Removed []uuid.UUID
	Members []uuid.UUID
}

var scimGroupsTable = scimTable{
	tableName:  SCIMGroup{}.TableName(),
	label:      "SCIM group",
	columns:    scimGroupColumns,
	nameColumn: "display_name",
	notFound:   SCIMGroupNotFoundError{},
	stale:      SCIMGroupStaleError{},
	conflict:   SCIMGroupConflictError{},
}

func CreateSCIMGroup(tx *storage.Connection, providerID uuid.UUID, resource []byte) (*SCIMGroup, error) {
	return createSCIMRow[SCIMGroup](tx, scimGroupsTable, providerID, resource)
}

func FindSCIMGroup(tx *storage.Connection, providerID, id uuid.UUID) (*SCIMGroup, error) {
	return findSCIMRow[SCIMGroup](tx, scimGroupsTable, SCIMTarget{ProviderID: providerID, ID: id}, false)
}

func FindSCIMGroups(tx *storage.Connection, providerID uuid.UUID, query SCIMQuery) ([]SCIMGroup, int, error) {
	return findSCIMPage[SCIMGroup](tx, scimGroupsTable, providerID, query)
}

func ReplaceSCIMGroupIfChanged(tx *storage.Connection, target SCIMTarget, resource []byte) (*SCIMGroup, bool, error) {
	return replaceSCIMRowIfChanged[SCIMGroup](tx, scimGroupsTable, target, resource)
}

func LockUnchangedSCIMGroup(tx *storage.Connection, providerID, id uuid.UUID, resource []byte) (*SCIMGroup, error) {
	return findUnchangedSCIMRow[SCIMGroup](tx, scimGroupsTable, SCIMTarget{ProviderID: providerID, ID: id}, resource)
}

func DeleteSCIMGroup(tx *storage.Connection, target SCIMTarget) (*SCIMGroup, error) {
	group := &SCIMGroup{}
	err := tx.RawQuery(
		fmt.Sprintf("DELETE FROM %q WHERE %s AND "+scimVersionClause+" RETURNING %s", scimGroupsTable.tableName, scimGroupsTable.targetClause(), scimGroupsTable.columns),
		target.ID, target.ProviderID, target.UpdatedAt, target.UpdatedAt,
	).First(group)
	if err != nil {
		return nil, scimGroupsTable.writeError(tx, target, err, "deleting")
	}
	return group, nil
}

func FindSCIMMembershipsByGroup(tx *storage.Connection, providerID uuid.UUID, groupIDs []uuid.UUID) ([]SCIMGroupMembership, error) {
	members := []SCIMGroupMembership{}
	if len(groupIDs) == 0 {
		return members, nil
	}
	err := tx.RawQuery(
		fmt.Sprintf("SELECT m.group_id, m.scim_user_id FROM %q m JOIN %q u ON u.id = m.scim_user_id WHERE m.group_id = ANY(?::uuid[]) AND u.sso_provider_id = ? AND u.deleted_at IS NULL ORDER BY m.group_id, m.scim_user_id", SCIMGroupMember{}.TableName(), scimUsersTable.tableName),
		groupIDs, providerID,
	).All(&members)
	if err != nil {
		return nil, errors.Wrap(err, "error finding SCIM group members")
	}
	return members, nil
}

func FindSCIMMembershipsByUser(tx *storage.Connection, providerID uuid.UUID, scimUserIDs []uuid.UUID) ([]SCIMGroupMembership, error) {
	memberships := []SCIMGroupMembership{}
	if len(scimUserIDs) == 0 {
		return memberships, nil
	}
	err := tx.RawQuery(
		fmt.Sprintf("SELECT m.group_id, m.scim_user_id, g.resource->>'displayName' AS display FROM %q m JOIN %q g ON g.id = m.group_id WHERE m.scim_user_id = ANY(?::uuid[]) AND g.sso_provider_id = ? ORDER BY m.scim_user_id, g.display_name COLLATE \"C\", g.id", SCIMGroupMember{}.TableName(), scimGroupsTable.tableName),
		scimUserIDs, providerID,
	).All(&memberships)
	if err != nil {
		return nil, errors.Wrap(err, "error finding SCIM groups for users")
	}
	return memberships, nil
}

func ReplaceSCIMGroupMembers(tx *storage.Connection, group *SCIMGroup, scimUserIDs []uuid.UUID) (*SCIMGroup, SCIMGroupMemberChange, error) {
	change := SCIMGroupMemberChange{Members: sortedUniqueUUIDs(scimUserIDs)}
	added, removed, err := diffSCIMGroupMembers(tx, group.ID, change.Members)
	if err != nil {
		return nil, change, err
	}
	change.Added, change.Removed = added, removed
	return applySCIMGroupMemberChange(tx, group, change)
}

func ReplaceSCIMGroupMembersFrom(tx *storage.Connection, group *SCIMGroup, current, scimUserIDs []uuid.UUID) (*SCIMGroup, SCIMGroupMemberChange, error) {
	members := sortedUniqueUUIDs(scimUserIDs)
	change := SCIMGroupMemberChange{Members: members, Added: differenceUUIDs(members, current), Removed: differenceUUIDs(current, members)}
	return applySCIMGroupMemberChange(tx, group, change)
}

func MergeSCIMGroupMembers(tx *storage.Connection, group *SCIMGroup, base, scimUserIDs []uuid.UUID) (*SCIMGroup, SCIMGroupMemberChange, error) {
	group, change, err := ReplaceSCIMGroupMembersFrom(tx, group, base, scimUserIDs)
	if err != nil {
		return nil, change, err
	}
	members, err := FindSCIMGroupMemberIDs(tx, group.ID)
	if err != nil {
		return nil, change, err
	}
	change.Members = sortedUniqueUUIDs(members)
	return group, change, nil
}

func FindSCIMGroupMemberIDs(tx *storage.Connection, groupID uuid.UUID) ([]uuid.UUID, error) {
	members := []uuid.UUID{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT scim_user_id FROM %q WHERE group_id = ?", SCIMGroupMember{}.TableName()),
		groupID,
	).All(&members); err != nil {
		return nil, errors.Wrap(err, "error finding SCIM group members")
	}
	return members, nil
}

func RemoveSCIMUserFromGroups(tx *storage.Connection, scimUserID uuid.UUID) ([]uuid.UUID, error) {
	groups, members := scimGroupsTable.tableName, SCIMGroupMember{}.TableName()
	groupIDs := []uuid.UUID{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT group_id FROM %q WHERE scim_user_id = ? ORDER BY group_id", members),
		scimUserID,
	).All(&groupIDs); err != nil {
		return nil, errors.Wrap(err, "error finding SCIM user groups")
	}
	for _, id := range groupIDs {
		if err := tx.RawQuery(
			fmt.Sprintf("UPDATE %q SET updated_at = clock_timestamp() WHERE id = ?", groups),
			id,
		).Exec(); err != nil {
			return nil, errors.Wrap(err, "error updating SCIM groups")
		}
	}
	if err := tx.RawQuery(
		fmt.Sprintf("DELETE FROM %q WHERE scim_user_id = ?", members),
		scimUserID,
	).Exec(); err != nil {
		return nil, errors.Wrap(err, "error removing SCIM user from groups")
	}
	return groupIDs, nil
}

func applySCIMGroupMemberChange(tx *storage.Connection, group *SCIMGroup, planned SCIMGroupMemberChange) (*SCIMGroup, SCIMGroupMemberChange, error) {
	change := SCIMGroupMemberChange{Members: planned.Members}
	added, removed := planned.Added, planned.Removed
	var err error
	if change.Removed, err = removeSCIMGroupMembers(tx, group.ID, removed); err != nil {
		return nil, change, err
	}
	if change.Added, err = addSCIMGroupMembers(tx, group, added); err != nil {
		return nil, change, err
	}
	if len(change.Added) == 0 && len(change.Removed) == 0 {
		return group, change, nil
	}
	group, err = touchSCIMGroup(tx, group)
	return group, change, err
}

func findLiveSCIMUserIDs(tx *storage.Connection, providerID uuid.UUID, ids []uuid.UUID) ([]uuid.UUID, error) {
	found := []uuid.UUID{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT id FROM %q WHERE id = ANY(?::uuid[]) AND sso_provider_id = ? AND deleted_at IS NULL", scimUsersTable.tableName),
		ids, providerID,
	).All(&found); err != nil {
		return nil, errors.Wrap(err, "error finding SCIM group members")
	}
	if missing := differenceUUIDs(ids, found); len(missing) > 0 {
		return nil, SCIMGroupMemberNotFoundError{IDs: missing}
	}
	return found, nil
}

func touchSCIMGroup(tx *storage.Connection, group *SCIMGroup) (*SCIMGroup, error) {
	touched := &SCIMGroup{}
	if err := tx.RawQuery(
		fmt.Sprintf("UPDATE %q SET updated_at = clock_timestamp() WHERE id = ? RETURNING "+scimGroupColumns, scimGroupsTable.tableName),
		group.ID,
	).First(touched); err != nil {
		return nil, errors.Wrap(err, "error updating SCIM group")
	}
	return touched, nil
}

func diffSCIMGroupMembers(tx *storage.Connection, groupID uuid.UUID, members []uuid.UUID) ([]uuid.UUID, []uuid.UUID, error) {
	rows := []struct {
		Added   uuid.NullUUID `db:"added"`
		Removed uuid.NullUUID `db:"removed"`
	}{}
	if err := tx.RawQuery(
		fmt.Sprintf("SELECT k.id AS added, m.scim_user_id AS removed FROM unnest(?::uuid[]) AS k(id) FULL JOIN (SELECT scim_user_id FROM %q WHERE group_id = ?) m ON m.scim_user_id = k.id WHERE k.id IS NULL OR m.scim_user_id IS NULL", SCIMGroupMember{}.TableName()),
		uuidArray(members), groupID,
	).All(&rows); err != nil {
		return nil, nil, errors.Wrap(err, "error finding SCIM group member changes")
	}
	added, removed := []uuid.UUID{}, []uuid.UUID{}
	for _, row := range rows {
		if row.Added.Valid {
			added = append(added, row.Added.UUID)
		}
		if row.Removed.Valid {
			removed = append(removed, row.Removed.UUID)
		}
	}
	return added, removed, nil
}

func removeSCIMGroupMembers(tx *storage.Connection, groupID uuid.UUID, ids []uuid.UUID) ([]uuid.UUID, error) {
	removed := []uuid.UUID{}
	if len(ids) == 0 {
		return removed, nil
	}
	if err := tx.RawQuery(
		fmt.Sprintf("DELETE FROM %q WHERE group_id = ? AND scim_user_id = ANY(?::uuid[]) RETURNING scim_user_id", SCIMGroupMember{}.TableName()),
		groupID, uuidArray(ids),
	).All(&removed); err != nil {
		return nil, errors.Wrap(err, "error removing SCIM group members")
	}
	return sortedUniqueUUIDs(removed), nil
}

func addSCIMGroupMembers(tx *storage.Connection, group *SCIMGroup, ids []uuid.UUID) ([]uuid.UUID, error) {
	added := []uuid.UUID{}
	if len(ids) == 0 {
		return added, nil
	}
	live, err := findLiveSCIMUserIDs(tx, group.SSOProviderID, ids)
	if err != nil {
		return nil, err
	}
	if err := tx.RawQuery(
		fmt.Sprintf("INSERT INTO %q (group_id, scim_user_id) SELECT ?, unnest(?::uuid[]) ON CONFLICT DO NOTHING RETURNING scim_user_id", SCIMGroupMember{}.TableName()),
		group.ID, uuidArray(live),
	).All(&added); err != nil {
		return nil, errors.Wrap(err, "error adding SCIM group members")
	}
	return sortedUniqueUUIDs(added), nil
}
