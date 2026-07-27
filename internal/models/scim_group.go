package models

import (
	"database/sql"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

var (
	scimGroupTable       = (&pop.Model{Value: SCIMGroup{}}).TableName()
	scimGroupMemberTable = (&pop.Model{Value: SCIMGroupMember{}}).TableName()
)

type SCIMGroup struct {
	ID            uuid.UUID          `db:"id" json:"id"`
	SSOProviderID uuid.UUID          `db:"sso_provider_id" json:"-"`
	ExternalID    storage.NullString `db:"external_id" json:"external_id,omitempty"`
	DisplayName   string             `db:"display_name" json:"display_name"`
	CreatedAt     time.Time          `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time          `db:"updated_at" json:"updated_at"`

	SSOProvider *SSOProvider `belongs_to:"sso_providers" json:"-"`
	Members     []User       `many_to_many:"scim_group_members" json:"members,omitempty"`
}

func (SCIMGroup) TableName() string {
	return "scim_groups"
}

type SCIMGroupMember struct {
	GroupID   uuid.UUID `db:"group_id" json:"-"`
	UserID    uuid.UUID `db:"user_id" json:"-"`
	CreatedAt time.Time `db:"created_at" json:"-"`
}

func (SCIMGroupMember) TableName() string {
	return "scim_group_members"
}

func NewSCIMGroup(ssoProviderID uuid.UUID, externalID, displayName string) *SCIMGroup {
	id := uuid.Must(uuid.NewV4())
	group := &SCIMGroup{
		ID:            id,
		SSOProviderID: ssoProviderID,
		DisplayName:   displayName,
	}
	if externalID != "" {
		group.ExternalID = storage.NullString(externalID)
	}
	return group
}

func FindSCIMGroupByID(tx *storage.Connection, id uuid.UUID) (*SCIMGroup, error) {
	var group SCIMGroup
	if err := tx.Find(&group, id); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SCIMGroupNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding SCIM group by ID")
	}
	return &group, nil
}

func FindSCIMGroupByExternalID(tx *storage.Connection, ssoProviderID uuid.UUID, externalID string) (*SCIMGroup, error) {
	var group SCIMGroup
	if err := tx.Q().Where("sso_provider_id = ? AND external_id = ?", ssoProviderID, externalID).First(&group); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SCIMGroupNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding SCIM group by external ID")
	}
	return &group, nil
}

type SCIMFilterClause struct {
	Where string
	Args  []interface{}
}

func FindSCIMGroupsBySSOProviderWithFilter(tx *storage.Connection, ssoProviderID uuid.UUID, filterClause *SCIMFilterClause, startIndex, count int) ([]*SCIMGroup, int, error) {
	groups := []*SCIMGroup{}

	offset := startIndex - 1
	if offset < 0 {
		offset = 0
	}

	whereClause := "sso_provider_id = ?"
	args := []interface{}{ssoProviderID}

	if filterClause != nil && filterClause.Where != "" && filterClause.Where != "1=1" {
		whereClause += " AND (" + filterClause.Where + ")"
		args = append(args, filterClause.Args...)
	}

	var totalResults int
	countQuery := "SELECT COUNT(*) FROM " + scimGroupTable + " WHERE " + whereClause
	if err := tx.RawQuery(countQuery, args...).First(&totalResults); err != nil {
		return nil, 0, errors.Wrap(err, "error counting SCIM groups")
	}

	query := "SELECT * FROM " + scimGroupTable + " WHERE " + whereClause + " ORDER BY created_at ASC LIMIT ? OFFSET ?"
	args = append(args, count, offset)
	if err := tx.RawQuery(query, args...).All(&groups); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return []*SCIMGroup{}, totalResults, nil
		}
		return nil, 0, errors.Wrap(err, "error finding SCIM groups")
	}
	return groups, totalResults, nil
}

func buildINClause(ids []uuid.UUID) (string, []interface{}) {
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	return strings.Join(placeholders, ","), args
}

func (g *SCIMGroup) AddMember(tx *storage.Connection, userID uuid.UUID) error {
	user, err := FindUserByID(tx, userID)
	if err != nil {
		return err
	}

	if !UserBelongsToSSOProvider(user, g.SSOProviderID) {
		return UserNotInSSOProviderError{}
	}

	return tx.RawQuery(
		"INSERT INTO "+scimGroupMemberTable+" (group_id, user_id, created_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
		g.ID, userID, time.Now(),
	).Exec()
}

func UserBelongsToSSOProvider(user *User, ssoProviderID uuid.UUID) bool {
	providerType := "sso:" + ssoProviderID.String()
	for _, identity := range user.Identities {
		if identity.Provider == providerType {
			return true
		}
	}
	return false
}

func (g *SCIMGroup) AddMembers(tx *storage.Connection, userIDs []uuid.UUID) error {
	if len(userIDs) == 0 {
		return nil
	}

	userIDs = deduplicateUUIDs(userIDs)

	if err := g.validateMemberIDs(tx, userIDs); err != nil {
		return err
	}
	return g.insertMembers(tx, userIDs)
}

func (g *SCIMGroup) RemoveMember(tx *storage.Connection, userID uuid.UUID) error {
	return tx.RawQuery(
		"DELETE FROM "+scimGroupMemberTable+" WHERE group_id = ? AND user_id = ?",
		g.ID, userID,
	).Exec()
}

// GetMembers loads the users belonging to this group. Uses a two-step query
// to avoid SELECT * on users (which breaks on unmapped columns like is_super_admin).
func (g *SCIMGroup) GetMembers(tx *storage.Connection) ([]*User, error) {
	// Step 1: get user IDs from the junction table
	type idRow struct {
		UserID uuid.UUID `db:"user_id"`
	}
	var idResults []idRow
	if err := tx.RawQuery(
		"SELECT m.user_id FROM "+scimGroupMemberTable+" m WHERE m.group_id = ? ORDER BY m.user_id ASC",
		g.ID,
	).All(&idResults); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return []*User{}, nil
		}
		return nil, errors.Wrap(err, "error getting SCIM group member IDs")
	}
	if len(idResults) == 0 {
		return []*User{}, nil
	}

	// Step 2: load full user objects via Pop's query builder (infers column list from struct)
	placeholders := make([]string, len(idResults))
	loadArgs := make([]interface{}, len(idResults))
	for i, r := range idResults {
		placeholders[i] = "?"
		loadArgs[i] = r.UserID
	}
	users := []*User{}
	err := tx.Q().
		Where("id IN ("+strings.Join(placeholders, ",")+") ", loadArgs...).
		Order("email ASC").
		All(&users)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return []*User{}, nil
		}
		return nil, errors.Wrap(err, "error loading SCIM group members")
	}
	return users, nil
}

func (g *SCIMGroup) SetMembers(tx *storage.Connection, userIDs []uuid.UUID) error {
	if len(userIDs) == 0 {
		if err := tx.RawQuery("DELETE FROM "+scimGroupMemberTable+" WHERE group_id = ?", g.ID).Exec(); err != nil {
			return errors.Wrap(err, "error clearing SCIM group members")
		}
		return nil
	}

	userIDs = deduplicateUUIDs(userIDs)

	if err := g.validateMemberIDs(tx, userIDs); err != nil {
		return err
	}
	if err := tx.RawQuery("DELETE FROM "+scimGroupMemberTable+" WHERE group_id = ?", g.ID).Exec(); err != nil {
		return errors.Wrap(err, "error clearing SCIM group members")
	}
	return g.insertMembers(tx, userIDs)
}

func (g *SCIMGroup) validateMemberIDs(tx *storage.Connection, userIDs []uuid.UUID) error {
	identityTable := (&pop.Model{Value: Identity{}}).TableName()
	userTable := (&pop.Model{Value: User{}}).TableName()
	providerType := "sso:" + g.SSOProviderID.String()

	inClause, queryArgs := buildINClause(userIDs)

	var rawValidIDs []uuid.UUID
	validationArgs := make([]interface{}, 0, len(userIDs)+1)
	validationArgs = append(validationArgs, queryArgs...)
	validationArgs = append(validationArgs, providerType)
	if err := tx.RawQuery(
		"SELECT u.id FROM "+userTable+" u "+
			"INNER JOIN "+identityTable+" i ON i.user_id = u.id "+
			"WHERE u.id IN ("+inClause+") AND i.provider = ? "+
			"FOR SHARE OF u, i",
		validationArgs...,
	).All(&rawValidIDs); err != nil {
		return errors.Wrap(err, "error validating SCIM group member IDs")
	}

	validSet := make(map[uuid.UUID]struct{}, len(rawValidIDs))
	for _, id := range rawValidIDs {
		validSet[id] = struct{}{}
	}

	if len(validSet) != len(userIDs) {
		var existingIDs []uuid.UUID
		if err := tx.RawQuery(
			"SELECT id FROM "+userTable+" WHERE id IN ("+inClause+") FOR SHARE",
			queryArgs...,
		).All(&existingIDs); err != nil {
			return errors.Wrap(err, "error checking user existence")
		}
		existingSet := make(map[uuid.UUID]struct{}, len(existingIDs))
		for _, id := range existingIDs {
			existingSet[id] = struct{}{}
		}
		for _, id := range userIDs {
			if _, ok := validSet[id]; !ok {
				if _, exists := existingSet[id]; !exists {
					return UserNotFoundError{}
				}
				return UserNotInSSOProviderError{}
			}
		}
	}
	return nil
}

func (g *SCIMGroup) insertMembers(tx *storage.Connection, userIDs []uuid.UUID) error {
	identityTable := (&pop.Model{Value: Identity{}}).TableName()
	userTable := (&pop.Model{Value: User{}}).TableName()
	providerType := "sso:" + g.SSOProviderID.String()

	inClause, queryArgs := buildINClause(userIDs)

	now := time.Now()
	insertArgs := make([]interface{}, 0, 2+len(userIDs)+1)
	insertArgs = append(insertArgs, g.ID, now)
	insertArgs = append(insertArgs, queryArgs...)
	insertArgs = append(insertArgs, providerType)

	if err := tx.RawQuery(
		"INSERT INTO "+scimGroupMemberTable+" (group_id, user_id, created_at) "+
			"SELECT ?, u.id, ? FROM "+userTable+" u "+
			"INNER JOIN "+identityTable+" i ON i.user_id = u.id "+
			"WHERE u.id IN ("+inClause+") AND i.provider = ? "+
			"ON CONFLICT DO NOTHING",
		insertArgs...,
	).Exec(); err != nil {
		return errors.Wrap(err, "error adding SCIM group members")
	}
	return nil
}

// GetMembersForGroups loads users for each group. Uses a two-step query to
// avoid SELECT * on users (which breaks when DB has columns not mapped in
// the Go struct, e.g. is_super_admin).
func GetMembersForGroups(tx *storage.Connection, groupIDs []uuid.UUID) (map[uuid.UUID][]*User, error) {
	result := make(map[uuid.UUID][]*User)
	if len(groupIDs) == 0 {
		return result, nil
	}

	// Step 1: get (group_id, user_id) pairs via raw query on the junction table
	type memberRef struct {
		GroupID uuid.UUID `db:"group_id"`
		UserID  uuid.UUID `db:"user_id"`
	}

	inClause, args := buildINClause(groupIDs)

	refs := []memberRef{}
	if err := tx.RawQuery(
		"SELECT m.group_id, m.user_id FROM "+scimGroupMemberTable+" m "+
			"WHERE m.group_id IN ("+inClause+")",
		args...,
	).All(&refs); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return result, nil
		}
		return nil, errors.Wrap(err, "error batch loading SCIM group members")
	}

	if len(refs) == 0 {
		return result, nil
	}

	// Collect unique user IDs
	userIDSet := make(map[uuid.UUID]bool)
	for _, ref := range refs {
		userIDSet[ref.UserID] = true
	}

	// Step 2: load full user objects via Pop's query builder (infers column
	// list from struct, avoids SELECT * which breaks on unmapped columns)
	placeholders := make([]string, 0, len(userIDSet))
	loadArgs := make([]interface{}, 0, len(userIDSet))
	for id := range userIDSet {
		placeholders = append(placeholders, "?")
		loadArgs = append(loadArgs, id)
	}
	users := []*User{}
	err := tx.Q().
		Where("id IN ("+strings.Join(placeholders, ",")+") ", loadArgs...).
		Order("email ASC").
		All(&users)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return result, nil
		}
		return nil, errors.Wrap(err, "error loading users for SCIM group members")
	}

	userMap := make(map[uuid.UUID]*User, len(users))
	for _, u := range users {
		userMap[u.ID] = u
	}

	// Step 3: assemble group → users map
	for _, ref := range refs {
		if u, ok := userMap[ref.UserID]; ok {
			result[ref.GroupID] = append(result[ref.GroupID], u)
		}
	}
	return result, nil
}

func deduplicateUUIDs(ids []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{}, len(ids))
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}
