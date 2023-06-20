package models

import (
	"database/sql"
	"sort"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/gotrue/internal/storage"
)

type AuthenticatorAssuranceLevel int

const (
	AAL1 AuthenticatorAssuranceLevel = iota
	AAL2
	AAL3
)

func (aal AuthenticatorAssuranceLevel) String() string {
	switch aal {
	case AAL1:
		return "aal1"
	case AAL2:
		return "aal2"
	case AAL3:
		return "aal3"
	default:
		return ""
	}
}

// AMREntry represents a method that a user has logged in together with the corresponding time
type AMREntry struct {
	Method    string `json:"method"`
	Timestamp int64  `json:"timestamp"`
	Provider  string `json:"provider,omitempty"`
}

type sortAMREntries struct {
	Array []AMREntry
}

func (s sortAMREntries) Len() int {
	return len(s.Array)
}

func (s sortAMREntries) Less(i, j int) bool {
	return s.Array[i].Timestamp < s.Array[j].Timestamp
}

func (s sortAMREntries) Swap(i, j int) {
	s.Array[j], s.Array[i] = s.Array[i], s.Array[j]
}

type Session struct {
	ID        uuid.UUID  `json:"-" db:"id"`
	UserID    uuid.UUID  `json:"user_id" db:"user_id"`
	NotAfter  *time.Time `json:"not_after,omitempty" db:"not_after"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	FactorID  *uuid.UUID `json:"factor_id" db:"factor_id"`
	AMRClaims []AMRClaim `json:"amr,omitempty" has_many:"amr_claims"`
	AAL       *string    `json:"aal" db:"aal"`
}

func (Session) TableName() string {
	tableName := "sessions"
	return tableName
}

func NewSession() (*Session, error) {
	id := uuid.Must(uuid.NewV4())

	defaultAAL := AAL1.String()

	session := &Session{
		ID:  id,
		AAL: &defaultAAL,
	}

	return session, nil
}

func FindSessionByID(tx *storage.Connection, id uuid.UUID) (*Session, error) {
	session := &Session{}
	if err := tx.Eager().Q().Where("id = ?", id).First(session); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SessionNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding session")
	}
	return session, nil
}

func FindSessionByUserID(tx *storage.Connection, userId uuid.UUID) (*Session, error) {
	session := &Session{}
	if err := tx.Eager().Q().Where("user_id = ?", userId).Order("created_at asc").First(session); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, SessionNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding session")
	}
	return session, nil
}

func FindSessionsByFactorID(tx *storage.Connection, factorID uuid.UUID) ([]*Session, error) {
	sessions := []*Session{}
	if err := tx.Q().Where("factor_id = ?", factorID).All(&sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

func updateFactorAssociatedSessions(tx *storage.Connection, userID, factorID uuid.UUID, aal string) error {
	return tx.RawQuery("UPDATE "+(&pop.Model{Value: Session{}}).TableName()+" set aal = ?, factor_id = ? WHERE user_id = ? AND factor_id = ?", aal, nil, userID, factorID).Exec()
}

func InvalidateSessionsWithAALLessThan(tx *storage.Connection, userID uuid.UUID, level string) error {
	return tx.RawQuery("DELETE FROM "+(&pop.Model{Value: Session{}}).TableName()+" WHERE user_id = ? AND aal < ?", userID, level).Exec()
}

// Logout deletes all sessions for a user.
func Logout(tx *storage.Connection, userId uuid.UUID) error {
	return tx.RawQuery("DELETE FROM "+(&pop.Model{Value: Session{}}).TableName()+" WHERE user_id = ?", userId).Exec()
}

// LogoutSession deletes the current session for a user
func LogoutSession(tx *storage.Connection, sessionId uuid.UUID) error {
	return tx.RawQuery("DELETE FROM "+(&pop.Model{Value: Session{}}).TableName()+" WHERE id = ?", sessionId).Exec()
}

// LogoutAllExceptMe deletes all sessions for a user except the current one
func LogoutAllExceptMe(tx *storage.Connection, sessionId uuid.UUID, userID uuid.UUID) error {
	return tx.RawQuery("DELETE FROM "+(&pop.Model{Value: Session{}}).TableName()+" WHERE id != ? AND user_id = ?", sessionId, userID).Exec()
}

func (s *Session) UpdateAssociatedFactor(tx *storage.Connection, factorID *uuid.UUID) error {
	s.FactorID = factorID
	return tx.Update(s)
}

func (s *Session) UpdateAssociatedAAL(tx *storage.Connection, aal string) error {
	s.AAL = &aal
	return tx.Update(s)
}

func (s *Session) CalculateAALAndAMR(tx *storage.Connection) (aal string, amr []AMREntry, err error) {
	amr, aal = []AMREntry{}, AAL1.String()
	for _, claim := range s.AMRClaims {
		if *claim.AuthenticationMethod == TOTPSignIn.String() {
			aal = AAL2.String()
		}
		amr = append(amr, AMREntry{Method: claim.GetAuthenticationMethod(), Timestamp: claim.UpdatedAt.Unix()})
	}

	// makes sure that the AMR claims are always ordered most-recent first

	// sort in ascending order
	sort.Sort(sortAMREntries{
		Array: amr,
	})

	// now reverse for descending order
	_ = sort.Reverse(sortAMREntries{
		Array: amr,
	})

	lastIndex := len(amr) - 1

	if lastIndex > -1 && amr[lastIndex].Method == SSOSAML.String() {
		// initial AMR claim is from sso/saml, we need to add information
		// about the provider that was used for the authentication
		identities, err := FindIdentitiesByUserID(tx, s.UserID)
		if err != nil {
			return aal, amr, err
		}

		if len(identities) == 1 {
			identity := identities[0]

			if strings.HasPrefix(identity.Provider, "sso:") {
				amr[lastIndex].Provider = strings.TrimPrefix(identity.Provider, "sso:")
			}
		}

		// otherwise we can't identify that this user account has only
		// one SSO identity, so we are not encoding the provider at
		// this time
	}

	return aal, amr, nil
}

func (s *Session) GetAAL() string {
	if s.AAL == nil {
		return ""
	}
	return *(s.AAL)
}

func (s *Session) IsAAL2() bool {
	return s.GetAAL() == AAL2.String()
}
