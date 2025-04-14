package models

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
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

func (aal AuthenticatorAssuranceLevel) PointerString() *string {
	value := aal.String()

	return &value
}

// CompareAAL returns 0 if both AAL levels are equal, > 0 if A is a higher level than B or < 0 if A is a lower level than B.
func CompareAAL(a, b AuthenticatorAssuranceLevel) int {
	return strings.Compare(a.String(), b.String())
}

func ParseAAL(value *string) AuthenticatorAssuranceLevel {
	if value == nil {
		return AAL1
	}

	switch *value {
	case AAL1.String():
		return AAL1

	case AAL2.String():
		return AAL2

	case AAL3.String():
		return AAL3
	}

	return AAL1
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
	ID     uuid.UUID `json:"-" db:"id"`
	UserID uuid.UUID `json:"user_id" db:"user_id"`

	// NotAfter is overriden by timeboxed sessions.
	NotAfter *time.Time `json:"not_after,omitempty" db:"not_after"`

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	FactorID  *uuid.UUID `json:"factor_id" db:"factor_id"`
	AMRClaims []AMRClaim `json:"amr,omitempty" has_many:"amr_claims"`
	AAL       *string    `json:"aal" db:"aal"`

	RefreshedAt *time.Time `json:"refreshed_at,omitempty" db:"refreshed_at"`
	UserAgent   *string    `json:"user_agent,omitempty" db:"user_agent"`
	IP          *string    `json:"ip,omitempty" db:"ip"`

	Tag *string `json:"tag" db:"tag"`
}

func (Session) TableName() string {
	tableName := "sessions"
	return tableName
}

func (s *Session) LastRefreshedAt(refreshTokenTime *time.Time) time.Time {
	refreshedAt := s.RefreshedAt

	if refreshedAt == nil || refreshedAt.IsZero() {
		if refreshTokenTime != nil {
			rtt := *refreshTokenTime

			if rtt.IsZero() {
				return s.CreatedAt
			} else if rtt.After(s.CreatedAt) {
				return rtt
			}
		}

		return s.CreatedAt
	}

	return *refreshedAt
}

func (s *Session) UpdateOnlyRefreshInfo(tx *storage.Connection) error {
	// TODO(kangmingtay): The underlying database type uses timestamp without timezone,
	// so we need to convert the value to UTC before updating it.
	// In the future, we should add a migration to update the type to contain the timezone.
	*s.RefreshedAt = s.RefreshedAt.UTC()
	return tx.UpdateOnly(s, "refreshed_at", "user_agent", "ip")
}

type SessionValidityReason = int

const (
	SessionValid        SessionValidityReason = iota
	SessionPastNotAfter                       = iota
	SessionPastTimebox                        = iota
	SessionTimedOut                           = iota
	SessionLowAAL                             = iota
)

type SessionValidityConfig struct {
	Timebox           *time.Duration
	InactivityTimeout *time.Duration
	AllowLowAAL       *time.Duration
}

func (s *Session) CheckValidity(config SessionValidityConfig, now time.Time, refreshTokenTime *time.Time, userHighestPossibleAAL AuthenticatorAssuranceLevel) SessionValidityReason {
	if s.NotAfter != nil && now.After(*s.NotAfter) {
		return SessionPastNotAfter
	}

	if config.Timebox != nil && *config.Timebox != 0 && now.After(s.CreatedAt.Add(*config.Timebox)) {
		return SessionPastTimebox
	}

	if config.InactivityTimeout != nil && *config.InactivityTimeout != 0 && now.After(s.LastRefreshedAt(refreshTokenTime).Add(*config.InactivityTimeout)) {
		return SessionTimedOut
	}

	if config.AllowLowAAL != nil && *config.AllowLowAAL != 0 && CompareAAL(ParseAAL(s.AAL), userHighestPossibleAAL) < 0 && now.After(s.CreatedAt.Add(*config.AllowLowAAL)) {
		return SessionLowAAL
	}

	return SessionValid
}

func (s *Session) DetermineTag(tags []string) string {
	if len(tags) == 0 {
		return ""
	}

	if s.Tag == nil {
		return tags[0]
	}

	tag := *s.Tag
	if tag == "" {
		return tags[0]
	}

	for _, t := range tags {
		if t == tag {
			return tag
		}
	}

	return tags[0]
}

func NewSession(userID uuid.UUID, factorID *uuid.UUID) (*Session, error) {
	id := uuid.Must(uuid.NewV4())

	session := &Session{
		ID:       id,
		AAL:      AAL1.PointerString(),
		UserID:   userID,
		FactorID: factorID,
	}

	return session, nil
}

// FindSessionByID looks up a Session by the provided id. If forUpdate is set
// to true, then the SELECT statement used by the query has the form SELECT ...
// FOR UPDATE SKIP LOCKED. This means that a FOR UPDATE lock will only be
// acquired if there's no other lock. In case there is a lock, a
// IsNotFound(err) error will be retured.
func FindSessionByID(tx *storage.Connection, id uuid.UUID, forUpdate bool) (*Session, error) {
	session := &Session{}

	if forUpdate {
		// pop does not provide us with a way to execute FOR UPDATE
		// queries which lock the rows affected by the query from
		// being accessed by any other transaction that also uses FOR
		// UPDATE
		if err := tx.RawQuery(fmt.Sprintf("SELECT * FROM %q WHERE id = ? LIMIT 1 FOR UPDATE SKIP LOCKED;", session.TableName()), id).First(session); err != nil {
			if errors.Cause(err) == sql.ErrNoRows {
				return nil, SessionNotFoundError{}
			}

			return nil, err
		}
	}

	// once the rows are locked (if forUpdate was true), we can query again using pop
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

// FindAllSessionsForUser finds all of the sessions for a user. If forUpdate is
// set, it will first lock on the user row which can be used to prevent issues
// with concurrency. If the lock is acquired, it will return a
// UserNotFoundError and the operation should be retried. If there are no
// sessions for the user, a nil result is returned without an error.
func FindAllSessionsForUser(tx *storage.Connection, userId uuid.UUID, forUpdate bool) ([]*Session, error) {
	if forUpdate {
		user := &User{}
		if err := tx.RawQuery(fmt.Sprintf("SELECT id FROM %q WHERE id = ? LIMIT 1 FOR UPDATE SKIP LOCKED;", user.TableName()), userId).First(user); err != nil {
			if errors.Cause(err) == sql.ErrNoRows {
				return nil, UserNotFoundError{}
			}

			return nil, err
		}
	}

	var sessions []*Session
	if err := tx.Where("user_id = ?", userId).All(&sessions); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, nil
		}

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

func (s *Session) UpdateAALAndAssociatedFactor(tx *storage.Connection, aal AuthenticatorAssuranceLevel, factorID *uuid.UUID) error {
	s.FactorID = factorID
	aalAsString := aal.String()
	s.AAL = &aalAsString
	return tx.UpdateOnly(s, "aal", "factor_id")
}

func (s *Session) CalculateAALAndAMR(user *User) (aal AuthenticatorAssuranceLevel, amr []AMREntry, err error) {
	amr, aal = []AMREntry{}, AAL1
	for _, claim := range s.AMRClaims {
		if claim.IsAAL2Claim() {
			aal = AAL2
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
		identities := user.Identities

		if len(identities) == 1 {
			identity := identities[0]

			if identity.IsForSSOProvider() {
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

// FindCurrentlyActiveRefreshToken returns the currently active refresh
// token in the session. This is the last created (ordered by the serial
// primary key) non-revoked refresh token for the session.
func (s *Session) FindCurrentlyActiveRefreshToken(tx *storage.Connection) (*RefreshToken, error) {
	var activeRefreshToken RefreshToken

	if err := tx.Q().Where("session_id = ? and revoked is false", s.ID).Order("id desc").First(&activeRefreshToken); err != nil {
		if errors.Cause(err) == sql.ErrNoRows || errors.Is(err, sql.ErrNoRows) {
			return nil, RefreshTokenNotFoundError{}
		}

		return nil, err
	}

	return &activeRefreshToken, nil
}
