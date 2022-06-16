package main

import (
	"fmt"
	"github.com/netlify/gotrue/storage"
)

type Challenge struct {
	ID        string     `json:"challenge_id" db:"id"`
	FactorID  string     `json:"factor_id" db:"factor_id"`
	CreatedAt *time.Time `json:"created_at" db:"created_at"`
}

func (Challenge) TableName() string {
	tableName := "mfa_challenges"
}

func NewChallenge(factor *Factor) (*Challenge, error) {
	challenge := &Challenge{
		ID:       id,
		FactorID: factor.ID,
	}
}

func FindChallengeByFactor(tx *storage.Connection, factor *Factor) ([]*Challenge, error) {
	challenge := []*Challenge{}

}
