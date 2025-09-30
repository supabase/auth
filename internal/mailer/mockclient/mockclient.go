package mockclient

import (
	"net/http"
	"net/url"

	"github.com/supabase/auth/internal/models"
)

// MockMailer implements the mailer.Mailer interface for testing
type MockMailer struct {
	InviteMailCalls         []InviteMailCall
	ConfirmationMailCalls   []ConfirmationMailCall
	RecoveryMailCalls       []RecoveryMailCall
	MagicLinkMailCalls      []MagicLinkMailCall
	EmailChangeMailCalls    []EmailChangeMailCall
	ReauthenticateMailCalls []ReauthenticateMailCall
	GetEmailActionLinkCalls []GetEmailActionLinkCall

	PasswordChangedMailCalls     []PasswordChangedMailCall
	EmailChangedMailCalls        []EmailChangedMailCall
	MFAFactorEnrolledMailCalls   []MFAFactorEnrolledMailCall
	MFAFactorUnenrolledMailCalls []MFAFactorUnenrolledMailCall
}

type InviteMailCall struct {
	User        *models.User
	OTP         string
	ReferrerURL string
	ExternalURL *url.URL
}

type ConfirmationMailCall struct {
	User        *models.User
	OTP         string
	ReferrerURL string
	ExternalURL *url.URL
}

type RecoveryMailCall struct {
	User        *models.User
	OTP         string
	ReferrerURL string
	ExternalURL *url.URL
}

type MagicLinkMailCall struct {
	User        *models.User
	OTP         string
	ReferrerURL string
	ExternalURL *url.URL
}

type EmailChangeMailCall struct {
	User        *models.User
	OTPNew      string
	OTPCurrent  string
	ReferrerURL string
	ExternalURL *url.URL
}

type ReauthenticateMailCall struct {
	User *models.User
	OTP  string
}

type GetEmailActionLinkCall struct {
	User        *models.User
	ActionType  string
	ReferrerURL string
	ExternalURL *url.URL
	Result      string
	Error       error
}

type PasswordChangedMailCall struct {
	User *models.User
}

type EmailChangedMailCall struct {
	User     *models.User
	OldEmail string
}

type MFAFactorEnrolledMailCall struct {
	User       *models.User
	FactorType string
}

type MFAFactorUnenrolledMailCall struct {
	User       *models.User
	FactorType string
}

func (m *MockMailer) InviteMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	m.InviteMailCalls = append(m.InviteMailCalls, InviteMailCall{
		User:        user,
		OTP:         otp,
		ReferrerURL: referrerURL,
		ExternalURL: externalURL,
	})
	return nil
}

func (m *MockMailer) ConfirmationMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	m.ConfirmationMailCalls = append(m.ConfirmationMailCalls, ConfirmationMailCall{
		User:        user,
		OTP:         otp,
		ReferrerURL: referrerURL,
		ExternalURL: externalURL,
	})
	return nil
}

func (m *MockMailer) RecoveryMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	m.RecoveryMailCalls = append(m.RecoveryMailCalls, RecoveryMailCall{
		User:        user,
		OTP:         otp,
		ReferrerURL: referrerURL,
		ExternalURL: externalURL,
	})
	return nil
}

func (m *MockMailer) MagicLinkMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	m.MagicLinkMailCalls = append(m.MagicLinkMailCalls, MagicLinkMailCall{
		User:        user,
		OTP:         otp,
		ReferrerURL: referrerURL,
		ExternalURL: externalURL,
	})
	return nil
}

func (m *MockMailer) EmailChangeMail(r *http.Request, user *models.User, otpNew, otpCurrent, referrerURL string, externalURL *url.URL) error {
	m.EmailChangeMailCalls = append(m.EmailChangeMailCalls, EmailChangeMailCall{
		User:        user,
		OTPNew:      otpNew,
		OTPCurrent:  otpCurrent,
		ReferrerURL: referrerURL,
		ExternalURL: externalURL,
	})
	return nil
}

func (m *MockMailer) ReauthenticateMail(r *http.Request, user *models.User, otp string) error {
	m.ReauthenticateMailCalls = append(m.ReauthenticateMailCalls, ReauthenticateMailCall{
		User: user,
		OTP:  otp,
	})
	return nil
}

func (m *MockMailer) GetEmailActionLink(user *models.User, actionType, referrerURL string, externalURL *url.URL) (string, error) {
	call := GetEmailActionLinkCall{
		User:        user,
		ActionType:  actionType,
		ReferrerURL: referrerURL,
		ExternalURL: externalURL,
		Result:      "http://example.com/action",
		Error:       nil,
	}
	m.GetEmailActionLinkCalls = append(m.GetEmailActionLinkCalls, call)
	return call.Result, call.Error
}

func (m *MockMailer) PasswordChangedNotificationMail(r *http.Request, user *models.User) error {
	m.PasswordChangedMailCalls = append(m.PasswordChangedMailCalls, PasswordChangedMailCall{
		User: user,
	})
	return nil
}

func (m *MockMailer) EmailChangedNotificationMail(r *http.Request, user *models.User, oldEmail string) error {
	m.EmailChangedMailCalls = append(m.EmailChangedMailCalls, EmailChangedMailCall{
		User:     user,
		OldEmail: oldEmail,
	})
	return nil
}

func (m *MockMailer) MFAFactorEnrolledNotificationMail(r *http.Request, user *models.User, factorType string) error {
	m.MFAFactorEnrolledMailCalls = append(m.MFAFactorEnrolledMailCalls, MFAFactorEnrolledMailCall{
		User:       user,
		FactorType: factorType,
	})
	return nil
}

func (m *MockMailer) MFAFactorUnenrolledNotificationMail(r *http.Request, user *models.User, factorType string) error {
	m.MFAFactorUnenrolledMailCalls = append(m.MFAFactorUnenrolledMailCalls, MFAFactorUnenrolledMailCall{
		User:       user,
		FactorType: factorType,
	})
	return nil
}

func (m *MockMailer) Reset() {
	m.InviteMailCalls = nil
	m.ConfirmationMailCalls = nil
	m.RecoveryMailCalls = nil
	m.MagicLinkMailCalls = nil
	m.EmailChangeMailCalls = nil
	m.ReauthenticateMailCalls = nil
	m.GetEmailActionLinkCalls = nil

	m.PasswordChangedMailCalls = nil
	m.EmailChangedMailCalls = nil
	m.MFAFactorEnrolledMailCalls = nil
	m.MFAFactorUnenrolledMailCalls = nil
}
