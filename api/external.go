package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/netlify/gotrue/api/provider"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/sirupsen/logrus"
)

type ExternalProviderSession struct {
	SiteURL     string       `json:"SiteURL"`
	InstanceID  string       `json:"InstanceID"`
	NetlifyID   string       `json:"NetlifyID"`
	ExpiresAt   int64        `json:"ExpiresAt"`
	Provider    string       `json:"Provider"`
	InviteToken string       `json:"InviteToken,omitempty"`
	Referrer    string       `json:"Referrer,omitempty"`
	Session     goth.Session `json:"Session"`
}

type ExternalProviderClaims struct {
	NetlifyMicroserviceClaims
	Provider    string `json:"provider"`
	InviteToken string `json:"invite_token,omitempty"`
	Referrer    string `json:"referrer,omitempty"`
}

// ExternalSignupParams are the parameters the Signup endpoint accepts
type ExternalSignupParams struct {
	Provider string `json:"provider"`
	Code     string `json:"code"`
}

func (a *API) ExternalProviderRedirect(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)

	providerType := r.URL.Query().Get("provider")
	scopes := r.URL.Query().Get("scopes")

	inviteToken := r.URL.Query().Get("invite_token")
	if inviteToken != "" {
		_, userErr := models.FindUserByConfirmationToken(a.db, inviteToken)
		if userErr != nil {
			if models.IsNotFoundError(userErr) {
				return notFoundError(userErr.Error())
			}
			return internalServerError("Database error finding user").WithInternalError(userErr)
		}
	}

	redirectURL := a.validateRedirectURL(r, r.URL.Query().Get("redirect_to"))
	if redirectURL == "" {
		redirectURL = a.getReferrer(r)
	}

	provider, err := a.Provider(ctx, providerType, scopes)
	if err != nil {
		// check if goth supports provider
		gothProvider, err := goth.GetProvider(providerType)
		if err != nil {
			return internalServerError("Goth cannot find provider").WithInternalError(err)
		}
		gothSession, err := gothProvider.BeginAuth(gothic.SetState(r))
		if err != nil {
			return internalServerError("Goth cannot authenticate with provider").WithInternalError(err)
		}
		url, err := gothSession.GetAuthURL()
		if err != nil {
			return internalServerError("Goth cannot retrieve URL for the auth endpoint for the provider").WithInternalError(err)
		}

		// make use of session-based auth
		sess := &ExternalProviderSession{
			SiteURL:     config.SiteURL,
			InstanceID:  getInstanceID(ctx).String(),
			NetlifyID:   getNetlifyID(ctx),
			ExpiresAt:   time.Now().Add(5 * time.Minute).Unix(),
			Provider:    providerType,
			InviteToken: inviteToken,
			Referrer:    redirectURL,
			Session:     gothSession,
		}

		err = gothic.StoreInSession(providerType, sess.Marshal(), r, w)
		if err != nil {
			return internalServerError("Goth cannot store session").WithInternalError(err)
		}

		http.Redirect(w, r, url, http.StatusFound)
		return nil
	}

	log := getLogEntry(r)
	log.WithField("provider", providerType).Info("Redirecting to external provider")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, ExternalProviderClaims{
		NetlifyMicroserviceClaims: NetlifyMicroserviceClaims{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
			},
			SiteURL:    config.SiteURL,
			InstanceID: getInstanceID(ctx).String(),
			NetlifyID:  getNetlifyID(ctx),
		},
		Provider:    providerType,
		InviteToken: inviteToken,
		Referrer:    redirectURL,
	})
	tokenString, err := token.SignedString([]byte(a.config.OperatorToken))
	if err != nil {
		return internalServerError("Error creating state").WithInternalError(err)
	}

	http.Redirect(w, r, provider.AuthCodeURL(tokenString), http.StatusFound)
	return nil
}

func (a *API) ExternalProviderCallback(w http.ResponseWriter, r *http.Request) error {
	a.redirectErrors(a.internalExternalProviderCallback, w, r)
	return nil
}

func (a *API) internalExternalProviderCallback(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)

	// handle callback using session data
	providerType, err := gothic.GetProviderName(r)
	if err != nil {
		return err
	}

	var userData *provider.UserProvidedData
	var providerToken string

	gothProvider, err := goth.GetProvider(providerType)
	if err != nil {
		return err
	}
	value, err := gothic.GetFromSession(providerType, r)
	if err != nil {
		return err
	}
	sess, err := unmarshalSession(value, gothProvider)
	if err != nil {
		return err
	}
	// validate state to ensure that the state token param from the original
	// AuthURL matches the one included in the current callback req
	rawAuthURL, err := sess.Session.GetAuthURL()
	if err != nil {
		return err
	}
	authURL, err := url.Parse(rawAuthURL)
	if err != nil {
		return err
	}
	reqState := gothic.GetState(r)
	originalState := authURL.Query().Get("state")
	if originalState != "" && (originalState != reqState) {
		return errors.New("state token mismatch")
	}
	gothUser, err := gothProvider.FetchUser(sess.Session)
	if err != nil {
		params := r.URL.Query()
		if params.Encode() == "" && r.Method == "POST" {
			r.ParseForm()
			params = r.Form
		}
		_, err = sess.Session.Authorize(gothProvider, params)
		if err != nil {
			return err
		}
		gothUser, err = gothProvider.FetchUser(sess.Session)
		if err != nil {
			return err
		}
	}

	providerToken = gothUser.AccessToken
	userData = &provider.UserProvidedData{
		Metadata: map[string]string{
			"full_name":  gothUser.Name,
			"avatar_url": gothUser.AvatarURL,
		},
	}

	if gothUser.Email != "" {
		userData.Emails = append(userData.Emails, provider.Email{
			Email:    gothUser.Email,
			Verified: true, // TODO: check with external provider if email is verified
			Primary:  true, // TODO: check with external provider if email is primary email

		})
	}

	var user *models.User
	var token *AccessTokenResponse
	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		inviteToken := sess.InviteToken
		instanceID, terr := uuid.FromString(sess.InstanceID)
		if terr != nil {
			return terr
		}
		if inviteToken != "" {
			if user, terr = a.processInvite(ctx, tx, userData, instanceID, inviteToken, providerType); terr != nil {
				return terr
			}
		} else {
			// TODO: migrate existing users using JWT Audience claim
			aud := "authenticated"
			var emailData provider.Email
			for _, e := range userData.Emails {
				if e.Verified || config.Mailer.Autoconfirm {
					user, terr = models.FindUserByEmailAndAudience(tx, instanceID, e.Email, aud)
					if terr != nil && !models.IsNotFoundError(terr) {
						return internalServerError("Error checking for duplicate users").WithInternalError(terr)
					}

					if user != nil {
						emailData = e
						break
					}
				}
			}

			if user == nil {
				if config.DisableSignup {
					return forbiddenError("Signups not allowed for this instance")
				}

				// prefer primary email for new signups
				emailData = userData.Emails[0]
				for _, e := range userData.Emails {
					if e.Primary {
						emailData = e
						break
					}
				}

				params := &SignupParams{
					Provider: providerType,
					Email:    emailData.Email,
					Aud:      aud,
					Data:     make(map[string]interface{}),
				}
				for k, v := range userData.Metadata {
					if v != "" {
						params.Data[k] = v
					}
				}

				user, terr = a.signupNewUser(ctx, tx, params, instanceID)
				if terr != nil {
					return terr
				}
			}
			if !user.IsConfirmed() {
				return internalServerError("User confirmation error").WithInternalError(errors.New("TODO: Implement unconfirmed user logic!"))
			} else {
				if terr := models.NewAuditLogEntry(tx, instanceID, user, models.LoginAction, nil); terr != nil {
					return terr
				}
				if terr = triggerEventHooks(ctx, tx, LoginEvent, user, instanceID, config); terr != nil {
					return terr
				}
			}

			token, terr = a.issueRefreshToken(ctx, tx, user)
			if terr != nil {
				return oauthError("server_error", terr.Error())
			}
			return nil
		}
		if err != nil {
			return err
		}
		return nil
	})

	// err = a.db.Transaction(func(tx *storage.Connection) error {
	// 	var terr error
	// 	// inviteToken := getInviteToken(ctx)
	// 	inviteToken := sess.InviteToken
	// 	if inviteToken != "" {
	// 		if user, terr = a.processInvite(ctx, tx, userData, sess.InstanceID, inviteToken, providerType); terr != nil {
	// 			return terr
	// 		}
	// 	} else {
	// 		aud := a.requestAud(ctx, r)

	// 		// search user using all available emails
	// 		var emailData provider.Email
	// 		for _, e := range userData.Emails {
	// 			if e.Verified || config.Mailer.Autoconfirm {
	// 				user, terr = models.FindUserByEmailAndAudience(tx, instanceID, e.Email, aud)
	// 				if terr != nil && !models.IsNotFoundError(terr) {
	// 					return internalServerError("Error checking for duplicate users").WithInternalError(terr)
	// 				}

	// 				if user != nil {
	// 					emailData = e
	// 					break
	// 				}
	// 			}
	// 		}

	// 		if user == nil {
	// 			if config.DisableSignup {
	// 				return forbiddenError("Signups not allowed for this instance")
	// 			}

	// 			// prefer primary email for new signups
	// 			emailData = userData.Emails[0]
	// 			for _, e := range userData.Emails {
	// 				if e.Primary {
	// 					emailData = e
	// 					break
	// 				}
	// 			}

	// 			params := &SignupParams{
	// 				Provider: providerType,
	// 				Email:    emailData.Email,
	// 				Aud:      aud,
	// 				Data:     make(map[string]interface{}),
	// 			}
	// 			for k, v := range userData.Metadata {
	// 				if v != "" {
	// 					params.Data[k] = v
	// 				}
	// 			}

	// 			user, terr = a.signupNewUser(ctx, tx, params)
	// 			if terr != nil {
	// 				return terr
	// 			}
	// 		}

	// 		if !user.IsConfirmed() {
	// 			if !emailData.Verified && !config.Mailer.Autoconfirm {
	// 				mailer := a.Mailer(ctx)
	// 				referrer := a.getReferrer(r)
	// 				if terr = sendConfirmation(tx, user, mailer, config.SMTP.MaxFrequency, referrer); terr != nil {
	// 					return internalServerError("Error sending confirmation mail").WithInternalError(terr)
	// 				}
	// 				// email must be verified to issue a token
	// 				return nil
	// 			}

	// 			if terr := models.NewAuditLogEntry(tx, instanceID, user, models.UserSignedUpAction, nil); terr != nil {
	// 				return terr
	// 			}
	// 			if terr = triggerEventHooks(ctx, tx, SignupEvent, user, instanceID, config); terr != nil {
	// 				return terr
	// 			}

	// 			// fall through to auto-confirm and issue token
	// 			if terr = user.Confirm(tx); terr != nil {
	// 				return internalServerError("Error updating user").WithInternalError(terr)
	// 			}
	// 		} else {
	// 			if terr := models.NewAuditLogEntry(tx, instanceID, user, models.LoginAction, nil); terr != nil {
	// 				return terr
	// 			}
	// 			if terr = triggerEventHooks(ctx, tx, LoginEvent, user, instanceID, config); terr != nil {
	// 				return terr
	// 			}
	// 		}
	// 	}

	// 	token, terr = a.issueRefreshToken(ctx, tx, user)
	// 	if terr != nil {
	// 		return oauthError("server_error", terr.Error())
	// 	}
	// 	return nil
	// })

	// if err != nil {
	// 	return err
	// }

	rurl := a.getExternalRedirectURL(r)
	q := url.Values{}
	q.Set("provider_token", providerToken)
	q.Set("access_token", token.Token)
	q.Set("token_type", token.TokenType)
	q.Set("expires_in", strconv.Itoa(int(sess.ExpiresAt)))
	q.Set("refresh_token", token.RefreshToken)
	rurl += "#" + q.Encode()

	http.Redirect(w, r, rurl, http.StatusFound)
	return nil
}

func (a *API) processInvite(ctx context.Context, tx *storage.Connection, userData *provider.UserProvidedData, instanceID uuid.UUID, inviteToken, providerType string) (*models.User, error) {
	config := a.getConfig(ctx)
	user, err := models.FindUserByConfirmationToken(tx, inviteToken)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, notFoundError(err.Error())
		}
		return nil, internalServerError("Database error finding user").WithInternalError(err)
	}

	var emailData *provider.Email
	var emails []string
	for _, e := range userData.Emails {
		emails = append(emails, e.Email)
		if user.Email == e.Email {
			emailData = &e
			break
		}
	}

	if emailData == nil {
		return nil, badRequestError("Invited email does not match emails from external provider").WithInternalMessage("invited=%s external=%s", user.Email, strings.Join(emails, ", "))
	}

	if err := user.UpdateAppMetaData(tx, map[string]interface{}{
		"provider": providerType,
	}); err != nil {
		return nil, internalServerError("Database error updating user").WithInternalError(err)
	}

	updates := make(map[string]interface{})
	for k, v := range userData.Metadata {
		if v != "" {
			updates[k] = v
		}
	}
	if err := user.UpdateUserMetaData(tx, updates); err != nil {
		return nil, internalServerError("Database error updating user").WithInternalError(err)
	}

	if err := models.NewAuditLogEntry(tx, instanceID, user, models.InviteAcceptedAction, nil); err != nil {
		return nil, err
	}
	if err := triggerEventHooks(ctx, tx, SignupEvent, user, instanceID, config); err != nil {
		return nil, err
	}

	// confirm because they were able to respond to invite email
	if err := user.Confirm(tx); err != nil {
		return nil, err
	}
	return user, nil
}

func (a *API) loadExternalState(ctx context.Context, state string) (context.Context, error) {
	claims := ExternalProviderClaims{}
	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	_, err := p.ParseWithClaims(state, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.config.OperatorToken), nil
	})
	if err != nil || claims.Provider == "" {
		return nil, badRequestError("OAuth state is invalid: %v", err)
	}
	if claims.InviteToken != "" {
		ctx = withInviteToken(ctx, claims.InviteToken)
	}
	if claims.Referrer != "" {
		ctx = withExternalReferrer(ctx, claims.Referrer)
	}

	ctx = withExternalProviderType(ctx, claims.Provider)
	return withSignature(ctx, state), nil
}

// Provider returns a Provider interface for the given name.
func (a *API) Provider(ctx context.Context, name string, scopes string) (provider.Provider, error) {
	config := a.getConfig(ctx)
	name = strings.ToLower(name)

	switch name {
	case "bitbucket":
		return provider.NewBitbucketProvider(config.External.Bitbucket)
	case "github":
		return provider.NewGithubProvider(config.External.Github, scopes)
	case "gitlab":
		return provider.NewGitlabProvider(config.External.Gitlab, scopes)
	// case "google":
	// 	return provider.NewGoogleProvider(config.External.Google, scopes)
	case "facebook":
		return provider.NewFacebookProvider(config.External.Facebook, scopes)
	case "azure":
		return provider.NewAzureProvider(config.External.Azure, scopes)
	case "saml":
		return provider.NewSamlProvider(config.External.Saml, a.db, getInstanceID(ctx))
	default:
		return nil, fmt.Errorf("Provider %s could not be found", name)
	}
}

func (a *API) redirectErrors(handler apiHandler, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := getLogEntry(r)
	errorID := getRequestID(ctx)
	err := handler(w, r)
	if err != nil {
		q := getErrorQueryString(err, errorID, log)
		http.Redirect(w, r, a.getExternalRedirectURL(r)+"?"+q.Encode(), http.StatusFound)
	}
}

func getErrorQueryString(err error, errorID string, log logrus.FieldLogger) *url.Values {
	q := url.Values{}
	switch e := err.(type) {
	case *HTTPError:
		if str, ok := oauthErrorMap[e.Code]; ok {
			q.Set("error", str)
		} else {
			q.Set("error", "server_error")
		}
		if e.Code >= http.StatusInternalServerError {
			e.ErrorID = errorID
			// this will get us the stack trace too
			log.WithError(e.Cause()).Error(e.Error())
		} else {
			log.WithError(e.Cause()).Info(e.Error())
		}
		q.Set("error_description", e.Message)
	case *OAuthError:
		q.Set("error", e.Err)
		q.Set("error_description", e.Description)
		log.WithError(e.Cause()).Info(e.Error())
	case ErrorCause:
		return getErrorQueryString(e.Cause(), errorID, log)
	default:
		q.Set("error", "server_error")
		q.Set("error_description", err.Error())
	}
	return &q
}

func (a *API) getExternalRedirectURL(r *http.Request) string {
	ctx := r.Context()
	config := a.getConfig(ctx)
	if config.External.RedirectURL != "" {
		return config.External.RedirectURL
	}
	if er := getExternalReferrer(ctx); er != "" {
		return er
	}
	return config.SiteURL
}

func (s ExternalProviderSession) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func unmarshalSession(data string, provider goth.Provider) (ExternalProviderSession, error) {
	var dataMap map[string]json.RawMessage
	err := json.Unmarshal([]byte(data), &dataMap)
	sess := &ExternalProviderSession{}

	for k, v := range dataMap {
		if k == "Session" {
			gothSession, err := provider.UnmarshalSession(string(v))
			if err != nil {
				return *sess, fmt.Errorf("Unmarshal session error: %s", err)
			}
			if err := SetField(sess, k, gothSession); err != nil {
				return *sess, fmt.Errorf("Unmarshal session error: %s", err)
			}
		} else if k == "ExpiresAt" {
			expiresAt, err := strconv.ParseInt(string(v), 10, 64)
			if err != nil {
				return *sess, fmt.Errorf("Unmarshal session error: %s", err)
			}
			if err := SetField(sess, k, expiresAt); err != nil {
				return *sess, fmt.Errorf("Unmarshal session error: %s", err)
			}
		} else {
			ns, err := strconv.Unquote(string(v))
			if err != nil {
				return *sess, fmt.Errorf("Unmarshal session error: %s", err)
			}
			if err := SetField(sess, k, ns); err != nil {
				return *sess, fmt.Errorf("Unmarshal session error: %s", err)
			}
		}
	}
	return *sess, err
}

func SetField(obj interface{}, name string, value interface{}) error {
	structValue := reflect.ValueOf(obj).Elem()
	structFieldValue := structValue.FieldByName(name)

	if !structFieldValue.IsValid() {
		return fmt.Errorf("No such field: %s in obj", name)
	}

	if !structFieldValue.CanSet() {
		return fmt.Errorf("Cannot set %s field value", name)
	}

	structFieldType := structFieldValue.Type()
	val := reflect.ValueOf(value)
	if name == "Session" {
		structFieldValue.Set(val)
		return nil
	}
	if structFieldType != val.Type() {
		return errors.New("Provided value type didn't match obj field type")
	}

	structFieldValue.Set(val)
	return nil
}
