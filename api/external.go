package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt"
	"github.com/netlify/gotrue/api/provider"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/utilities"
	"github.com/sirupsen/logrus"
)

// ExternalProviderClaims are the JWT claims sent as the state in the external oauth provider signup flow
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

// ExternalProviderRedirect redirects the request to the corresponding oauth provider
func (a *API) ExternalProviderRedirect(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)

	query := r.URL.Query()
	providerType := query.Get("provider")
	scopes := query.Get("scopes")

	p, err := a.Provider(ctx, providerType, scopes, &query)
	if err != nil {
		return badRequestError("Unsupported provider: %+v", err).WithInternalError(err)
	}

	inviteToken := query.Get("invite_token")
	if inviteToken != "" {
		_, userErr := models.FindUserByConfirmationToken(a.db, inviteToken)
		if userErr != nil {
			if models.IsNotFoundError(userErr) {
				return notFoundError(userErr.Error())
			}
			return internalServerError("Database error finding user").WithInternalError(userErr)
		}
	}

	redirectURL := a.getRedirectURLOrReferrer(r, query.Get("redirect_to"))
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
	tokenString, err := token.SignedString([]byte(config.JWT.Secret))
	if err != nil {
		return internalServerError("Error creating state").WithInternalError(err)
	}

	var authURL string
	switch externalProvider := p.(type) {
	case *provider.TwitterProvider:
		authURL = externalProvider.AuthCodeURL(tokenString)
		err := storage.StoreInSession(providerType, externalProvider.Marshal(), r, w)
		if err != nil {
			return internalServerError("Error storing request token in session").WithInternalError(err)
		}
	default:
		authURL = p.AuthCodeURL(tokenString)
	}

	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

// ExternalProviderCallback handles the callback endpoint in the external oauth provider flow
func (a *API) ExternalProviderCallback(w http.ResponseWriter, r *http.Request) error {
	a.redirectErrors(a.internalExternalProviderCallback, w, r)
	return nil
}

// SAMLAssertionConsumerService handles the ACS endpoint
func (a *API) SAMLAssertionConsumerService(w http.ResponseWriter, r *http.Request) error {
	// TODO: I'm really not super happy with the handling of this in
	// internalExternalProviderCallback -- needs to be refactored.
	newReq := r.WithContext(withExternalProviderType(r.Context(), "saml"))

	a.redirectErrors(a.internalExternalProviderCallback, w, newReq)
	return nil
}

func (a *API) internalExternalProviderCallback(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)

	providerType := getExternalProviderType(ctx)
	var userData *provider.UserProvidedData
	var cond *models.GrantAuthenticatedConditions
	var providerToken string
	if providerType == "saml" {
		samlUserData, samlCond, err := a.samlCallback(ctx, r)
		if err != nil {
			return err
		}
		userData = samlUserData
		cond = samlCond
	} else if providerType == "twitter" {
		// future OAuth1.0 providers will use this method
		oAuthResponseData, err := a.oAuth1Callback(ctx, r, providerType)
		if err != nil {
			return err
		}
		userData = oAuthResponseData.userData
		providerToken = oAuthResponseData.token
	} else {
		oAuthResponseData, err := a.oAuthCallback(ctx, r, providerType)
		if err != nil {
			return err
		}
		userData = oAuthResponseData.userData
		providerToken = oAuthResponseData.token
	}

	var user *models.User
	var token *AccessTokenResponse
	err := a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		inviteToken := getInviteToken(ctx)
		if inviteToken != "" {
			if user, terr = a.processInvite(ctx, tx, userData, instanceID, inviteToken, providerType); terr != nil {
				return terr
			}
		} else {
			aud := a.requestAud(ctx, r)
			var emailData provider.Email
			var identityData map[string]interface{}
			if userData.Metadata != nil {
				identityData, terr = userData.Metadata.ToMap()
				if terr != nil {
					return terr
				}
			}

			var identity *models.Identity
			// check if identity exists
			if identity, terr = models.FindIdentityByIdAndProvider(tx, userData.Metadata.Subject, providerType); terr != nil {
				if models.IsNotFoundError(terr) {
					user, emailData, terr = a.getUserByVerifiedEmail(tx, config, userData.Emails, instanceID, aud)
					if terr != nil && !models.IsNotFoundError(terr) {
						return internalServerError("Error checking for existing users").WithInternalError(terr)
					}
					if user != nil {
						if identity, terr = a.createNewIdentity(tx, user, providerType, identityData); terr != nil {
							return terr
						}
						if terr = user.UpdateAppMetaDataProviders(tx); terr != nil {
							return terr
						}
					} else {
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
							Data:     identityData,
						}

						user, terr = a.signupNewUser(ctx, tx, params)
						if terr != nil {
							return terr
						}

						if identity, terr = a.createNewIdentity(tx, user, providerType, identityData); terr != nil {
							return terr
						}
					}
				} else {
					return terr
				}
			}

			if identity != nil && user == nil {
				// get user associated with identity
				user, terr = models.FindUserByID(tx, identity.UserID)
				if terr != nil {
					return terr
				}
				identity.IdentityData = identityData
				if terr = tx.UpdateOnly(identity, "identity_data", "last_sign_in_at"); terr != nil {
					return terr
				}
				// email & verified status might have changed if identity's email changed
				emailData = provider.Email{
					Email:    userData.Metadata.Email,
					Verified: userData.Metadata.EmailVerified,
				}
				if terr = user.UpdateUserMetaData(tx, identityData); terr != nil {
					return terr
				}
				if terr = user.UpdateAppMetaDataProviders(tx); terr != nil {
					return terr
				}
			}

			if user.IsBanned() {
				return unauthorizedError("User is unauthorized")
			}

			// an account with a previously unconfirmed email + password
			// combination or phone may exist. so now that there is an
			// OAuth identity bound to this user, and since they have not
			// confirmed their email or phone, they are unaware that a
			// potentially malicious door exists into their account; thus
			// the password and phone needs to be removed.
			if terr = user.RemoveUnconfirmedIdentities(tx); terr != nil {
				return internalServerError("Error updating user").WithInternalError(terr)
			}

			if !user.IsConfirmed() {
				if !emailData.Verified && !config.Mailer.Autoconfirm {
					mailer := a.Mailer(ctx)
					referrer := a.getReferrer(r)
					if terr = sendConfirmation(tx, user, mailer, config.SMTP.MaxFrequency, referrer, config.Mailer.OtpLength); terr != nil {
						if errors.Is(terr, MaxFrequencyLimitError) {
							return tooManyRequestsError("For security purposes, you can only request this once every minute")
						}
						return internalServerError("Error sending confirmation mail").WithInternalError(terr)
					}
					// email must be verified to issue a token
					return nil
				}

				if terr := models.NewAuditLogEntry(tx, instanceID, user, models.UserSignedUpAction, "", map[string]interface{}{
					"provider": providerType,
				}); terr != nil {
					return terr
				}
				if terr = triggerEventHooks(ctx, tx, SignupEvent, user, instanceID, config); terr != nil {
					return terr
				}

				// fall through to auto-confirm and issue token
				if terr = user.Confirm(tx); terr != nil {
					return internalServerError("Error updating user").WithInternalError(terr)
				}
			} else {
				if terr := models.NewAuditLogEntry(tx, instanceID, user, models.LoginAction, "", map[string]interface{}{
					"provider": providerType,
				}); terr != nil {
					return terr
				}
				if terr = triggerEventHooks(ctx, tx, LoginEvent, user, instanceID, config); terr != nil {
					return terr
				}
			}
		}

		token, terr = a.issueRefreshToken(ctx, tx, user, cond)
		if terr != nil {
			return oauthError("server_error", terr.Error())
		}
		return nil
	})
	if err != nil {
		return err
	}

	rurl := a.getExternalRedirectURL(r)
	if token != nil {
		q := url.Values{}
		q.Set("provider_token", providerToken)
		q.Set("access_token", token.Token)
		q.Set("token_type", token.TokenType)
		q.Set("expires_in", strconv.Itoa(token.ExpiresIn))
		q.Set("refresh_token", token.RefreshToken)
		rurl += "#" + q.Encode()

		if err := a.setCookieTokens(config, token, false, w); err != nil {
			return internalServerError("Failed to set JWT cookie. %s", err)
		}
	} else {
		rurl = a.prepErrorRedirectURL(unauthorizedError("Unverified email with %v", providerType), r, rurl)
	}

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
		if user.GetEmail() == e.Email {
			emailData = &e
			break
		}
	}

	if emailData == nil {
		return nil, badRequestError("Invited email does not match emails from external provider").WithInternalMessage("invited=%s external=%s", user.Email, strings.Join(emails, ", "))
	}

	var identityData map[string]interface{}
	if userData.Metadata != nil {
		identityData, err = userData.Metadata.ToMap()
		if err != nil {
			return nil, internalServerError("Error serialising user metadata").WithInternalError(err)
		}
	}
	if _, err := a.createNewIdentity(tx, user, providerType, identityData); err != nil {
		return nil, err
	}
	if err = user.UpdateAppMetaData(tx, map[string]interface{}{
		"provider": providerType,
	}); err != nil {
		return nil, err
	}
	if err = user.UpdateAppMetaDataProviders(tx); err != nil {
		return nil, err
	}
	if err := user.UpdateUserMetaData(tx, identityData); err != nil {
		return nil, internalServerError("Database error updating user").WithInternalError(err)
	}

	if err := models.NewAuditLogEntry(tx, instanceID, user, models.InviteAcceptedAction, "", map[string]interface{}{
		"provider": providerType,
	}); err != nil {
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
	config := a.getConfig(ctx)
	claims := ExternalProviderClaims{}
	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	_, err := p.ParseWithClaims(state, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JWT.Secret), nil
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
func (a *API) Provider(ctx context.Context, name string, scopes string, query *url.Values) (provider.Provider, error) {
	config := a.getConfig(ctx)
	name = strings.ToLower(name)

	switch name {
	case "apple":
		return provider.NewAppleProvider(config.External.Apple)
	case "azure":
		return provider.NewAzureProvider(config.External.Azure, scopes)
	case "bitbucket":
		return provider.NewBitbucketProvider(config.External.Bitbucket)
	case "discord":
		return provider.NewDiscordProvider(config.External.Discord, scopes)
	case "github":
		return provider.NewGithubProvider(config.External.Github, scopes)
	case "gitlab":
		return provider.NewGitlabProvider(config.External.Gitlab, scopes)
	case "google":
		return provider.NewGoogleProvider(config.External.Google, scopes)
	case "keycloak":
		return provider.NewKeycloakProvider(config.External.Keycloak, scopes)
	case "linkedin":
		return provider.NewLinkedinProvider(config.External.Linkedin, scopes)
	case "facebook":
		return provider.NewFacebookProvider(config.External.Facebook, scopes)
	case "notion":
		return provider.NewNotionProvider(config.External.Notion)
	case "spotify":
		return provider.NewSpotifyProvider(config.External.Spotify, scopes)
	case "slack":
		return provider.NewSlackProvider(config.External.Slack, scopes)
	case "twitch":
		return provider.NewTwitchProvider(config.External.Twitch, scopes)
	case "twitter":
		return provider.NewTwitterProvider(config.External.Twitter, scopes)
	case "workos":
		return provider.NewWorkOSProvider(config.External.WorkOS, query)
	case "zoom":
		return provider.NewZoomProvider(config.External.Zoom)
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
		error_type, error_description := "server_error", err.Error()

		// Provide better error messages for certain user-triggered Postgres errors.
		if pgErr := utilities.NewPostgresError(e); pgErr != nil {
			error_description = pgErr.Message
			if oauthErrorType, ok := oauthErrorMap[pgErr.HttpStatusCode]; ok {
				error_type = oauthErrorType
			}
		}

		q.Set("error", error_type)
		q.Set("error_description", error_description)
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

func (a *API) createNewIdentity(conn *storage.Connection, user *models.User, providerType string, identityData map[string]interface{}) (*models.Identity, error) {
	identity, err := models.NewIdentity(user, providerType, identityData)
	if err != nil {
		return nil, err
	}

	err = conn.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(identity); terr != nil {
			return internalServerError("Error creating identity").WithInternalError(terr)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return identity, nil
}

// getUserByVerifiedEmail checks if one of the verified emails already belongs to a user
func (a *API) getUserByVerifiedEmail(tx *storage.Connection, config *conf.Configuration, emails []provider.Email, instanceID uuid.UUID, aud string) (*models.User, provider.Email, error) {
	var user *models.User
	var emailData provider.Email
	var err error

	for _, e := range emails {
		if e.Verified || config.Mailer.Autoconfirm {
			user, err = models.FindUserByEmailAndAudience(tx, instanceID, e.Email, aud)
			if err != nil && !models.IsNotFoundError(err) {
				return user, emailData, err
			}
			if user != nil {
				emailData = e
				break
			}
		}
	}
	return user, emailData, err
}
