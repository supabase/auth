package api

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fatih/structs"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const (
	AppleAuthURL  = "https://appleid.apple.com/auth/authorize"
	AppleTokenURL = "https://appleid.apple.com/auth/token"
	AppleIssuer   = "https://appleid.apple.com"
)

func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{})

	// Set up mock verifier if in dev mode
	if os.Getenv("GOTRUE_DEV_BYPASS_SIG") == "true" {
		logrus.Info("Setting up global mock verifier for Apple")
		setupAppleMockVerifier()
	}
}

func setupAppleMockVerifier() {
	createVerifier := func(ctx context.Context, config *oidc.Config) *oidc.IDTokenVerifier {
		pk := myIdTokenPrivateKey()

		logrus.WithFields(logrus.Fields{
			"component": "api",
			"issuer":    AppleIssuer,
			"auth_url":  AppleAuthURL,
			"token_url": AppleTokenURL,
		}).Info("Configured mock verifier for Apple")

		return oidc.NewVerifier(
			AppleIssuer,
			&oidc.StaticKeySet{
				PublicKeys: []crypto.PublicKey{
					&pk.PublicKey,
				},
			},
			&oidc.Config{
				SkipClientIDCheck: true,
				Now:               config.Now,
			},
		)
	}

	// Register the verifier at all possible lookup points
	provider.OverrideVerifiers[AppleAuthURL] = createVerifier
	provider.OverrideVerifiers[AppleTokenURL] = createVerifier
	provider.OverrideVerifiers[AppleIssuer] = createVerifier
}

func myIdTokenPrivateKey() *rsa.PrivateKey {
	// #nosec
	der, err := base64.StdEncoding.DecodeString("MIIEpAIBAAKCAQEAvklrFDsVgbhs3DOQICMqm4xdFoi/MHj/T6XH8S7wXWd0roqdWVarwCLV4y3DILkLre4PzNK+hEY5NAnoAKrsCMyyCb4Wdl8HCdJk4ojDqAig+DJw67imqZoxJMFJyIhfMJhwVK1V8GRUPATn855rygLo7wThahMJeEHNiJr3TtV6Rf35KSs7DuyoWIUSjISYabQozKqIvpdUpTpSqjlOQvjdAxggRyycBZSgLzjWhsA8metnAMO48bX4bgiHLR6Kzu/dfPyEVPfgeYpA2ebIY6GzIUxVS0yX8+ExA6jeLCkuepjLHuz5XCJtd6zzGDXr1eX7nA6ZIeUNdFbWRDnPawIDAQABAoIBABH4Qvl1HvHSJc2hvPGcAJER71SKc2uzcYDnCfu30BEyDO3Sv0tJiQyq/YHnt26mqviw66MPH9jD/PDyIou1mHa4RfPvlJV3IeYGjWprOfbrYbAuq0VHec24dv2el0YtwreHHcyRVfVOtDm6yODTzCAWqEKyNktbIuDNbgiBgetayaJecDRoFMF9TOCeMCL92iZytzAr7fi+JWtLkRS/GZRIBjbr8LJ/ueYoCRmIx3MIw0WdPp7v2ZfeRTxP7LxJZ+MAsrq2pstmZYP7K0305e0bCJX1HexfXLs2Ul7u8zaxrXL8zw4/9+/GMsAeU3ffCVnGz/RKL5+T6iuz2RotjFECgYEA+Xk7DGwRXfDg9xba1GVFGeiC4nybqZw/RfZKcz/RRJWSHRJV/ps1avtbca3B19rjI6rewZMO1NWNv/tI2BdXP8vAKUnI9OHJZ+J/eZzmqDE6qu0v0ddRFUDzCMWE0j8BjrUdy44n4NQgopcv14u0iyr9tuhGO6YXn2SuuvEkZokCgYEAw0PNnT55kpkEhXSp7An2hdBJEub9ST7hS6Kcd8let62/qUZ/t5jWigSkWC1A2bMtH55+LgudIFjiehwVzRs7jym2j4jkKZGonyAX1l9IWgXwKl7Pn49lEQH5Yk6MhnXdyLGoFTzXiUyk/fKvgXX7jow1bD3j6sAc8P495I7TyVMCgYAHg6VJrH+har37805IE3zPWPeIRuSRaUlmnBKGAigVfsPV6FV6w8YKIOQSOn+aNtecnWr0Pa+2rXAFllYNXDaej06Mb9KDvcFJRcM9MIKqEkGIIHjOQ0QH9drcKsbjZk5vs/jfxrpgxULuYstoHKclgff+aGSlK02O2YOB0f2csQKBgQCEC/MdNiWCpKXxFg7fB3HF1i/Eb56zjKlQu7uyKeQ6tG3bLEisQNg8Z5034Apt7gRC0KyluMbeHB2z1BBOLu9dBill8X3SOqVcTpiwKKlF76QVEx622YLQOJSMDXBscYK0+KchDY74U3N0JEzZcI7YPCrYcxYRJy+rLVNvn8LK7wKBgQDE8THsZ589e10F0zDBvPK56o8PJnPeH71sgdM2Co4oLzBJ6g0rpJOKfcc03fLHsoJVOAya9WZeIy6K8+WVdcPTadR07S4p8/tcK1eguu5qlmCUOzswrTKAaJoIHO7cddQp3nySIqgYtkGdHKuvlQDMQkEKJS0meOm+vdeAG2rkaA==")
	if err != nil {
		logrus.WithError(err).Fatal("Failed to decode private key")
		panic(err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to parse private key")
		panic(err)
	}

	return privateKey
}

// LinkIdentityWithIDToken links a new identity to an existing user using an OIDC ID token
func (a *API) LinkIdentityWithIDToken(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	user := getUser(ctx)
	if user == nil {
		return unprocessableEntityError(ErrorCodeUserNotFound, "Missing authenticated user")
	}

	params := &IdTokenGrantParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	if params.IdToken == "" {
		return badRequestError(ErrorCodeValidationFailed, "id_token is required")
	}

	if params.Provider == "" && (params.ClientID == "" || params.Issuer == "") {
		return badRequestError(ErrorCodeValidationFailed, "provider or client_id and issuer are required")
	}

	logrus.WithFields(logrus.Fields{
		"provider":  params.Provider,
		"has_token": params.IdToken != "",
	}).Info("Retrieved token params")

	// Get OIDC provider
	oidcProvider, skipNonceCheck, providerType, acceptableClientIDs, err := params.getProvider(ctx, config, r)
	if err != nil {
		return err
	}

	logrus.WithFields(logrus.Fields{
		"provider_type": providerType,
		"skip_nonce":    skipNonceCheck,
		"token_url":     oidcProvider.Endpoint().TokenURL,
	}).Info("🏀 Got provider details")

	idToken, userData, err := provider.ParseIDToken(ctx, oidcProvider, nil, params.IdToken, provider.ParseIDTokenOptions{
		SkipAccessTokenCheck: params.AccessToken == "",
		AccessToken:          params.AccessToken,
	})
	if err != nil {
		logrus.WithError(err).Error("Failed to parse ID token")
		return oauthError("invalid_request", "Bad ID token").WithInternalError(err)
	}

	logrus.WithFields(logrus.Fields{
		"id_token_audience":     idToken.Audience,
		"acceptable_client_ids": acceptableClientIDs,
	}).Info("Verifying audience")

	correctAudience := false
	for _, clientID := range acceptableClientIDs {
		if clientID == "" {
			continue
		}

		for _, aud := range idToken.Audience {
			if aud == clientID {
				correctAudience = true
				logrus.WithField("matching_client_id", clientID).Info("Found matching audience")
				break
			}
		}

		if correctAudience {
			break
		}
	}

	if !correctAudience {
		return oauthError("invalid_request", "Unacceptable audience in id_token check GOTRUE_EXTERNAL_IOS_BUNDLE_ID")
	}

	if !skipNonceCheck && params.Nonce != "" {
		if params.Nonce != idToken.Nonce {
			return oauthError("invalid_nonce", "Invalid nonce")
		}
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		// Check if identity already exists
		identity, terr := models.FindIdentityByIdAndProvider(tx, userData.Metadata.Subject, providerType)
		if terr != nil {
			if !models.IsNotFoundError(terr) {
				return internalServerError("Database error finding identity").WithInternalError(terr)
			}
		}

		if identity != nil {
			if identity.UserID == user.ID {
				return unprocessableEntityError(ErrorCodeIdentityAlreadyExists, "Identity is already linked to this user")
			}
			return unprocessableEntityError(ErrorCodeIdentityAlreadyExists, "Identity is already linked to another user")
		}

		// Create new identity
		identityData := structs.Map(userData.Metadata)
		newIdentity, terr := models.NewIdentity(user, providerType, identityData)
		if terr != nil {
			return terr
		}

		if terr := tx.Create(newIdentity); terr != nil {
			return internalServerError("Error creating identity").WithInternalError(terr)
		}

		// Update user metadata
		if terr := user.UpdateUserMetaData(tx, identityData); terr != nil {
			return internalServerError("Error updating user metadata").WithInternalError(terr)
		}

		// Update app metadata providers
		if terr := user.UpdateAppMetaDataProviders(tx); terr != nil {
			return internalServerError("Error updating user providers").WithInternalError(terr)
		}

		return nil
	})

	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, user)
}
