package security

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/supabase/gotrue/utilities"
)

type GotrueRequest struct {
	Security GotrueSecurity `json:"gotrue_meta_security"`
}

type GotrueSecurity struct {
	Token string `json:"captcha_token"`
}

type VerificationResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
	Hostname   string   `json:"hostname"`
}

var Client *http.Client

func init() {
	var defaultTimeout time.Duration = time.Second * 10
	timeoutStr := os.Getenv("GOTRUE_SECURITY_CAPTCHA_TIMEOUT")
	if timeoutStr != "" {
		if timeout, err := time.ParseDuration(timeoutStr); err != nil {
			log.Fatalf("error loading GOTRUE_SECURITY_CAPTCHA_TIMEOUT: %v", err.Error())
		} else if timeout != 0 {
			defaultTimeout = timeout
		}
	}

	Client = &http.Client{Timeout: defaultTimeout}
}

func VerifyRequest(r *http.Request, secretKey string) (VerificationResponse, error) {
	bodyBytes, err := utilities.GetBodyBytes(r)
	if err != nil {
		return VerificationResponse{}, err
	}

	var requestBody GotrueRequest

	if err := json.Unmarshal(bodyBytes, &requestBody); err != nil {
		return VerificationResponse{}, errors.Wrap(err, "request body was not JSON")
	}

	captchaResponse := strings.TrimSpace(requestBody.Security.Token)

	if captchaResponse == "" {
		return VerificationResponse{}, errors.New("no hCaptcha response (captcha_token) found in request")
	}

	clientIP := utilities.GetIPAddress(r)

	return verifyCaptchaCode(captchaResponse, secretKey, clientIP)
}

func verifyCaptchaCode(token string, secretKey string, clientIP string) (VerificationResponse, error) {
	data := url.Values{}
	data.Set("secret", secretKey)
	data.Set("response", token)
	data.Set("remoteip", clientIP)
	// TODO (darora): pipe through sitekey

	r, err := http.NewRequest("POST", "https://hcaptcha.com/siteverify", strings.NewReader(data.Encode()))
	if err != nil {
		return VerificationResponse{}, errors.Wrap(err, "couldn't initialize request object for hcaptcha check")
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	res, err := Client.Do(r)
	if err != nil {
		return VerificationResponse{}, errors.Wrap(err, "failed to verify hcaptcha response")
	}
	defer res.Body.Close()

	var verificationResponse VerificationResponse

	if err := json.NewDecoder(res.Body).Decode(&verificationResponse); err != nil {
		return VerificationResponse{}, errors.Wrap(err, "failed to decode hcaptcha response: not JSON")
	}

	return verificationResponse, nil
}
