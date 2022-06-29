package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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

type VerificationResult int

const (
	UserRequestFailed VerificationResult = iota
	VerificationProcessFailure
	SuccessfullyVerified
)

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

func VerifyRequest(r *http.Request, secretKey string) (VerificationResult, error) {
	if r.FormValue("grant_type") == "refresh_token" {
		// captcha shouldn't be enabled on requests to refresh the token
		return SuccessfullyVerified, nil
	}
	res := GotrueRequest{}
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return UserRequestFailed, err
	}
	r.Body.Close()
	// re-init body so downstream route handlers don't get borked
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	jsonDecoder := json.NewDecoder(bytes.NewBuffer(bodyBytes))
	err = jsonDecoder.Decode(&res)
	if err != nil || strings.TrimSpace(res.Security.Token) == "" {
		return UserRequestFailed, errors.Wrap(err, "couldn't decode captcha info")
	}
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	return verifyCaptchaCode(res.Security.Token, secretKey, clientIP)
}

func verifyCaptchaCode(token string, secretKey string, clientIP string) (VerificationResult, error) {
	data := url.Values{}
	data.Set("secret", secretKey)
	data.Set("response", token)
	data.Set("remoteip", clientIP)
	// TODO (darora): pipe through sitekey

	r, err := http.NewRequest("POST", "https://hcaptcha.com/siteverify", strings.NewReader(data.Encode()))
	if err != nil {
		return VerificationProcessFailure, errors.Wrap(err, "couldn't initialize request object for hcaptcha check")
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	res, err := Client.Do(r)
	if err != nil {
		return VerificationProcessFailure, errors.Wrap(err, "failed to verify hcaptcha token")
	}
	verResult := VerificationResponse{}
	defer res.Body.Close()
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(&verResult)
	if err != nil {
		return VerificationProcessFailure, errors.Wrap(err, "failed to decode hcaptcha response")
	}
	logrus.WithField("result", verResult).Info("obtained hcaptcha verification result")
	if !verResult.Success {
		return UserRequestFailed, fmt.Errorf("user request suppressed by hcaptcha")
	}
	return SuccessfullyVerified, nil
}
