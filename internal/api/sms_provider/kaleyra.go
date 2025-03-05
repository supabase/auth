// filepath: internal/api/sms_provider/kaleyra.go
package sms_provider

import (
    "fmt"
    "net/http"
    "net/url"
    "strings"
    "github.com/supabase/auth/internal/conf"
    "github.com/supabase/auth/internal/utilities"
)

const kaleyraApiBase = "https://api.kaleyra.io/v1"

type Kaleyra struct {
    Config  *conf.KaleyraConfiguration
    APIPath string
}

func NewKaleyraProvider(config conf.KaleyraConfiguration) (SmsProvider, error) {
    if err := config.Validate(); err != nil {
        return nil, err
    }

    apiPath := kaleyraApiBase + "/messages"
    return &Kaleyra{
        Config:  &config,
        APIPath: apiPath,
    }, nil
}

func (k *Kaleyra) SendMessage(phone, message, channel, otp string) (string, error) {
    return k.SendSms(phone, message)
}

func (k *Kaleyra) SendSms(phone, message string) (string, error) {
    body := url.Values{
        "sender":  {k.Config.SenderID},
        "to":      {phone},
        "message": {message},
        "api_key": {k.Config.ApiKey},
    }

    client := &http.Client{Timeout: defaultTimeout}
    r, err := http.NewRequest("POST", k.APIPath, strings.NewReader(body.Encode()))
    if err != nil {
        return "", err
    }

    r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
    res, err := client.Do(r)
    if err != nil {
        return "", err
    }
    defer utilities.SafeClose(res.Body)

    // Handle response...
    return "", nil
}

func (k *Kaleyra) VerifyOTP(phone, code string) error {
    return fmt.Errorf("VerifyOTP is not supported for Kaleyra")
}