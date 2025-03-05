// filepath: internal/api/sms_provider/kaleyra_test.go
package sms_provider

import (
    "testing"
    "github.com/stretchr/testify/require"
    "github.com/supabase/auth/internal/conf"
    "gopkg.in/h2non/gock.v1"
)

func TestKaleyraSendSms(t *testing.T) {
    defer gock.Off()
    provider, err := NewKaleyraProvider(conf.KaleyraConfiguration{
        ApiKey:   "test_api_key",
        SenderID: "test_sender_id",
    })
    require.NoError(t, err)

    kaleyra, ok := provider.(*Kaleyra)
    require.Equal(t, true, ok)

    phone := "123456789"
    message := "This is the sms code: 123456"
    body := url.Values{
        "sender":  {kaleyra.Config.SenderID},
        "to":      {phone},
        "message": {message},
        "api_key": {kaleyra.Config.ApiKey},
    }

    gock.New(kaleyra.APIPath).Post("").MatchType("url").BodyString(body.Encode()).Reply(200).JSON(map[string]interface{}{
        "status": "success",
    })

    _, err = kaleyra.SendSms(phone, message)
    require.NoError(t, err)
}