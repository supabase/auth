package sms_provider

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/supabase/gotrue/internal/conf"
)

var err_codes = map[string]int{
	"Missing mobile number": 101,
	"Missing message":       102,
	"Missing username":      104,
	"Missing password":      105,
	"Invalid username or password. 201 also appears in case the XML code triggered is incorrect.": 201,
	"Invalid mobile number":                                         202,
	"Invalid sender ID or DLT Entity Id Missing":                    203,
	"Invalid authentication key":                                    207,
	"IP is blacklisted":                                             208,
	"Default route not found":                                       209,
	"The route could not be determined. Please contact support":     210,
	"DLT Template Id Missing":                                       211,
	"The user does not have sufficient balance to send SMS":         301,
	"Expired user account":                                          302,
	"Banned user account":                                           303,
	"This route is currently unavailable":                           306,
	"The schedule time is incorrect":                                307,
	"Campaign name cannot be more than 32 characters":               308,
	"The selected group(s) does not belong to you":                  309,
	"SMS is too long. The system paused this request automatically": 310,
	"When the same SMS content is sent to the same number within 10 seconds. This is a security feature used to avoid multiple deliveries. The first SMS will be delivered and the second will be rejected. The balance will also be deducted only once.": 311,
	"Flow ID Missing or Invalid Flow":                                 400,
	"Flow Not Yet Approved":                                           401,
	"Flow is disabled":                                                403,
	"IP not whitelisted":                                              418,
	"Internal error, please contact your account manager":             506,
	"If your current route is disabled, kindly select another route":  602,
	"This sender ID is blacklisted, please use a different sender ID": 603,
	"Please enter at least one correct number to send an SMS":         604,
	"The scheduled date cannot be more than three weeks":              606,
	"Please enter the campaign name":                                  607,
	"Scheduled SMS cannot be less than the current end time":          608,
}

const (
	defaultMsg91ApiBase = "https://api.msg91.com/api/sendhttp.php?pluginsource=68"
)

type Msg91Provider struct {
	Config  *conf.Msg91ProviderConfiguration
	APIPath string
}

type Msg91Response struct {
	Data string `json:"data"`
}

// NewMsg91Provider creates a new SmsProvider for Msg91.
func NewMsg91Provider(config conf.Msg91ProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &Msg91Provider{
		Config:  &config,
		APIPath: defaultMsg91ApiBase,
	}, nil
}

func (t *Msg91Provider) SendMessage(phone string, message string, channel string) (string, error) {
	switch channel {
	case SMSProvider:
		return t.SendSms(phone, message)
	default:
		return "", fmt.Errorf("channel type %q is not supported for Msg91", channel)
	}
}

func (t *Msg91Provider) SendSms(phone string, message string) (string, error) {
	body := url.Values{
		"authkey":   {t.Config.AuthKey},
		"sender":    {t.Config.SenderId},
		"DLT_TE_ID": {t.Config.DltTemplateId},
		"mobiles":   {phone},
		"message":   {message},
		"route":     {strconv.Itoa(4)},
	}

	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", t.APIPath, strings.NewReader(body.Encode()))

	if err != nil {
		return "", err
	}

	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(r)
	if err != nil {
		return "", err
	}

	resBody, _ := io.ReadAll(res.Body)

	resBodyString := string(resBody)
	resBodyString = strings.Replace(resBodyString, ".", "", -1)

	if value, ok := err_codes[resBodyString]; ok {
		return "", fmt.Errorf("Msg91 error: %v (code: %v)", resBodyString, value)
	} else {
		return "", nil
	}

}
