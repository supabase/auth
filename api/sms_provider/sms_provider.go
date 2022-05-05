package sms_provider

import (
	"fmt"
	"time"

	"github.com/netlify/gotrue/conf"
)

const defaultTimeout = time.Second * 10

type SmsProvider interface {
	SendSms(phone, message string) error
}

func GetSmsProvider(config conf.Configuration) (SmsProvider, error) {
	switch name := config.Sms.Provider; name {
	case "twilio":
		return NewTwilioProvider(config.Sms.Twilio)
	case "messagebird":
		return NewMessagebirdProvider(config.Sms.Messagebird)
	case "textlocal":
		return NewTextlocalProvider(config.Sms.Textlocal)
	case "vonage":
		return NewVonageProvider(config.Sms.Vonage)
	default:
		return nil, fmt.Errorf("Sms Provider %s could not be found", name)
	}
}
