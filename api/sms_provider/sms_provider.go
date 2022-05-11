package sms_provider

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/netlify/gotrue/conf"
)

var defaultTimeout time.Duration = time.Second * 10

func init() {
	timeoutStr := os.Getenv("GOTRUE_INTERNAL_HTTP_TIMEOUT")
	if timeoutStr != "" {
		if timeout, err := time.ParseDuration(timeoutStr); err != nil {
			log.Fatalf("error loading GOTRUE_INTERNAL_HTTP_TIMEOUT: %v", err.Error())
		} else if timeout != 0 {
			defaultTimeout = timeout
		}
	}
}

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
