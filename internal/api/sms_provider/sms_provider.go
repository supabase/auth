package sms_provider

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/supabase/gotrue/internal/conf"
)

var defaultTimeout time.Duration = time.Second * 10

const SMSProvider = "sms"
const WhatsappProvider = "whatsapp"

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
	SendMessage(phone, message, channel string) (string, error)
}

func GetSmsProvider(config conf.GlobalConfiguration) (SmsProvider, error) {
	switch name := config.Sms.Provider; name {
	case "twilio":
		return NewTwilioProvider(config.Sms.Twilio)
	case "messagebird":
		return NewMessagebirdProvider(config.Sms.Messagebird)
	case "textlocal":
		return NewTextlocalProvider(config.Sms.Textlocal)
	case "vonage":
		return NewVonageProvider(config.Sms.Vonage)
	case "gateway":
		return NewGatewayProvider(config.Sms.Gateway)
	case "twilio_verify":
		return NewTwilioVerifyProvider(config.Sms.TwilioVerify)
	default:
		return nil, fmt.Errorf("sms Provider %s could not be found", name)
	}
}

func IsValidMessageChannel(channel string, smsProvider string) bool {
	switch channel {
	case SMSProvider:
		return true
	case WhatsappProvider:
		return smsProvider == "twilio"
	default:
		return false
	}
}
