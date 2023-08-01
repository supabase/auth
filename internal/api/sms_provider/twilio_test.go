package sms_provider

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsTwilioMessagingServiceID(ts *testing.T) {
	cases := []struct {
		desc                 string
		input                string
		isMessagingServiceID bool
	}{
		{
			desc:                 "Phone number",
			input:                "+6591234567",
			isMessagingServiceID: false,
		},
		{
			desc:                 "SID",
			input:                "VAcf79287d476f9dd47f0d6324273cf79d",
			isMessagingServiceID: false,
		},
		{
			desc:                 "Message Service SID",
			input:                "MGcf79287d476f9dd47f0d6324273cf79d",
			isMessagingServiceID: true,
		},
	}
	for _, c := range cases {
		require.Equal(ts, c.isMessagingServiceID, isTwilioMessagingServiceID(c.input))
	}
}
