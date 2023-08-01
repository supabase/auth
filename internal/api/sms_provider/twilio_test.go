package sms_provider

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsTwilioMessageSID(ts *testing.T) {
	cases := []struct {
		desc         string
		input        string
		isMessageSID bool
	}{
		{
			desc:         "Phone number",
			input:        "+6591234567",
			isMessageSID: false,
		},
		{
			desc:         "SID",
			input:        "VAcf79287d476f9dd47f0d6324273cf79d",
			isMessageSID: false,
		},
		{
			desc:         "Message Service SID",
			input:        "SMcf79287d476f9dd47f0d6324273cf79d",
			isMessageSID: true,
		},
	}
	for _, c := range cases {
		require.Equal(ts, c.isMessageSID, isTwilioMessageSID(c.input))
	}
}
