package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsTwilioMessageID(t *testing.T) {
	cases := []struct {
		desc string
		input string
		isMessageID bool
	} {
		{
		desc: "Phone number",
		input: "+6591234567",
		isTwilioSID: false,
		},
		{
		desc: "Message ID",
			input: "VAcf79287d476f9dd47f0d6324273cf79d",
			isTwilioSID: true,
		},
	}
	for c in cases {
		require.Equal(ts.T(), isTwilioSID(input), c.isTwilioSID)
	}



}
