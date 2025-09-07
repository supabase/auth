
import (
	"os"
	"testing"
	"github.com/supabase/auth/internal/conf"
)

func TestBirdProvider_SendSms_Live(t *testing.T) {
	accessKey := os.Getenv("BIRD_ACCESS_KEY")
	workspaceID := os.Getenv("BIRD_WORKSPACE_ID")
	channelID := os.Getenv("BIRD_CHANNEL_ID")
	phone := os.Getenv("BIRD_TEST_PHONE")

	if accessKey == "" || workspaceID == "" || channelID == "" || phone == "" {
		t.Skip("Live Bird API test skipped: set BIRD_ACCESS_KEY, BIRD_WORKSPACE_ID, BIRD_CHANNEL_ID, BIRD_TEST_PHONE env vars to run.")
	}

	provider, err := NewBirdProvider(conf.BirdProviderConfiguration{
		AccessKey:   accessKey,
		WorkspaceID: workspaceID,
		ChannelID:   channelID,
	})
	if err != nil {
		t.Fatalf("failed to create BirdProvider: %v", err)
	}

	msg := "Your Supabase test code is: 123456"
	msgID, err := provider.SendSms(phone, msg)
	if err != nil {
		t.Fatalf("SendSms failed: %v", err)
	}
	if msgID == "" {
		t.Error("expected non-empty message ID from Bird API")
	}
}
