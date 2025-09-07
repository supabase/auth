package bird

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"bytes"
	"github.com/supabase/auth/internal/conf"
)

type BirdProvider struct {
	Config *conf.BirdProviderConfiguration
}

type BirdResponse struct {
	ID        string `json:"id"`
	ChannelID string `json:"channelId"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
}

type BirdSendRequest struct {
	Receiver struct {
		Contacts []struct {
			IdentifierValue string `json:"identifierValue"`
			IdentifierKey   string `json:"identifierKey"`
		} `json:"contacts"`
	} `json:"receiver"`
	Body struct {
		Type string `json:"type"`
		Text struct {
			Text string `json:"text"`
		} `json:"text"`
	} `json:"body"`
}

func NewBirdProvider(config conf.BirdProviderConfiguration) (*BirdProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &BirdProvider{Config: &config}, nil
}

func (b *BirdProvider) SendSms(phone, message string) (string, error) {
	workspaceId := b.Config.WorkspaceID
	channelId := b.Config.ChannelID
	accessKey := b.Config.AccessKey

	if workspaceId == "" || channelId == "" || accessKey == "" {
		return "", fmt.Errorf("missing Bird API configuration")
	}

	url := fmt.Sprintf("https://api.bird.com/workspaces/%s/channels/%s/messages", workspaceId, channelId)

	var req BirdSendRequest
	req.Receiver.Contacts = append(req.Receiver.Contacts, struct {
		IdentifierValue string `json:"identifierValue"`
		IdentifierKey   string `json:"identifierKey"`
	}{
		IdentifierValue: phone,
		IdentifierKey:   "phonenumber",
	})
	req.Body.Type = "text"
	req.Body.Text.Text = message

	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("Authorization", "AccessKey "+accessKey)

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return "", fmt.Errorf("bird error: %v", errResp)
	}

	var birdResp BirdResponse
	if err := json.NewDecoder(resp.Body).Decode(&birdResp); err != nil {
		return "", err
	}

	if birdResp.Status != "accepted" {
		return "", fmt.Errorf("bird error: %s - %s", birdResp.Status, birdResp.Reason)
	}

	return birdResp.ID, nil
}
