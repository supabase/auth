package api

import (
	tst "testing"

	"encoding/xml"
	"net/http"
	"net/http/httptest"

	"github.com/crewjam/saml"
	"github.com/netlify/gotrue/conf"
	"github.com/stretchr/testify/require"
)

func TestSAMLMetadataWithAPI(t *tst.T) {
	config := &conf.GlobalConfiguration{}
	config.API.ExternalURL = "https://projectref.supabase.co/auth/v1/"
	config.SAML.Enabled = true
	config.SAML.PrivateKey = "MIIEpAIBAAKCAQEA7i+IEc9ziokzITndZre0fGtCP+34ID8EPR6BOgdUnPtNr/0PSB0g0gwpcgb1GYCgqEsz5tkP0hvHOBYJJi9Q0rbxzBVz6FodNUaV0gN2LGjuJ7ISvKbmNvSjjtsbMlOY42bWIn2lVVvZX3Em0YouY+TEHae6m0P46YbM+g86LdLZA+4xU+nIssAAgqxi31prJrEt7cj9jU0vP4qqGJvGy1Z+SfjKyL3ibLLn/ES3VPK9YUNNak8t+4vRruEpDx3dXFLzezz7scT6cY1w1fUhwyZuakxruAuXL7hYisitUVcQNNh6as3GPaxBYeHCxRKGd6UvXvmid2Ji+BcyRaNJywIDAQABAoIBAQCzxipkjvi9Morl5B/onHVchzRMvldON2ICo5iT7N5/Ueo0D8POATY5c7aAeyHZqs0X2RMGhQS85/x4p6EmMgZF1JEyIWsHj6SGBo2kIrq6EETYrz4XJ72Q8xrUAypG1PQLhx3OkJkOkTHDKMtM0ofrG8quO1/MOwSPdhAWGRInbI0swhLMFuudoAca7JZUOTKEwf2ZoSSfd34T3d+JlbWwc3sI0FyLVGQk4a4Nn5nA6GcQGqNUtZV/kowGTTKLmXtl9JsIHhdDrdfUbWaTxU7kH1GI8c/N3SJLFYf4VjqvO6y/rGV0gu4kkVll6lyIiJY0H7HVID8Uluq9LriG/u4xAoGBAP8m7s3MfzLiJZcN76qOKAY6ifLdHQsCxILVtBTxWRNfbBtwBeKUuXASwBPZvrlVZY8zuvRS5IsFSmsNCykC/NN/ixme2sATQ95gIr5/99cn/VCJN1WAg+vEIKTe8vQ9/xvLRlmam5aNSb+IZK2drxiNCqY0KgK7o582s0ao40DZAoGBAO76Ki0JXchpZHm+P/S0VryvzkOfOo8NPhqVwbf16ClSKs0xh5qm2qiCoL9dT/LuP9hKNKuXITe05Tlvt2jJprVKEa7ZiWChJKoYMK49xO2bhugbD3EWfZzwPlqWkXWp9J0M2734H0BZ5C/S2uJOa6OM43JdjiDlZtv0eV0K4TlDAoGACw2NtL6SGAsx46xH4JSN6U8p4KpxcqOpDZ3iUjHuUOeGUF3280zMB63YQkPhfjfT0XNFOwZIPjl5cs+61wj5GNRimzaFdWKgQwbZGnWCsABcedun2P1bOaBiZaH+1lPFNFgG8STAbrIqKrDm45p8Fk0t0+tYkou8V85Pz9TLG2kCgYBSAjNbBS3TyqcaSDl2ZjSlx8cG2aukz6ySPvYdhRvIolPh2q9oWP4MeddkFEeNXEk4li6A+/oAPemzziyonxrAd8ydrjVAncwROv/pq3Ta/VZMbIzeCBPPOXqMZ8M/F7XD91epV26SDMcLylYm9zZlB8I9yvEtRMwJi1ningswNQKBgQDCh4dFLP5Eg9ML9pHqzD8WMfKSzoMNQtDR/hcLFZyGkilB+/lyIOCJwQLNKiF41tzq9Zb0I4WYEszqcvsVX3i6WC+D+/LsmjLDI90y99SsmNrChvAGdiClS1lgX9XmvHKaaK3/EUCdueLGP5Gfwf9NBq7VZ9Pyzw5olh1xWiehpw=="

	require.NoError(t, config.ApplyDefaults())

	require.NotNil(t, config.SAML.Certificate)

	api := NewAPI(config, nil)

	// Setup request
	req := httptest.NewRequest(http.MethodGet, "http://localhost/saml/metadata", nil)

	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)
	require.Equal(t, w.Code, http.StatusOK)

	t.Logf("SAML Metadata XML: %q", w.Body.Bytes())

	metadata := saml.EntityDescriptor{}
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &metadata))

	require.Equal(t, metadata.EntityID, "https://projectref.supabase.co/auth/v1/saml/metadata")
	require.Equal(t, metadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location, "https://projectref.supabase.co/auth/v1/saml/acs")
	require.Equal(t, metadata.SPSSODescriptors[0].AssertionConsumerServices[1].Location, "https://projectref.supabase.co/auth/v1/saml/acs")
	require.Equal(t, metadata.SPSSODescriptors[0].SingleLogoutServices[0].Location, "https://projectref.supabase.co/auth/v1/saml/slo")

	require.Equal(t, metadata.SPSSODescriptors[0].KeyDescriptors[0].Use, "encryption")
	require.Equal(t, metadata.SPSSODescriptors[0].KeyDescriptors[1].Use, "signing")
}
