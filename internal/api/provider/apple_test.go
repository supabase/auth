package provider

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppleProvider_ParseUser(t *testing.T) {
	t.Run("populates all name fields when firstName and lastName present", func(t *testing.T) {
		p := AppleProvider{}
		userData := &UserProvidedData{Metadata: &Claims{}}
		err := p.ParseUser(`{"name":{"firstName":"Test","lastName":"User"},"email":"test@example.com"}`, userData)
		require.NoError(t, err)
		require.Equal(t, "Test", userData.Metadata.GivenName)
		require.Equal(t, "User", userData.Metadata.FamilyName)
		require.Equal(t, "Test User", userData.Metadata.Name)
		require.Equal(t, "Test User", userData.Metadata.FullName)
	})

	t.Run("populates given name only when lastName missing", func(t *testing.T) {
		p := AppleProvider{}
		userData := &UserProvidedData{Metadata: &Claims{}}
		err := p.ParseUser(`{"name":{"firstName":"Cher"},"email":"cher@example.com"}`, userData)
		require.NoError(t, err)
		require.Equal(t, "Cher", userData.Metadata.GivenName)
		require.Empty(t, userData.Metadata.FamilyName)
		require.Equal(t, "Cher", userData.Metadata.Name)
		require.Equal(t, "Cher", userData.Metadata.FullName)
	})

	t.Run("populates family name only when firstName missing", func(t *testing.T) {
		p := AppleProvider{}
		userData := &UserProvidedData{Metadata: &Claims{}}
		err := p.ParseUser(`{"name":{"lastName":"User"},"email":"user@example.com"}`, userData)
		require.NoError(t, err)
		require.Empty(t, userData.Metadata.GivenName)
		require.Equal(t, "User", userData.Metadata.FamilyName)
		require.Equal(t, "User", userData.Metadata.Name)
		require.Equal(t, "User", userData.Metadata.FullName)
	})

	t.Run("leaves name fields empty when name object absent", func(t *testing.T) {
		p := AppleProvider{}
		userData := &UserProvidedData{Metadata: &Claims{}}
		err := p.ParseUser(`{"email":"anonymous@example.com"}`, userData)
		require.NoError(t, err)
		require.Empty(t, userData.Metadata.GivenName)
		require.Empty(t, userData.Metadata.FamilyName)
		require.Empty(t, userData.Metadata.Name)
		require.Empty(t, userData.Metadata.FullName)
	})

	t.Run("returns error on invalid JSON", func(t *testing.T) {
		p := AppleProvider{}
		userData := &UserProvidedData{Metadata: &Claims{}}
		err := p.ParseUser(`not-json`, userData)
		require.Error(t, err)
	})
}
