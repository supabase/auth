package main

import (
	"fmt"
	"github.com/go-jose/go-jose/v3"
)

func main() {
	jwksStr := `{"keys":[{"kty":"EC","crv":"secp256k1","x":"1","y":"2"}]}`
	var jwks jose.JSONWebKeySet
	err := jwks.UnmarshalJSON([]byte(jwksStr))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Parsed:", len(jwks.Keys))
}
