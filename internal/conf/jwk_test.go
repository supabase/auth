package conf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecode(t *testing.T) {
	// array of JWKs containing 4 keys
	gotrueJwtKeys := `[{"kty":"oct","k":"lTPZqLlq8unu2q3-sx_9fZMphA5j5qzLbd4lZgp7u3k","kid":"998ec4f0-d7b2-46da-919d-fe8c67117674","use":"sig","alg":"HS256"},{"kty":"RSA","n":"0hOs9TihsN3kyTpAzvKH8Hy_E94wouGCP9dakxnPQc0Ap7G56d79m4v5OpqStbJ6QC_p2tHho-jQsx1dFMVUDofETiNqANda2b51uU41PHBxYkEn0qo7XuhvsD1jMSW_URhkugZM0jaiV6DM-1GoDI-lwlpq-MqG7buQc9GdhD6RY9wsJU4fd6Z3ehDt-RCOyCYjfNhRfDPNOI7cNXPl8TDapWBzORiu-1xt-ImsjlDn4HNb_rdU3nqKihsgGDiRtv7wizYUvN8DrLB1wWBCRPBPzjrSQ0CBOiNvo1DM11PfkFkojJiKBsMWqoCWfzSe_BmxxqnibnHXzTwGUGyJwQ","e":"AQAB","d":"BKkeVmiRsMIe02aNExz0bl3MIkQU4DuLIite-sIRCVi47copUbKVEzR7UeUllwLycqEFfzRBEpElloBdemqdez7gmGsGzOWPjM1h4KZcfhPmC2aekYOd59SrDACepjOxegUl0Jk3btdQCcw7LqJbWApUpHpQ-CZLxkjZyHIDRzs5o3EJDWpD9ks3nWXUixX64zT9Q4dLE4gofXVWR2D2qI-gxL7gSQZQb-vV_7syZkw9PzNtkc55mYtroMG1EBrmNVRuvgU2MpmDiSh7mwBhuBC4d7KAuxproel8CX1AmXmzsIDIYtoR7gdzBPrVN-g36oXsi-bubiVlxcl2XSpjWQ","p":"-jjD5vJUhFfxBjhoZ62y1OUZpxW3e1kZtpf4zAsvv2oL0wffk22y9sNahldP5GBXuwwYto9I5ojnNCuKooIDpozevpu1Ikne0sJ2CxWz7i7k7b0QrtjZA_5dzacMPmP0yHZ-XMLMGG78mk1eAHIeQo7iabaIx02WLyyjXnjNNbk","q":"1u2WB7cLtEbjwgJCp-UMz7z3OwLlqHwbyzvSwjGTEzyJE1EfLbz06KXx8L6LMvmW-nCQefLNSKTvnp2J8RIwfbIwcImAKQ6gAMm14HUjLJ5sEdRs3-VN9__Kt-sQiKiuvZ7s3sP9F6tL5wYlMxu4Ptkhs1XooaAsTmUlR89F-Ek","dp":"2enj2laC-nroAkXPzzM7wiL_kz7be0XemeGCIJlBbQ862v9JW8i2iicZyFNz1W1-Gfzv7NWeZH8n84xUATD_YuXd-tv6BLGWp7AJQ6AUAkO-xbjZNZzOaqb1JGvtwswkWwyvAbP4MPM_dFYanoLEDa0IS45XUlMkj1LtuBG2jak","dq":"YSUmKPqNacCY9Xn8EtMuxT7OKHgYwdzG20eA7ZFmvs0f0AFcrFm6AOXwwzX8yN-TZEM4qkYaj3ktbW4biUEFderyhgtASE5596E0ee24JlS82BpB07lbUnrlb9fpszs7MC4DNnUzkl00g4l9iuo-jvmph9uOuG8jV5PUE-8V2zE","qi":"Plp0-Ui827O1ciKenIikwfICuiKhx7TDIX_lblSyEbtZ21datWsr8XpQZaM5NEnN8nCZSwQ3VLTLBUai__gG3O_WKcOh5ozR10XU84WWNpvfzLUwMZ6Vm6kkGya_jw3hxNx_a6_9qZiQWOwEgkjZDouzLJ9Vq6PhZZUdhEtd2zU","kid":"462eb2fa-e31d-42e9-bb27-70d2ea832b89","use":"enc","alg":"RS256"},{"kty":"EC","x":"AglJaeHJfeea2ypQpIfKz-YVM0SDmxyosdX3hm3r_OY","y":"deWJWjUn9cW8qX3cR0SpiEserdgfarAFNifBEQqtGu8","crv":"P-256","d":"isP8oPMtBWSMAQPVJ_nKZaOwruDe7PJJbRxGtp8AEFg","kid":"c41f3f01-1b31-4795-9df6-8c4d78ff9908","use":"sig","alg":"ES256"},{"crv":"Ed25519","d":"ixHsrx2zZ44wavVzENw9TjcdlIx61ANlwFKeuWFLjms","x":"3v1LnbbCmuZtZEHm8r9gZlvUw-PQimYP2Oc587hMok8","kty":"OKP","kid":"6804dfd3-d3e0-4c1d-a8dc-dc83632001ce","use":"sig","alg":"EdDSA"}]`
	var decoder JwtKeysDecoder
	require.NoError(t, decoder.Decode(gotrueJwtKeys))
	require.Len(t, decoder, 4)

	for kid, key := range decoder {
		require.NotEmpty(t, kid)
		require.NotNil(t, key.PrivateKey)
		require.NotNil(t, key.PublicKey)
		require.NotEmpty(t, key.PublicKey.KeyUsage(), "missing use claim")
	}
}
