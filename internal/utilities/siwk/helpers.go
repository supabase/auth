package siwk

import (
	"regexp"

	"github.com/kaspanet/go-secp256k1"
	"golang.org/x/crypto/blake2b"
)

var domainPattern = regexp.MustCompile(`^(localhost|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})(?::\d{1,5})?$`)

func IsValidDomain(domain string) bool {
	return domainPattern.MatchString(domain)
}

// @TODO: use generic network list instead of tying up with kasware values
func isValidKaspaNetwork(network string) bool {
	switch network {
	case "kaspa_mainnet", "kaspa_testnet_10", "kaspa_devnet", "kaspa_simnet":
		return true
	default:
		return false
	}
}

var PersonalMessageSigningKey = []byte("PersonalMessageSigningHash")

func MessageHash(msg []byte) [32]byte {
	h, _ := blake2b.New256((PersonalMessageSigningKey))
	h.Write(msg)

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func VerifySchnorr(msg []byte, sigBytes, pubkeyBytes []byte) (bool, error) {
	d := MessageHash(msg)

	var h secp256k1.Hash
	copy(h[:], d[:])

	sig, err := secp256k1.DeserializeSchnorrSignatureFromSlice(sigBytes)
	if err != nil {
		return false, err
	}

	pub, err := secp256k1.DeserializeSchnorrPubKey(pubkeyBytes)
	if err != nil {
		return false, err
	}

	ok := pub.SchnorrVerify(&h, sig)
	return ok, nil
}

func VerifyECDSA(msg []byte, sigBytes, pubkeyBytes []byte) (bool, error) {
	d := MessageHash(msg)

	var h secp256k1.Hash
	copy(h[:], d[:])

	sig, err := secp256k1.DeserializeECDSASignatureFromSlice(sigBytes)
	if err != nil {
		return false, err
	}

	pub, err := secp256k1.DeserializeECDSAPubKey(pubkeyBytes)
	if err != nil {
		return false, err
	}

	ok := pub.ECDSAVerify(&h, sig)
	return ok, nil
}
