package api

type Web3GrantParams struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	Address   string `json:"address"`
	Chain     string `json:"chain"`
	Nonce     string `json:"nonce"` // Added nonce field
}
