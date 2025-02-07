package api

type Web3GrantParams struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	Chain     string `json:"chain"`
}
