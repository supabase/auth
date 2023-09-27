package api

// TODO: Document how to generate the jsonschema to insert into the DB from this and/or add a make command which quickly does this
type CustomSmsHookResponse struct {
	Status   int         `json:"status"`
	Message  string      `json:"message"`
	Code     string      `json:"code"`
	MoreInfo string      `json:"more_info"`
	Data     interface{} `json:"data,omitempty"`
}
