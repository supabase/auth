package api

import (
    "encoding/json"
    "fmt"
    "bytes"
    "errors"
)

// CustomSMSHookResponse Custom SMS provider Request
type CustomSMSHookResponse struct {

  // API Version
  ApiVersion string `json:"api_version"`

  // Internal Error code reference
  Code string `json:"code,omitempty"`

  // Response data returned by the hook
  Data interface{} `json:"data,omitempty"`

  // Short Description of the error message
  Message string `json:"message,omitempty"`

  // Detailed elaboration and possibly link to an error page in the future.
  MoreInfo string `json:"more_info,omitempty"`

  // HTTP Status code (e.g. 400)
  Status float64 `json:"status,omitempty"`

  // User information
  User *User `json:"user"`
}

// User User information
type User struct {
}

func (strct *CustomSMSHookResponse) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0))
	buf.WriteString("{")
    comma := false
    // "ApiVersion" field is required
    // only required object types supported for marshal checking (for now)
    // Marshal the "api_version" field
    if comma {
        buf.WriteString(",")
    }
    buf.WriteString("\"api_version\": ")
	if tmp, err := json.Marshal(strct.ApiVersion); err != nil {
		return nil, err
 	} else {
 		buf.Write(tmp)
	}
	comma = true
    // Marshal the "code" field
    if comma {
        buf.WriteString(",")
    }
    buf.WriteString("\"code\": ")
	if tmp, err := json.Marshal(strct.Code); err != nil {
		return nil, err
 	} else {
 		buf.Write(tmp)
	}
	comma = true
    // Marshal the "data" field
    if comma {
        buf.WriteString(",")
    }
    buf.WriteString("\"data\": ")
	if tmp, err := json.Marshal(strct.Data); err != nil {
		return nil, err
 	} else {
 		buf.Write(tmp)
	}
	comma = true
    // Marshal the "message" field
    if comma {
        buf.WriteString(",")
    }
    buf.WriteString("\"message\": ")
	if tmp, err := json.Marshal(strct.Message); err != nil {
		return nil, err
 	} else {
 		buf.Write(tmp)
	}
	comma = true
    // Marshal the "more_info" field
    if comma {
        buf.WriteString(",")
    }
    buf.WriteString("\"more_info\": ")
	if tmp, err := json.Marshal(strct.MoreInfo); err != nil {
		return nil, err
 	} else {
 		buf.Write(tmp)
	}
	comma = true
    // Marshal the "status" field
    if comma {
        buf.WriteString(",")
    }
    buf.WriteString("\"status\": ")
	if tmp, err := json.Marshal(strct.Status); err != nil {
		return nil, err
 	} else {
 		buf.Write(tmp)
	}
	comma = true
    // "User" field is required
    if strct.User == nil {
        return nil, errors.New("user is a required field")
    }
    // Marshal the "user" field
    if comma {
        buf.WriteString(",")
    }
    buf.WriteString("\"user\": ")
	if tmp, err := json.Marshal(strct.User); err != nil {
		return nil, err
 	} else {
 		buf.Write(tmp)
	}
	comma = true

	buf.WriteString("}")
	rv := buf.Bytes()
	return rv, nil
}

func (strct *CustomSMSHookResponse) UnmarshalJSON(b []byte) error {
    api_versionReceived := false
    userReceived := false
    var jsonMap map[string]json.RawMessage
    if err := json.Unmarshal(b, &jsonMap); err != nil {
        return err
    }
    // parse all the defined properties
    for k, v := range jsonMap {
        switch k {
        case "api_version":
            if err := json.Unmarshal([]byte(v), &strct.ApiVersion); err != nil {
                return err
             }
            api_versionReceived = true
        case "code":
            if err := json.Unmarshal([]byte(v), &strct.Code); err != nil {
                return err
             }
        case "data":
            if err := json.Unmarshal([]byte(v), &strct.Data); err != nil {
                return err
             }
        case "message":
            if err := json.Unmarshal([]byte(v), &strct.Message); err != nil {
                return err
             }
        case "more_info":
            if err := json.Unmarshal([]byte(v), &strct.MoreInfo); err != nil {
                return err
             }
        case "status":
            if err := json.Unmarshal([]byte(v), &strct.Status); err != nil {
                return err
             }
        case "user":
            if err := json.Unmarshal([]byte(v), &strct.User); err != nil {
                return err
             }
            userReceived = true
        default:
            return fmt.Errorf("additional property not allowed: \"" + k + "\"")
        }
    }
    // check if api_version (a required property) was received
    if !api_versionReceived {
        return errors.New("\"api_version\" is required but was not present")
    }
    // check if user (a required property) was received
    if !userReceived {
        return errors.New("\"user\" is required but was not present")
    }
    return nil
}
