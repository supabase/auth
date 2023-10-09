package api

import (
    "bytes"
    "errors"
    "encoding/json"
    "fmt"
)

// AppMetadata
type AppMetadata struct {
}

// CustomSMSRequest
type CustomSMSRequest struct {

  // version of the api
  ApiVersion string `json:"api_version"`
  UserData *UserData `json:"user"`
}

// UserData
type UserData struct {
  AppMetadata *AppMetadata `json:"app_metadata"`

  // Stores user attributes which do not impact core functionality
  ConfirmedAt string `json:"confirmed_at"`

  // Store when a phone has been confirmed. Null if unconfirmed.
  Phone string `json:"phone"`
}

func (strct *CustomSMSRequest) MarshalJSON() ([]byte, error) {
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
    // "UserData" field is required
    if strct.UserData == nil {
        return nil, errors.New("user is a required field")
    }
    // Marshal the "user" field
    if comma {
        buf.WriteString(",")
    }
    buf.WriteString("\"user\": ")
	if tmp, err := json.Marshal(strct.UserData); err != nil {
		return nil, err
 	} else {
 		buf.Write(tmp)
	}
	comma = true

	buf.WriteString("}")
	rv := buf.Bytes()
	return rv, nil
}

func (strct *CustomSMSRequest) UnmarshalJSON(b []byte) error {
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
        case "user":
            if err := json.Unmarshal([]byte(v), &strct.UserData); err != nil {
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

func (strct *UserData) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0))
	buf.WriteString("{")
    comma := false
    // "AppMetadata" field is required
    if strct.AppMetadata == nil {
        return nil, errors.New("app_metadata is a required field")
    }
    // Marshal the "app_metadata" field
    if comma {
        buf.WriteString(",")
    }
    buf.WriteString("\"app_metadata\": ")
	if tmp, err := json.Marshal(strct.AppMetadata); err != nil {
		return nil, err
 	} else {
 		buf.Write(tmp)
	}
	comma = true
    // "ConfirmedAt" field is required
    // only required object types supported for marshal checking (for now)
    // Marshal the "confirmed_at" field
    if comma {
        buf.WriteString(",")
    }
    buf.WriteString("\"confirmed_at\": ")
	if tmp, err := json.Marshal(strct.ConfirmedAt); err != nil {
		return nil, err
 	} else {
 		buf.Write(tmp)
	}
	comma = true
    // "Phone" field is required
    // only required object types supported for marshal checking (for now)
    // Marshal the "phone" field
    if comma {
        buf.WriteString(",")
    }
    buf.WriteString("\"phone\": ")
	if tmp, err := json.Marshal(strct.Phone); err != nil {
		return nil, err
 	} else {
 		buf.Write(tmp)
	}
	comma = true

	buf.WriteString("}")
	rv := buf.Bytes()
	return rv, nil
}

func (strct *UserData) UnmarshalJSON(b []byte) error {
    app_metadataReceived := false
    confirmed_atReceived := false
    phoneReceived := false
    var jsonMap map[string]json.RawMessage
    if err := json.Unmarshal(b, &jsonMap); err != nil {
        return err
    }
    // parse all the defined properties
    for k, v := range jsonMap {
        switch k {
        case "app_metadata":
            if err := json.Unmarshal([]byte(v), &strct.AppMetadata); err != nil {
                return err
             }
            app_metadataReceived = true
        case "confirmed_at":
            if err := json.Unmarshal([]byte(v), &strct.ConfirmedAt); err != nil {
                return err
             }
            confirmed_atReceived = true
        case "phone":
            if err := json.Unmarshal([]byte(v), &strct.Phone); err != nil {
                return err
             }
            phoneReceived = true
        }
    }
    // check if app_metadata (a required property) was received
    if !app_metadataReceived {
        return errors.New("\"app_metadata\" is required but was not present")
    }
    // check if confirmed_at (a required property) was received
    if !confirmed_atReceived {
        return errors.New("\"confirmed_at\" is required but was not present")
    }
    // check if phone (a required property) was received
    if !phoneReceived {
        return errors.New("\"phone\" is required but was not present")
    }
    return nil
}
