## Proposed Developer's Guide to adding a new extensibility point

This directory contains the JSONSchema's of each extensibility point. To introduce a new extensibility point, do the following:

1. Install [`schema-generate`](https://github.com/a-h/generate)
2. In `internal/hooks`, create two JSON Schema files for the inputs and outputs:  `<extensibility_point>_request.json` and `<extensibility_point>_response.json` 
3. Run `schema-generate <extensibility_point>_request.json` and `schema-generate <extensibility_point>_response.json` and place the generated outputs in  `internal/api/hook_inputs` and `internal/api/hook_outputs.go` respectively.
4. Run the following SQL statement:

``` sql
INSERT INTO auth.hook_config (id, uri, secret, extensibility_point, request_schema, response_schema, metadata)
VALUES
  ('your_uuid_value', 'your_uri_value', 'my_supa_secret', 'custom-sms-provider',
   'your_request_jsonschema',
   'your_response_jsonschema',
   '{}'::jsonb);
```

5. Edit `internal/api/transforms.go` so that it moulds the fields provided by GoTrue into a suitable request for the Hook. 
6. Update the `EncodeAndValidateInput` as well as `DecodeAndValidateResponse` function in `hooks.go` to handle the new request and response.
