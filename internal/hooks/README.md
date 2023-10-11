## How To Add a Hook

To introduce a new hook at an extensibility point, do the following:

1. Clone [`schema-generate`](https://github.com/J0/generate) and run `make`
2. In `internal/hooks`, create two separate JSON Schema files for the inputs and outputs. They should follow the format `<extensibility_point>_request.json` and `<extensibility_point>_response.json` 
3. Run `schema-generate <extensibility_point>_request.json` and `schema-generate <extensibility_point>_response.json` and place the generated outputs in  `internal/api/hook_inputs` and `internal/api/hook_outputs.go` respectively.
4. Run the following SQL statement to register your hook:
``` sql
INSERT INTO auth.hook_config (id, uri, secret, extensibility_point, request_schema, response_schema, metadata)
VALUES
  ('your_uuid_value', 'your_uri_value', ARRAY['webhook_jwt_secret'], 'custom-sms-provider',
   'your_request_jsonschema',
   'your_response_jsonschema',
   '{}'::jsonb);
```

This will be superceded by an endpoint in the near future.

5. Edit `internal/api/transforms.go` so that it transforms the fields provided by GoTrue into a suitable request for the Hook. 
6. Update the `EncodeAndValidateInput` as well as `DecodeAndValidateResponse` function in `hooks.go` to handle the new request and response.
7. Add an event name in `hooks.go` to describe what happens when the Hook fires
