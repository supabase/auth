## How To Add a Hook

To introduce a new hook at an extensibility point, do the following:

1. Clone [`schema-generate`](https://github.com/J0/generate) and run `make`
2. Update the `hooks.csv` with a new entry with appropriate `request_schema` and `repsonse_schema` in JSON format.
3. Run `schema-generate <extensibility_point>_request.json` and `schema-generate <extensibility_point>_response.json` and place the generated outputs in  `internal/api/hook_inputs` and `internal/api/hook_outputs.go` respectively. See the entry for custom SMS provider as an example.
2. Copy hook information into container: `docker cp auth_hooks.csv gotrue_postgres:/tmp/auth_hooks.csv`
3. Load the hook config in: `COPY auth.hook_config FROM '/tmp/auth_hooks.csv' delimiter ',' csv header;`

This will be superceded by an endpoint in the near future.

5. Edit `internal/api/transforms.go` so that it transforms the fields provided by GoTrue into a suitable request for the Hook. 
6. Update the `EncodeAndValidateInput` as well as `DecodeAndValidateResponse` function in `hooks.go` to handle the new request and response.
7. Add an event name in `hooks.go` to describe what happens when the Hook fires

### Note On Developing Locally

If developing locally you will probably need to `http://host.docker.internal:54321/functions/v1/<function-name>` or similar to access the external port.
