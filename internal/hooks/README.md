## Overview

This directory contains the JSONSchema's of each extensibility point. To introduce a new extensibility point, please do the following:

1. File a Pull Request with the `<extensibility_point>_request.json` and `<extensibility_point>_response.json`
2. Run `schema-generate <extensibility_point>_request.json` and `schema-generate <extensibility_point>_response.json` and place the `hook_inputs` and `hook_outputs` respectively
3. Add a new sql statement into `hook.sql`
4. Update the switch statements in `hooks.go`
