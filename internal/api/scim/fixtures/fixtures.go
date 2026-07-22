// Package fixtures holds the expected SCIM wire payloads shared by tests.
package fixtures

import _ "embed"

//go:embed empty_list_response.json
var EmptyListResponse string

//go:embed filter_forbidden.json
var FilterForbidden string

//go:embed invalid_filter.json
var InvalidFilter string

//go:embed method_not_allowed.json
var MethodNotAllowed string

//go:embed method_not_allowed_without_detail.json
var MethodNotAllowedWithoutDetail string

//go:embed meta_service_provider_config.json
var MetaServiceProviderConfig string

//go:embed not_found.json
var NotFound string

//go:embed service_provider_config.json
var ServiceProviderConfig string
