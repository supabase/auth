#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE_URL="${GOTRUE_URL:-http://localhost:9999}"
SECRET="${GOTRUE_JWT_SECRET:-$(sed -n 's/^GOTRUE_JWT_SECRET=//p' "$ROOT/.env" 2>/dev/null | tr -d '"' || true)}"
RUN="$(date +%s)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

[ -n "$SECRET" ] || { echo "set GOTRUE_JWT_SECRET or add it to $ROOT/.env" >&2; exit 1; }

b64url() {
  openssl base64 -e -A | tr '+/' '-_' | tr -d '='
}

admin_jwt() {
  local now header payload sig
  now="$(date +%s)"
  header="$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64url)"
  payload="$(printf '{"role":"service_role","iat":%s,"exp":%s}' "$now" "$((now + 600))" | b64url)"
  sig="$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64url)"
  printf '%s.%s.%s' "$header" "$payload" "$sig"
}

ADMIN_TOKEN="$(admin_jwt)"

call() {
  local expected="$1" method="$2" url="$3" token="$4" body="${5:-}" show="${6:-.}" status
  local args=(-sS -X "$method" -o "$TMP/body" -D "$TMP/headers" -w '%{http_code}' -H "Authorization: Bearer $token")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/scim+json' --data "$body")
  printf '\n\033[1m%s %s\033[0m\n' "$method" "${url#"$BASE_URL"}"
  status="$(curl "${args[@]}" "$url")"
  [ -s "$TMP/body" ] && { jq -C "$show" < "$TMP/body" || cat "$TMP/body"; }
  if [ "$status" != "$expected" ]; then
    printf '\033[1;31mHTTP %s, expected %s\033[0m\n' "$status" "$expected"
    exit 1
  fi
  printf '\033[1;32mHTTP %s\033[0m\n' "$status"
  if [ -n "${PAUSE:-}" ]; then read -r -p "press enter for the next step "; fi
}

field() {
  jq -r "$1" < "$TMP/body"
}

header() {
  sed -n "s/^$1: //Ip" "$TMP/headers" | tr -d '\r'
}

fail() {
  printf '\033[1;31m%s\033[0m\n' "$1"
  exit 1
}

expect() {
  jq -e "$1" < "$TMP/body" > /dev/null || fail "expected $1"
  printf '\033[32m  ok %s\033[0m\n' "$1"
}

expect_header() {
  [[ "$(header "$1")" =~ $2 ]] || fail "expected header $1: $2, got $(header "$1")"
  printf '\033[32m  ok %s: %s\033[0m\n' "$1" "$2"
}

ids() {
  jq -c '[.Resources[].id]' < "$TMP/body"
}

uri() {
  jq -rn --arg v "$1" '$v | @uri'
}

section() {
  printf '\n\033[1;34m== %s ==\033[0m\n' "$1"
}

user() {
  jq -n --arg u "$1" --arg g "$2" --arg f "$3" '{
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    userName: $u,
    name: {givenName: $g, familyName: $f},
    emails: [{value: $u, primary: true}],
    active: true
  }'
}

patch() {
  jq -n --argjson ops "[$1]" '{schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: $ops}'
}

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/key.pem" -subj "/CN=scim-demo.example" -days 1 -outform DER -out "$TMP/cert.der" 2>/dev/null
CERT="$(openssl base64 -e -A < "$TMP/cert.der")"
METADATA="<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://scim-demo-$RUN.example/entityid\"><md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>$CERT</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://scim-demo-$RUN.example/sso\"/></md:IDPSSODescriptor></md:EntityDescriptor>"

section "Admin: provider, SCIM and tokens"
call 201 POST "$BASE_URL/admin/sso/providers" "$ADMIN_TOKEN" "$(jq -n --arg xml "$METADATA" '{type: "saml", metadata_xml: $xml}')"
PROVIDER="$(field .id)"
ADMIN="$BASE_URL/admin/sso/providers/$PROVIDER"

call 200 POST "$ADMIN/scim" "$ADMIN_TOKEN"
call 201 POST "$ADMIN/scim/tokens" "$ADMIN_TOKEN" '{}'
SCIM_TOKEN="$(field .token)"
call 201 POST "$ADMIN/scim/tokens" "$ADMIN_TOKEN" '{}'
SPARE_TOKEN="$(field .token)"
SPARE_ID="$(field .id)"
call 200 GET "$ADMIN/scim/tokens" "$ADMIN_TOKEN"
call 200 DELETE "$ADMIN/scim/tokens/$SPARE_ID" "$ADMIN_TOKEN"
call 200 GET "$ADMIN/scim" "$ADMIN_TOKEN"
SCIM="$BASE_URL/scim/v2"
call 401 GET "$SCIM/Users" "$SPARE_TOKEN"

section "Discovery"
call 200 GET "$SCIM/ServiceProviderConfig" "$SCIM_TOKEN"
call 200 GET "$SCIM/ResourceTypes" "$SCIM_TOKEN" "" '[.Resources[] | {name, endpoint, schema}]'
call 200 GET "$SCIM/Schemas" "$SCIM_TOKEN" "" '[.Resources[].id]'

ENT="urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
X509="MIIDQzCCAqygAwIBAgICEAAwDQYJKoZIhvcNAQEFBQAwTjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFDASBgNVBAoMC2V4YW1wbGUuY29tMRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0xMTEwMjIwNjI0MzFaFw0xMjEwMDQwNjI0MzFaMH8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRQwEgYDVQQKDAtleGFtcGxlLmNvbTEhMB8GA1UEAwwYTXMuIEJhcmJhcmEgSiBKZW5zZW4gSUlJMSIwIAYJKoZIhvcNAQkBFhNiamVuc2VuQGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Kr+Dcds/JQ5GwejJFcBIP682X3xpjis56AK02bc1FLgzdLI8auoR+cC9/Vrh5t66HkQIOdA4unHh0AaZ4xL5PhVbXIPMB5vAPKpzz5iPSi8xO8SL7I7SDhcBVJhqVqr3HgllEG6UClDdHO7nkLuwXq8HcISKkbT5WFTVfFZzidPl8HZ7DhXkZIRtJwBweq4bvm3hM1Os7UQH05ZS6cVDgweKNwdLLrT51ikSQG3DYrl+ft781UQRIqxgwqCfXEuDiinPh0kkvIi5jivVu1Z9QiwlYEdRbLJ4zJQBmDrSGTMYn4lRc2HgHO4DqB/bnMVorHB0CC6AV1QoFK4GPe1LwIDAQABo3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU8pD0U0vsZIsaA16lL8En8bx0F/gwHwYDVR0jBBgwFoAUdGeKitcaF7gnzsNwDx708kqaVt0wDQYJKoZIhvcNAQEFBQADgYEAA81SsFnOdYJtNg5Tcq+/ByEDrBgnusx0jloUhByPMEVkoMZ3J7j1ZgI8rAbOkNngX8+pKfTiDz1RC4+dx8oU6Za+4NJXUjlL5CvV6BEYb1+QAEJwitTVvxB/A67g42/vzgAtoRUeDov1+GFiBZ+GNF/cAYKcMtGcrs2i97ZkJMo="
JOHN="jsmith@example.com"
MANDY="mpepperidge@example.com"
BARBARA="bjensen@example.com"

barbara() {
  jq -n --arg manager "$1" --arg cert "$X509" --arg ent "$ENT" '{
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User", $ent],
    externalId: "701984",
    userName: "bjensen@example.com",
    name: {
      formatted: "Ms. Barbara J Jensen, III",
      familyName: "Jensen",
      givenName: "Barbara",
      middleName: "Jane",
      honorificPrefix: "Ms.",
      honorificSuffix: "III"
    },
    displayName: "Babs Jensen",
    nickName: "Babs",
    profileUrl: "https://login.example.com/bjensen",
    emails: [
      {value: "bjensen@example.com", type: "work", primary: true},
      {value: "babs@jensen.org", type: "home"}
    ],
    addresses: [
      {
        type: "work",
        streetAddress: "100 Universal City Plaza",
        locality: "Hollywood",
        region: "CA",
        postalCode: "91608",
        country: "USA",
        formatted: "100 Universal City Plaza\nHollywood, CA 91608 USA",
        primary: true
      },
      {
        type: "home",
        streetAddress: "456 Hollywood Blvd",
        locality: "Hollywood",
        region: "CA",
        postalCode: "91608",
        country: "USA",
        formatted: "456 Hollywood Blvd\nHollywood, CA 91608 USA"
      }
    ],
    phoneNumbers: [
      {value: "555-555-5555", type: "work"},
      {value: "555-555-4444", type: "mobile"}
    ],
    ims: [{value: "someaimhandle", type: "aim"}],
    photos: [
      {value: "https://photos.example.com/profilephoto/72930000000Ccne/F", type: "photo"},
      {value: "https://photos.example.com/profilephoto/72930000000Ccne/T", type: "thumbnail"}
    ],
    userType: "Employee",
    title: "Tour Guide",
    preferredLanguage: "en-US",
    locale: "en-US",
    timezone: "America/Los_Angeles",
    active: true,
    password: "t1meMa$heen",
    x509Certificates: [{value: $cert}],
    ($ent): {
      employeeNumber: "701984",
      costCenter: "4130",
      organization: "Universal Studios",
      division: "Theme Park",
      department: "Tour Operations",
      manager: {value: $manager, "$ref": ("../Users/" + $manager), displayName: "John Smith"}
    }
  }'
}

group() {
  jq -n --arg n "$1" --argjson members "${2:-[]}" '{
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    displayName: $n,
    members: $members
  }'
}

member() {
  printf '{"value": "%s"}' "$1"
}

section "Users"
call 201 POST "$SCIM/Users" "$SCIM_TOKEN" "$(user "$JOHN" John Smith)"
JOHN_ID="$(field .id)"
call 201 POST "$SCIM/Users" "$SCIM_TOKEN" "$(user "$MANDY" Mandy Pepperidge)"
MANDY_ID="$(field .id)"
call 200 GET "$SCIM/Users?filter=$(uri "userName eq \"$JOHN\"")" "$SCIM_TOKEN"
call 200 GET "$SCIM/Users?sortBy=userName&sortOrder=descending" "$SCIM_TOKEN"
call 200 GET "$SCIM/Users?sortBy=userName&startIndex=2&count=1" "$SCIM_TOKEN"
call 200 PATCH "$SCIM/Users/$MANDY_ID" "$SCIM_TOKEN" "$(patch '{"op": "replace", "path": "name.familyName", "value": "Pepperidge-Jones"}')"
call 200 PUT "$SCIM/Users/$MANDY_ID" "$SCIM_TOKEN" "$(user "$MANDY" Mandy Pepperidge)"
call 200 PATCH "$SCIM/Users/$MANDY_ID" "$SCIM_TOKEN" "$(patch '{"op": "replace", "path": "active", "value": false}')"
call 200 PATCH "$SCIM/Users/$MANDY_ID" "$SCIM_TOKEN" "$(patch '{"op": "replace", "path": "active", "value": true}')"

section "RFC 7644 s3.3: create with the RFC 7643 figure 4 and 5 user"
call 201 POST "$SCIM/Users" "$SCIM_TOKEN" "$(barbara "$JOHN_ID")"
BARBARA_ID="$(field .id)"
expect_header Content-Type '^application/scim\+json'
expect_header Location "/scim/v2/Users/$BARBARA_ID$"
expect '.meta.resourceType == "User" and .meta.location == "'"$(header Location)"'"'
expect '.meta.created and .meta.lastModified and (.meta.version | startswith("W/"))'
expect 'has("password") | not'
expect '.schemas | index("'"$ENT"'")'
expect '.externalId == "701984" and .userName == "bjensen@example.com" and .displayName == "Babs Jensen" and .nickName == "Babs"'
expect '.name == {"formatted": "Ms. Barbara J Jensen, III", "familyName": "Jensen", "givenName": "Barbara", "middleName": "Jane", "honorificPrefix": "Ms.", "honorificSuffix": "III"}'
expect '.profileUrl == "https://login.example.com/bjensen"'
expect '.userType == "Employee" and .title == "Tour Guide" and .preferredLanguage == "en-US" and .locale == "en-US" and .timezone == "America/Los_Angeles" and .active == true'
expect '(.emails | length) == 2 and (.addresses | length) == 2 and (.phoneNumbers | length) == 2 and (.photos | length) == 2'
expect '.ims == [{"value": "someaimhandle", "type": "aim"}]'
expect '(.x509Certificates | length) == 1'
expect '.["'"$ENT"'"] | .employeeNumber == "701984" and .costCenter == "4130" and .organization == "Universal Studios" and .division == "Theme Park" and .department == "Tour Operations"'
expect '.["'"$ENT"'"].manager.value == "'"$JOHN_ID"'"'
call 409 POST "$SCIM/Users" "$SCIM_TOKEN" "$(user "$(tr '[:lower:]' '[:upper:]' <<< "$BARBARA")" Barbara Again)"
expect '.schemas == ["urn:ietf:params:scim:api:messages:2.0:Error"] and .scimType == "uniqueness" and .status == "409"'
call 400 POST "$SCIM/Users" "$SCIM_TOKEN" '{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"]}'
expect '.status == "400"'

section "Groups"
call 201 POST "$SCIM/Groups" "$SCIM_TOKEN" "$(group "Tour Guides" "[$(member "$BARBARA_ID"), $(member "$MANDY_ID")]")"
TOUR_GUIDES="$(field .id)"
call 204 PATCH "$SCIM/Groups/$TOUR_GUIDES" "$SCIM_TOKEN" "$(patch "{\"op\": \"add\", \"path\": \"members\", \"value\": [$(member "$JOHN_ID")]}")"
call 204 PATCH "$SCIM/Groups/$TOUR_GUIDES" "$SCIM_TOKEN" "$(patch "{\"op\": \"remove\", \"path\": \"members[value eq \\\"$JOHN_ID\\\"]\"}")"
call 200 GET "$SCIM/Groups/$TOUR_GUIDES" "$SCIM_TOKEN"
expect '([.members[].value] | sort) == (["'"$BARBARA_ID"'", "'"$MANDY_ID"'"] | sort)'

section "Errors"
call 409 POST "$SCIM/Users" "$SCIM_TOKEN" "$(user "$JOHN" John Smith)"
call 400 GET "$SCIM/Users?filter=$(uri 'userName eq')" "$SCIM_TOKEN"
call 400 GET "$SCIM/Users?sortBy=nope" "$SCIM_TOKEN"
call 404 GET "$SCIM/Users/00000000-0000-0000-0000-000000000000" "$SCIM_TOKEN"
call 401 GET "$SCIM/Users" "not-a-token"

section "RFC 7644 s4: discovery"
call 200 GET "$SCIM/ServiceProviderConfig" "$SCIM_TOKEN"
expect_header Content-Type '^application/scim\+json'
expect '.schemas == ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"]'
expect '.patch.supported and .filter.supported and .sort.supported and .etag.supported'
expect '.filter.maxResults == 100'
expect '(.bulk.supported | not) and (.changePassword.supported | not)'
expect '.authenticationSchemes | length > 0'
call 200 GET "$SCIM/ResourceTypes/User" "$SCIM_TOKEN"
expect '.endpoint == "/Users" and .schema == "urn:ietf:params:scim:schemas:core:2.0:User"'
expect '.schemaExtensions == [{"schema": "'"$ENT"'", "required": false}]'
call 200 GET "$SCIM/ResourceTypes/Group" "$SCIM_TOKEN"
expect '.endpoint == "/Groups"'
call 200 GET "$SCIM/Schemas/urn:ietf:params:scim:schemas:core:2.0:User" "$SCIM_TOKEN"
expect '[.attributes[] | select(.name == "userName")][0] | .required and .uniqueness == "server" and (.caseExact | not)'
expect '[.attributes[] | select(.name == "password")][0] | .returned == "never" and .mutability == "writeOnly"'
call 200 GET "$SCIM/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group" "$SCIM_TOKEN"
call 200 GET "$SCIM/Schemas/$ENT" "$SCIM_TOKEN"
call 404 GET "$SCIM/Schemas/urn:example:nope" "$SCIM_TOKEN"
call 501 POST "$SCIM/Bulk" "$SCIM_TOKEN" '{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": []}'
call 501 GET "$SCIM/Me" "$SCIM_TOKEN"

section "RFC 7644 s3.4.1: read with attributes and excludedAttributes"
call 200 GET "$SCIM/Users/$BARBARA_ID?attributes=userName" "$SCIM_TOKEN"
expect 'keys - ["id", "schemas", "userName", "meta"] == []'
expect '.userName == "'"$BARBARA"'"'
call 200 GET "$SCIM/Users/$BARBARA_ID?excludedAttributes=emails,name" "$SCIM_TOKEN"
expect '(has("emails") or has("name")) | not'
expect '.id and .userName'
call 200 GET "$SCIM/Users/$BARBARA_ID?attributes=$ENT:employeeNumber" "$SCIM_TOKEN"
expect '.["'"$ENT"'"] == {"employeeNumber": "701984"}'

section "RFC 7644 s3.4.2: list response and paging"
call 200 GET "$SCIM/Users?count=0" "$SCIM_TOKEN"
expect '.schemas == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]'
expect '.totalResults == 3 and .itemsPerPage == 0 and ((.Resources // []) | length) == 0'
TOTAL="$(field .totalResults)"
call 200 GET "$SCIM/Users?startIndex=1&count=2" "$SCIM_TOKEN"
expect '.startIndex == 1 and .itemsPerPage == 2 and (.Resources | length) == 2'
call 200 GET "$SCIM/Users?startIndex=$((TOTAL + 10))" "$SCIM_TOKEN"
expect '.totalResults == '"$TOTAL"' and ((.Resources // []) | length) == 0'
call 200 GET "$SCIM/Users?startIndex=0&count=1" "$SCIM_TOKEN"
expect '.startIndex == 1'
call 200 GET "$SCIM/Users?count=1000" "$SCIM_TOKEN"
expect '.itemsPerPage <= 100'

section "RFC 7644 s3.4.2.2: filters"
filter() {
  call 200 GET "$SCIM/Users?$(jq -rn --arg f "$1" '"filter=" + ($f | @uri)')" "$SCIM_TOKEN" "" '{totalResults, ids: [.Resources[]?.userName]}'
  expect "$2"
}
filter "userName eq \"$BARBARA\"" '.totalResults == 1'
filter "USERNAME eq \"$(tr '[:lower:]' '[:upper:]' <<< "$BARBARA")\"" '.totalResults == 1'
filter "userName ne \"$BARBARA\"" '[.Resources[].id] | index("'"$BARBARA_ID"'") | not'
filter 'userName co "jensen"' '.totalResults == 1'
filter 'userName sw "bjensen"' '.totalResults == 1'
filter 'userName ew "@example.com"' '.totalResults == 3'
filter 'userName gt "bjensen" and userName lt "bjensen~"' '.totalResults == 1'
filter 'externalId eq "701984"' '.totalResults == 1'
filter "title pr and userName eq \"$BARBARA\"" '.totalResults == 1'
filter "not (title pr) and userName eq \"$BARBARA\"" '.totalResults == 0'
filter 'emails[type eq "work" and value co "bjensen"] and userName sw "bjensen"' '.totalResults == 1'
filter 'emails.value eq "babs@jensen.org"' '.totalResults == 1'
filter 'name.familyName eq "jensen" and userName ew "@example.com"' '.totalResults == 1'
filter "$ENT:employeeNumber eq \"701984\" and userName ew \"@example.com\"" '.totalResults == 1'
filter 'active eq true and userName ew "@example.com"' '.totalResults == 3'
filter "meta.lastModified gt \"2000-01-01T00:00:00Z\" and userName eq \"$BARBARA\"" '.totalResults == 1'
filter "(userName eq \"$BARBARA\" or userName eq \"$JOHN\") and active eq true" '.totalResults == 2'
call 400 GET "$SCIM/Users?$(jq -rn '"filter=" + ("userName xx \"a\"" | @uri)')" "$SCIM_TOKEN"
expect '.scimType == "invalidFilter"'
call 403 GET "$SCIM/Users?$(jq -rn '"filter=" + ("password eq \"x\"" | @uri)')" "$SCIM_TOKEN"
expect '.scimType == "sensitive"'

section "RFC 7644 s3.4.2.3: sorting"
call 200 GET "$SCIM/Users?$(jq -rn '"filter=" + ("userName ew \"@example.com\"" | @uri)')&sortBy=userName" "$SCIM_TOKEN" "" '[.Resources[].userName]'
expect '[.Resources[].userName] | . == sort'
call 200 GET "$SCIM/Users?$(jq -rn '"filter=" + ("userName ew \"@example.com\"" | @uri)')&sortBy=userName&sortOrder=descending" "$SCIM_TOKEN" "" '[.Resources[].userName]'
expect '[.Resources[].userName] | . == (sort | reverse)'
call 400 GET "$SCIM/Users?sortBy=userName&sortOrder=sideways" "$SCIM_TOKEN"

section "RFC 7644 s3.4.3: POST .search"
call 200 POST "$SCIM/Users/.search" "$SCIM_TOKEN" "$(jq -n --arg f "userName eq \"$BARBARA\"" '{
  schemas: ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
  filter: $f, attributes: ["userName"], startIndex: 1, count: 10
}')"
expect '.totalResults == 1 and (.Resources[0] | keys - ["id", "schemas", "userName", "meta"] == [])'

section "RFC 7644 s3.5.1: PUT"
call 200 PUT "$SCIM/Users/$BARBARA_ID" "$SCIM_TOKEN" "$(jq -n --arg u "$BARBARA" '{
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
  userName: $u, name: {givenName: "Babs"}, active: true
}')"
expect '.name == {"givenName": "Babs"} and (has("title") | not) and (has("emails") | not)'
call 404 PUT "$SCIM/Users/00000000-0000-0000-0000-000000000000" "$SCIM_TOKEN" "$(user "nobody@example.com" No Body)"

section "RFC 7644 s3.5.2: PATCH"
call 200 PATCH "$SCIM/Users/$BARBARA_ID" "$SCIM_TOKEN" "$(patch '{"op": "Add", "value": {"title": "Lead", "emails": [{"value": "work@example.com", "type": "work"}]}}')"
expect '.title == "Lead" and (.emails | length) == 1'
call 200 PATCH "$SCIM/Users/$BARBARA_ID" "$SCIM_TOKEN" "$(patch '{"op": "Replace", "path": "emails[type eq \"work\"].value", "value": "lead@example.com"}')"
expect '.emails[0].value == "lead@example.com"'
call 200 PATCH "$SCIM/Users/$BARBARA_ID" "$SCIM_TOKEN" "$(patch '{"op": "remove", "path": "title"}')"
expect 'has("title") | not'
call 200 PATCH "$SCIM/Users/$BARBARA_ID?attributes=active" "$SCIM_TOKEN" "$(patch '{"op": "replace", "value": {"active": false}}')"
expect '.active == false and (has("userName") | not)'
call 200 PATCH "$SCIM/Users/$BARBARA_ID" "$SCIM_TOKEN" "$(patch "{\"op\": \"replace\", \"path\": \"$ENT:manager.value\", \"value\": \"$JOHN_ID\"}")"
expect '.["'"$ENT"'"].manager.value == "'"$JOHN_ID"'"'
call 400 PATCH "$SCIM/Users/$BARBARA_ID" "$SCIM_TOKEN" "$(patch '{"op": "replace", "path": "id", "value": "x"}')"
expect '.scimType == "mutability"'
call 400 PATCH "$SCIM/Users/$BARBARA_ID" "$SCIM_TOKEN" "$(patch '{"op": "explode", "path": "title", "value": "x"}')"
call 400 PATCH "$SCIM/Users/$BARBARA_ID" "$SCIM_TOKEN" '{"Operations": [{"op": "remove", "path": "title"}]}'

section "Groups: members, nesting and user groups"
call 201 POST "$SCIM/Groups" "$SCIM_TOKEN" "$(group "US Employees")"
US_EMPLOYEES="$(field .id)"
call 201 POST "$SCIM/Groups" "$SCIM_TOKEN" "$(group "Employees")"
EMPLOYEES="$(field .id)"
expect_header Location "/scim/v2/Groups/$EMPLOYEES$"
call 204 PATCH "$SCIM/Groups/$EMPLOYEES" "$SCIM_TOKEN" "$(patch "{\"op\": \"add\", \"path\": \"members\", \"value\": [$(member "$US_EMPLOYEES"), $(member "$BARBARA_ID")]}")"
expect_header Content-Location "/scim/v2/Groups/$EMPLOYEES$"
call 200 GET "$SCIM/Groups/$EMPLOYEES" "$SCIM_TOKEN"
expect '([.members[].value] | sort) == (["'"$US_EMPLOYEES"'", "'"$BARBARA_ID"'"] | sort)'
call 200 GET "$SCIM/Users/$BARBARA_ID?attributes=groups" "$SCIM_TOKEN"
expect '([.groups[].value] | sort) == (["'"$TOUR_GUIDES"'", "'"$EMPLOYEES"'"] | sort)'
call 200 GET "$SCIM/Groups?$(jq -rn --arg f "members.value eq \"$US_EMPLOYEES\"" '"filter=" + ($f | @uri)')&excludedAttributes=members" "$SCIM_TOKEN"
expect '[.Resources[].id] == ["'"$EMPLOYEES"'"] and (.Resources[0] | has("members") | not)'
call 200 GET "$SCIM/Groups?$(jq -rn '"filter=" + ("displayName eq \"employees\"" | @uri)')" "$SCIM_TOKEN"
expect '.totalResults == 1'
call 400 PATCH "$SCIM/Groups/$TOUR_GUIDES" "$SCIM_TOKEN" "$(patch "{\"op\": \"add\", \"path\": \"members\", \"value\": [$(member "$TOUR_GUIDES")]}")"
call 400 PATCH "$SCIM/Groups/$EMPLOYEES" "$SCIM_TOKEN" "$(patch '{"op": "add", "path": "members", "value": [{"value": "00000000-0000-0000-0000-000000000000"}]}')"
call 200 PATCH "$SCIM/Groups/$EMPLOYEES" "$SCIM_TOKEN" "$(patch "{\"op\": \"replace\", \"value\": {\"id\": \"$EMPLOYEES\", \"displayName\": \"Employees\"}}")"
expect '(.members | length) == 2'
call 204 PATCH "$SCIM/Groups/$EMPLOYEES" "$SCIM_TOKEN" "$(patch "{\"op\": \"remove\", \"path\": \"members[value eq \\\"$BARBARA_ID\\\"]\"}")"
call 204 DELETE "$SCIM/Groups/$EMPLOYEES" "$SCIM_TOKEN"
call 200 GET "$SCIM/Users/$BARBARA_ID?attributes=groups" "$SCIM_TOKEN"
expect '[.groups[].value] == ["'"$TOUR_GUIDES"'"]'

section "RFC 7644 s3.12: errors"
call 404 GET "$SCIM/Groups/not-a-uuid" "$SCIM_TOKEN"
expect '.schemas == ["urn:ietf:params:scim:api:messages:2.0:Error"] and .status == "404"'
call 405 PUT "$SCIM/Users" "$SCIM_TOKEN" '{}'
call 400 POST "$SCIM/Users" "$SCIM_TOKEN" '{not json'
{ printf '{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "big@example.com", "title": "'; head -c 1100000 /dev/zero | tr '\0' a; printf '"}'; } > "$TMP/big.json"
call 413 POST "$SCIM/Users" "$SCIM_TOKEN" "@$TMP/big.json"

section "Tenant isolation"
call 201 POST "$BASE_URL/admin/sso/providers" "$ADMIN_TOKEN" "$(jq -n --arg xml "${METADATA//scim-demo-$RUN/scim-demo-$RUN-b}" '{type: "saml", metadata_xml: $xml}')" '.id'
OTHER_ADMIN="$BASE_URL/admin/sso/providers/$(field .id)"
call 200 POST "$OTHER_ADMIN/scim" "$ADMIN_TOKEN" "" '.enabled'
call 201 POST "$OTHER_ADMIN/scim/tokens" "$ADMIN_TOKEN" '{}' '.id'
OTHER_TOKEN="$(field .token)"
call 404 GET "$SCIM/Users/$BARBARA_ID" "$OTHER_TOKEN"
call 404 DELETE "$SCIM/Users/$BARBARA_ID" "$OTHER_TOKEN"
call 200 GET "$SCIM/Users?$(jq -rn --arg f "userName eq \"$BARBARA\"" '"filter=" + ($f | @uri)')" "$OTHER_TOKEN"
expect '.totalResults == 0'
call 201 POST "$SCIM/Users" "$OTHER_TOKEN" "$(user "$BARBARA" Barbara Elsewhere)"
call 200 DELETE "$OTHER_ADMIN" "$ADMIN_TOKEN" '' '.id'
call 204 DELETE "$SCIM/Users/$BARBARA_ID" "$SCIM_TOKEN"
call 404 GET "$SCIM/Users/$BARBARA_ID" "$SCIM_TOKEN"

section "Cleanup"
call 204 DELETE "$SCIM/Groups/$TOUR_GUIDES" "$SCIM_TOKEN"
call 204 DELETE "$SCIM/Groups/$US_EMPLOYEES" "$SCIM_TOKEN"
call 204 DELETE "$SCIM/Users/$JOHN_ID" "$SCIM_TOKEN"
call 204 DELETE "$SCIM/Users/$MANDY_ID" "$SCIM_TOKEN"
call 404 GET "$SCIM/Users/$MANDY_ID" "$SCIM_TOKEN"
call 200 DELETE "$ADMIN/scim" "$ADMIN_TOKEN"
call 401 GET "$SCIM/Users" "$SCIM_TOKEN"
call 200 DELETE "$ADMIN" "$ADMIN_TOKEN"
