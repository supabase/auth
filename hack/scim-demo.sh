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

section "Users"
BJENSEN="bjensen+$RUN@example.com"
JSMITH="jsmith+$RUN@example.com"
call 201 POST "$SCIM/Users" "$SCIM_TOKEN" "$(user "$BJENSEN" Barbara Jensen)"
USER="$(field .id)"
call 201 POST "$SCIM/Users" "$SCIM_TOKEN" "$(user "$JSMITH" John Smith)"
OTHER="$(field .id)"
call 200 GET "$SCIM/Users?filter=$(uri "userName eq \"$BJENSEN\"")" "$SCIM_TOKEN"
call 200 GET "$SCIM/Users?sortBy=userName&sortOrder=descending" "$SCIM_TOKEN"
call 200 GET "$SCIM/Users?sortBy=userName&startIndex=2&count=1" "$SCIM_TOKEN"
call 200 PATCH "$SCIM/Users/$USER" "$SCIM_TOKEN" "$(patch '{"op": "replace", "path": "name.familyName", "value": "Jensen-Smith"}')"
call 200 PUT "$SCIM/Users/$USER" "$SCIM_TOKEN" "$(user "$BJENSEN" Babs Jensen)"
call 200 PATCH "$SCIM/Users/$USER" "$SCIM_TOKEN" "$(patch '{"op": "replace", "path": "active", "value": false}')"
call 200 PATCH "$SCIM/Users/$USER" "$SCIM_TOKEN" "$(patch '{"op": "replace", "path": "active", "value": true}')"

section "Groups"
call 201 POST "$SCIM/Groups" "$SCIM_TOKEN" "$(jq -n --arg n "Tour Guides $RUN" --arg m "$USER" '{
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  displayName: $n,
  members: [{value: $m}]
}')"
GROUP="$(field .id)"
call 204 PATCH "$SCIM/Groups/$GROUP" "$SCIM_TOKEN" "$(patch "{\"op\": \"add\", \"path\": \"members\", \"value\": [{\"value\": \"$OTHER\"}]}")"
call 204 PATCH "$SCIM/Groups/$GROUP" "$SCIM_TOKEN" "$(patch "{\"op\": \"remove\", \"path\": \"members[value eq \\\"$USER\\\"]\"}")"
call 200 GET "$SCIM/Groups/$GROUP" "$SCIM_TOKEN"

section "Errors"
call 409 POST "$SCIM/Users" "$SCIM_TOKEN" "$(user "$BJENSEN" Barbara Jensen)"
call 400 GET "$SCIM/Users?filter=$(uri 'userName eq')" "$SCIM_TOKEN"
call 400 GET "$SCIM/Users?sortBy=nope" "$SCIM_TOKEN"
call 404 GET "$SCIM/Users/00000000-0000-0000-0000-000000000000" "$SCIM_TOKEN"
call 401 GET "$SCIM/Users" "not-a-token"

section "RFC 7644 s4: discovery"
call 200 GET "$SCIM/ServiceProviderConfig" "$SCIM_TOKEN"
expect_header Content-Type '^application/scim\+json'
expect '.schemas == ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"]'
expect '.patch.supported and .filter.supported and .sort.supported'
expect '.filter.maxResults == 100'
expect '(.bulk.supported | not) and (.changePassword.supported | not) and (.etag.supported | not)'
expect '.authenticationSchemes | length > 0'
call 200 GET "$SCIM/ResourceTypes/User" "$SCIM_TOKEN"
expect '.endpoint == "/Users" and .schema == "urn:ietf:params:scim:schemas:core:2.0:User"'
expect '.schemaExtensions == [{"schema": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", "required": false}]'
call 200 GET "$SCIM/ResourceTypes/Group" "$SCIM_TOKEN"
expect '.endpoint == "/Groups"'
call 200 GET "$SCIM/Schemas/urn:ietf:params:scim:schemas:core:2.0:User" "$SCIM_TOKEN"
expect '[.attributes[] | select(.name == "userName")][0] | .required and .uniqueness == "server" and (.caseExact | not)'
expect '[.attributes[] | select(.name == "password")][0] | .returned == "never" and .mutability == "writeOnly"'
call 200 GET "$SCIM/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group" "$SCIM_TOKEN"
call 200 GET "$SCIM/Schemas/urn:ietf:params:scim:schemas:extension:enterprise:2.0:User" "$SCIM_TOKEN"
call 404 GET "$SCIM/Schemas/urn:example:nope" "$SCIM_TOKEN"
call 501 POST "$SCIM/Bulk" "$SCIM_TOKEN" '{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": []}'
call 501 GET "$SCIM/Me" "$SCIM_TOKEN"

section "RFC 7644 s3.3: create"
ALICE="alice+$RUN@example.com"
call 201 POST "$SCIM/Users" "$SCIM_TOKEN" "$(jq -n --arg u "$ALICE" '{
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
  userName: $u,
  externalId: ("ext-" + $u),
  name: {givenName: "Alice", familyName: "Liddell"},
  title: "Engineer",
  emails: [{value: $u, type: "work", primary: true}, {value: ("home-" + $u), type: "home"}],
  password: "t1meMa$heen",
  active: true,
  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {employeeNumber: "42", department: "R&D"}
}')"
ALICE_ID="$(field .id)"
expect_header Content-Type '^application/scim\+json'
expect_header Location "/scim/v2/Users/$ALICE_ID$"
expect '.meta.resourceType == "User" and .meta.location == "'"$(header Location)"'"'
expect '.meta.created and .meta.lastModified and (.meta.version | startswith("W/"))'
expect 'has("password") | not'
expect '.schemas | index("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")'
call 409 POST "$SCIM/Users" "$SCIM_TOKEN" "$(user "$(tr '[:lower:]' '[:upper:]' <<< "$ALICE")" Alice Again)"
expect '.schemas == ["urn:ietf:params:scim:api:messages:2.0:Error"] and .scimType == "uniqueness" and .status == "409"'
call 400 POST "$SCIM/Users" "$SCIM_TOKEN" '{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"]}'
expect '.status == "400"'

section "RFC 7644 s3.4.1: read with attributes and excludedAttributes"
call 200 GET "$SCIM/Users/$ALICE_ID?attributes=userName" "$SCIM_TOKEN"
expect 'keys - ["id", "schemas", "userName", "meta"] == []'
expect '.userName == "'"$ALICE"'"'
call 200 GET "$SCIM/Users/$ALICE_ID?excludedAttributes=emails,name" "$SCIM_TOKEN"
expect '(has("emails") or has("name")) | not'
expect '.id and .userName'
call 200 GET "$SCIM/Users/$ALICE_ID?attributes=urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber" "$SCIM_TOKEN"
expect '.["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"] == {"employeeNumber": "42"}'

section "RFC 7644 s3.4.2: list response and paging"
call 200 GET "$SCIM/Users?count=0" "$SCIM_TOKEN"
expect '.schemas == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]'
expect '.totalResults >= 3 and .itemsPerPage == 0 and ((.Resources // []) | length) == 0'
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
filter "userName eq \"$ALICE\"" '.totalResults == 1'
filter "USERNAME eq \"$(tr '[:lower:]' '[:upper:]' <<< "$ALICE")\"" '.totalResults == 1'
filter "userName ne \"$ALICE\"" '[.Resources[].id] | index("'"$ALICE_ID"'") | not'
filter "userName co \"lice+$RUN\"" '.totalResults == 1'
filter "userName sw \"alice+$RUN\"" '.totalResults == 1'
filter "userName ew \"$RUN@example.com\"" '.totalResults == 3'
filter "userName gt \"alice+$RUN\" and userName lt \"alice+$RUN~\"" '.totalResults == 1'
filter "externalId eq \"ext-$ALICE\"" '.totalResults == 1'
filter "externalId eq \"EXT-$ALICE\"" '.totalResults == 0'
filter "title pr and userName eq \"$ALICE\"" '.totalResults == 1'
filter "not (title pr) and userName eq \"$ALICE\"" '.totalResults == 0'
filter "emails[type eq \"work\" and value co \"alice\"] and userName sw \"alice+$RUN\"" '.totalResults == 1'
filter "emails.value eq \"home-$ALICE\"" '.totalResults == 1'
filter "name.familyName eq \"liddell\" and userName ew \"$RUN@example.com\"" '.totalResults == 1'
filter "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber eq \"42\" and userName ew \"$RUN@example.com\"" '.totalResults == 1'
filter "active eq true and userName ew \"$RUN@example.com\"" '.totalResults == 3'
filter "meta.lastModified gt \"2000-01-01T00:00:00Z\" and userName eq \"$ALICE\"" '.totalResults == 1'
filter "(userName eq \"$ALICE\" or userName eq \"$JSMITH\") and active eq true" '.totalResults == 2'
call 400 GET "$SCIM/Users?$(jq -rn '"filter=" + ("userName xx \"a\"" | @uri)')" "$SCIM_TOKEN"
expect '.scimType == "invalidFilter"'
call 403 GET "$SCIM/Users?$(jq -rn '"filter=" + ("password eq \"x\"" | @uri)')" "$SCIM_TOKEN"
expect '.scimType == "sensitive"'

section "RFC 7644 s3.4.2.3: sorting"
call 200 GET "$SCIM/Users?$(jq -rn --arg f "userName ew \"$RUN@example.com\"" '"filter=" + ($f | @uri)')&sortBy=userName" "$SCIM_TOKEN" "" '[.Resources[].userName]'
expect '[.Resources[].userName] | . == sort'
call 200 GET "$SCIM/Users?$(jq -rn --arg f "userName ew \"$RUN@example.com\"" '"filter=" + ($f | @uri)')&sortBy=userName&sortOrder=descending" "$SCIM_TOKEN" "" '[.Resources[].userName]'
expect '[.Resources[].userName] | . == (sort | reverse)'
call 400 GET "$SCIM/Users?sortBy=userName&sortOrder=sideways" "$SCIM_TOKEN"

section "RFC 7644 s3.4.3: POST .search"
call 200 POST "$SCIM/Users/.search" "$SCIM_TOKEN" "$(jq -n --arg f "userName eq \"$ALICE\"" '{
  schemas: ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
  filter: $f, attributes: ["userName"], startIndex: 1, count: 10
}')"
expect '.totalResults == 1 and (.Resources[0] | keys - ["id", "schemas", "userName", "meta"] == [])'

section "RFC 7644 s3.5.1: PUT"
call 200 PUT "$SCIM/Users/$ALICE_ID" "$SCIM_TOKEN" "$(jq -n --arg u "$ALICE" '{
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
  userName: $u, name: {givenName: "Alicia"}, active: true
}')"
expect '.name == {"givenName": "Alicia"} and (has("title") | not) and (has("emails") | not)'
call 404 PUT "$SCIM/Users/00000000-0000-0000-0000-000000000000" "$SCIM_TOKEN" "$(user "nobody+$RUN@example.com" No Body)"

section "RFC 7644 s3.5.2: PATCH"
call 200 PATCH "$SCIM/Users/$ALICE_ID" "$SCIM_TOKEN" "$(patch '{"op": "Add", "value": {"title": "Lead", "emails": [{"value": "work@example.com", "type": "work"}]}}')"
expect '.title == "Lead" and (.emails | length) == 1'
call 200 PATCH "$SCIM/Users/$ALICE_ID" "$SCIM_TOKEN" "$(patch '{"op": "Replace", "path": "emails[type eq \"work\"].value", "value": "lead@example.com"}')"
expect '.emails[0].value == "lead@example.com"'
call 200 PATCH "$SCIM/Users/$ALICE_ID" "$SCIM_TOKEN" "$(patch '{"op": "remove", "path": "title"}')"
expect 'has("title") | not'
call 200 PATCH "$SCIM/Users/$ALICE_ID?attributes=active" "$SCIM_TOKEN" "$(patch '{"op": "replace", "value": {"active": false}}')"
expect '.active == false and (has("userName") | not)'
call 200 PATCH "$SCIM/Users/$ALICE_ID" "$SCIM_TOKEN" "$(patch "{\"op\": \"replace\", \"path\": \"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value\", \"value\": \"$USER\"}")"
expect '.["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"].manager == {"value": "'"$USER"'"}'
call 400 PATCH "$SCIM/Users/$ALICE_ID" "$SCIM_TOKEN" "$(patch '{"op": "replace", "path": "id", "value": "x"}')"
expect '.scimType == "mutability"'
call 400 PATCH "$SCIM/Users/$ALICE_ID" "$SCIM_TOKEN" "$(patch '{"op": "explode", "path": "title", "value": "x"}')"
call 400 PATCH "$SCIM/Users/$ALICE_ID" "$SCIM_TOKEN" '{"Operations": [{"op": "remove", "path": "title"}]}'

section "Groups: members, nesting and user groups"
call 201 POST "$SCIM/Groups" "$SCIM_TOKEN" "$(jq -n --arg n "Parents $RUN" '{schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"], displayName: $n}')"
PARENT="$(field .id)"
expect_header Location "/scim/v2/Groups/$PARENT$"
call 204 PATCH "$SCIM/Groups/$PARENT" "$SCIM_TOKEN" "$(patch "{\"op\": \"add\", \"path\": \"members\", \"value\": [{\"value\": \"$GROUP\"}, {\"value\": \"$ALICE_ID\"}]}")"
expect_header Content-Location "/scim/v2/Groups/$PARENT$"
call 200 GET "$SCIM/Groups/$PARENT" "$SCIM_TOKEN"
expect '([.members[].value] | sort) == (["'"$GROUP"'", "'"$ALICE_ID"'"] | sort)'
call 200 GET "$SCIM/Users/$OTHER?attributes=groups" "$SCIM_TOKEN"
expect '[.groups[].value] == ["'"$GROUP"'"]'
call 200 GET "$SCIM/Groups?$(jq -rn --arg f "members.value eq \"$ALICE_ID\"" '"filter=" + ($f | @uri)')&excludedAttributes=members" "$SCIM_TOKEN"
expect '[.Resources[].id] == ["'"$PARENT"'"] and (.Resources[0] | has("members") | not)'
call 200 GET "$SCIM/Groups?$(jq -rn --arg f "displayName eq \"parents $RUN\"" '"filter=" + ($f | @uri)')" "$SCIM_TOKEN"
expect '.totalResults == 1'
call 400 PATCH "$SCIM/Groups/$GROUP" "$SCIM_TOKEN" "$(patch "{\"op\": \"add\", \"path\": \"members\", \"value\": [{\"value\": \"$GROUP\"}]}")"
call 400 PATCH "$SCIM/Groups/$PARENT" "$SCIM_TOKEN" "$(patch '{"op": "add", "path": "members", "value": [{"value": "00000000-0000-0000-0000-000000000000"}]}')"
call 200 PATCH "$SCIM/Groups/$PARENT" "$SCIM_TOKEN" "$(patch "{\"op\": \"replace\", \"value\": {\"id\": \"$PARENT\", \"displayName\": \"Parents $RUN\"}}")"
expect '(.members | length) == 2'
call 204 PATCH "$SCIM/Groups/$PARENT" "$SCIM_TOKEN" "$(patch "{\"op\": \"remove\", \"path\": \"members[value eq \\\"$ALICE_ID\\\"]\"}")"
call 204 DELETE "$SCIM/Groups/$PARENT" "$SCIM_TOKEN"
call 200 GET "$SCIM/Users/$OTHER?attributes=groups" "$SCIM_TOKEN"
expect '[.groups[].value] == ["'"$GROUP"'"]'

section "RFC 7644 s3.12: errors"
call 404 GET "$SCIM/Groups/not-a-uuid" "$SCIM_TOKEN"
expect '.schemas == ["urn:ietf:params:scim:api:messages:2.0:Error"] and .status == "404"'
call 405 PUT "$SCIM/Users" "$SCIM_TOKEN" '{}'
call 400 POST "$SCIM/Users" "$SCIM_TOKEN" '{not json'
{ printf '{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "big+%s@example.com", "title": "' "$RUN"; head -c 1100000 /dev/zero | tr '\0' a; printf '"}'; } > "$TMP/big.json"
call 413 POST "$SCIM/Users" "$SCIM_TOKEN" "@$TMP/big.json"

section "Tenant isolation"
call 201 POST "$BASE_URL/admin/sso/providers" "$ADMIN_TOKEN" "$(jq -n --arg xml "${METADATA//scim-demo-$RUN/scim-demo-$RUN-b}" '{type: "saml", metadata_xml: $xml}')" '.id'
OTHER_ADMIN="$BASE_URL/admin/sso/providers/$(field .id)"
call 200 POST "$OTHER_ADMIN/scim" "$ADMIN_TOKEN" "" '.enabled'
call 201 POST "$OTHER_ADMIN/scim/tokens" "$ADMIN_TOKEN" '{}' '.id'
OTHER_TOKEN="$(field .token)"
call 404 GET "$SCIM/Users/$ALICE_ID" "$OTHER_TOKEN"
call 404 DELETE "$SCIM/Users/$ALICE_ID" "$OTHER_TOKEN"
call 200 GET "$SCIM/Users?$(jq -rn --arg f "userName eq \"$ALICE\"" '"filter=" + ($f | @uri)')" "$OTHER_TOKEN"
expect '.totalResults == 0'
call 201 POST "$SCIM/Users" "$OTHER_TOKEN" "$(user "$ALICE" Alice Elsewhere)"
call 200 DELETE "$OTHER_ADMIN" "$ADMIN_TOKEN" '' '.id'
call 204 DELETE "$SCIM/Users/$ALICE_ID" "$SCIM_TOKEN"
call 404 GET "$SCIM/Users/$ALICE_ID" "$SCIM_TOKEN"

section "Cleanup"
call 204 DELETE "$SCIM/Groups/$GROUP" "$SCIM_TOKEN"
call 204 DELETE "$SCIM/Users/$USER" "$SCIM_TOKEN"
call 204 DELETE "$SCIM/Users/$OTHER" "$SCIM_TOKEN"
call 404 GET "$SCIM/Users/$USER" "$SCIM_TOKEN"
call 200 DELETE "$ADMIN/scim" "$ADMIN_TOKEN"
call 401 GET "$SCIM/Users" "$SCIM_TOKEN"
call 200 DELETE "$ADMIN" "$ADMIN_TOKEN"
