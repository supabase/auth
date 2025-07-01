# AGENTS.md - Supabase Auth Development Guide

## Build/Test Commands
- `make test` - Run all tests with coverage and race detection
- `make build` - Build the binary with version info
- `make dev` - Start development environment (PostgreSQL on 5432, Auth on 9999)
- `make vet` - Run Go vet for code issues
- `make sec` - Security vulnerability checks with gosec
- `make format` - Format code with gofmt
- `make static` - Static analysis with staticcheck and exhaustive
- `go test ./internal/api/admin_test.go -v` - Run single test file
- `go test -run TestSpecificFunction ./internal/api/...` - Run specific test

## Code Style Guidelines
- **Imports**: Group standard library, third-party, then internal packages with blank lines
- **Naming**: Use camelCase for unexported, PascalCase for exported; descriptive names (e.g., `SignupParams`, `validateSignupParams`)
- **Error Handling**: Use `apierrors` package for API errors; wrap with context using `errors.Wrap()`
- **Types**: Use struct tags for JSON/DB mapping; pointer types for nullable fields (`*time.Time`, `storage.NullString`)
- **Testing**: Use testify/suite pattern; name tests `TestSuiteName` with receiver methods
- **Context**: Always pass `context.Context` as first parameter; use for cancellation and tracing
- **Database**: Use Pop ORM patterns; transactions with proper error handling
- **Validation**: Validate input in dedicated functions (e.g., `validateSignupParams`)