package apierrors

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var generateFlag = flag.Bool("generate", false, "Run tests that generate code")

func TestErrorCodesMap(t *testing.T) {
	cur := helpParseErrorCodes(t)
	gen := errorCodesMap

	for curCode, curName := range cur {
		genName, ok := gen[curCode]
		if !ok {
			t.Fatalf("error code %q: (%v) missing in errorCodesMap",
				curCode, curName)
		}
		if genName != curName {
			t.Fatalf("error code %q: (%v) has different name (%q) in errorCodesMap",
				curCode, curName, genName)
		}
	}
	if a, b := len(cur), len(gen); a != b {
		const msg = "generated code out of sync:" +
			" errorCodeSlice len(%v) != constant declaration len (%v)"
		t.Fatalf(msg, a, b)
	}
}

func TestGenerate(t *testing.T) {
	if !*generateFlag {
		t.SkipNow()
	}

	ecm := helpParseErrorCodes(t)
	ecs := slices.Sorted(maps.Keys(ecm))

	var sb strings.Builder
	sb.WriteString("package apierrors\n\n")
	sb.WriteString("//go:generate go test -run TestGenerate -args -generate\n")
	sb.WriteString("//go:generate go fmt\n\n")

	{
		sb.WriteString("var errorCodesMap = map[string]string{\n")
		for _, ec := range ecs {
			fmt.Fprintf(&sb, "\t%q: %q,\n", ec, ecm[ec])
		}
		sb.WriteString("}\n\n")
	}

	os.WriteFile("errorcode_gen.go", []byte(sb.String()), 0644)
}

func helpParseErrorCodes(t *testing.T) map[string]string {
	ecm, err := parseErrorCodesOnce()
	require.NoError(t, err)
	require.NotEmpty(t, ecm)
	return maps.Clone(ecm)
}

var parseErrorCodesOnce = sync.OnceValues(func() (map[string]string, error) {
	return parseErrorCodes()
})

func parseErrorCodes() (map[string]string, error) {
	data, err := os.ReadFile(`errorcode.go`)
	if err != nil {
		const msg = "parseErrorCodes: os.ReadFile(`errorcode.go`): %w"
		return nil, fmt.Errorf(msg, err)
	}
	src := string(data)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.SkipObjectResolution)
	if err != nil {
		const msg = "parseErrorCodes: parser.ParseFile: %w"
		return nil, fmt.Errorf(msg, err)
	}

	ecm := make(map[string]string)
	for declIdx, decl := range f.Decls {
		if err := parseErrorCodesDecl(ecm, declIdx, decl); err != nil {
			return nil, fmt.Errorf("parseErrorCodes %w", err)
		}
	}
	return ecm, nil
}

func parseErrorCodesDecl(ecm map[string]string, decIdx int, decl ast.Decl) error {
	dec, ok := decl.(*ast.GenDecl)
	if !ok || dec.Tok != token.CONST {
		return nil
	}
	if n := len(dec.Specs); n == 0 {
		return fmt.Errorf("decl[%d]: specs are empty", decIdx)
	}
	for idx, spec := range dec.Specs {
		valSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			return fmt.Errorf("const[%d]: unexpected type: %T", idx, spec)
		}
		if n := len(valSpec.Names); n != 1 {
			return fmt.Errorf("const[%d]: unexpected const len: %T", idx, n)
		}

		constName := valSpec.Names[0].Name
		if !strings.HasPrefix(constName, "ErrorCode") {
			return fmt.Errorf("const[%d]: missing ErrorCode prefix: %v", idx, constName)
		}
		if n := len(valSpec.Values); n != 1 {
			return fmt.Errorf("const[%d]: unexpected const value len: %v", idx, n)
		}

		constExpr := valSpec.Values[0]
		basicLit, ok := constExpr.(*ast.BasicLit)
		if !ok {
			return fmt.Errorf("const[%d]: unexpected const value expr type: %T", idx, constExpr)
		}

		constValue := basicLit.Value
		if n := len(constValue); n <= 3 {
			return fmt.Errorf("const[%d]: unexpected const value string len: %v (%q)",
				idx, n, constValue)
		}
		if constValue[0] != '"' || constValue[len(constValue)-1] != '"' {
			return fmt.Errorf("const[%d]: unexpected const value string quoting (%q)",
				idx, constValue)
		}
		constValue = constValue[1 : len(constValue)-1]

		if prev, found := ecm[constValue]; found {
			msg := "const[%d]: duplicate error code: %q: already defined by %q"
			return fmt.Errorf(msg, idx, constValue, prev)
		}
		ecm[constValue] = constName
	}
	return nil
}
