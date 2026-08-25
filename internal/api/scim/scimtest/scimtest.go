// Package scimtest checks an implementation against the examples of the SCIM
// specifications themselves.
//
// The golden files hold the JSON examples of the RFCs, extracted from the
// published text. They are stored as indented JSON: the RFC's own indentation
// and line breaks are artifacts of the text format rather than part of the
// specification, so only the JSON value is preserved.
//
// One normalization is worth knowing about. The RFC wraps long string values
// across lines, which no JSON parser accepts. Wrapped prose is rejoined with a
// space, and a wrapped continuous token, such as the base64 of a certificate,
// is rejoined with nothing. The runs of whitespace this leaves inside rejoined
// prose are collapsed, so a description reads as one line rather than exactly
// as the RFC typeset it. Every other value is the RFC's own.
//
// The goldens are embedded rather than read from disk, so that a package
// outside this module can use them: the testdata directory of a dependency is
// not on the importer's disk.
package scimtest

import (
	"embed"
	"io/fs"
	"path"
	"sort"
	"strings"
)

//go:embed testdata
var files embed.FS

const root = "testdata"

// TB is the part of testing.TB that this package uses. It is an interface so
// that these helpers can themselves be tested; *testing.T satisfies it.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// Load reads the named golden file, for a caller that is not a test.
func Load(name string) ([]byte, error) {
	return files.ReadFile(path.Join(root, name))
}

// Golden reads the named golden file, failing the test if it is not there.
func Golden(t TB, name string) []byte {
	t.Helper()

	data, err := Load(name)
	if err != nil {
		t.Fatalf("scimtest: %v", err)
		return nil
	}
	return data
}

// Names lists every golden file, for a test that wants to walk all of them.
func Names() []string {
	var names []string

	_ = fs.WalkDir(files, root, func(p string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if name, found := strings.CutPrefix(p, root+"/"); found {
			names = append(names, name)
		}
		return nil
	})

	sort.Strings(names)
	return names
}
