package etruscan

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// testdata holds the test corpus. A file is stored either plainly (x.jpg) or
// gzipped (x.jpg.gz); tests refer to it by its plain name and the file type
// decides how it is opened. The checked-in corpus is gzipped and has its image
// data blanked (see stripimg.py). To check against a full image, drop the plain
// file into testdata: if both exist the plain one wins.
const testdata = "testdata"

// testNames lists the testdata files by their uncompressed names.
func testNames(t testing.TB) []string {
	t.Helper()
	entries, _ := os.ReadDir(testdata)
	seen := map[string]bool{}
	var names []string
	for _, e := range entries {
		n := strings.TrimSuffix(e.Name(), ".gz")
		if !e.IsDir() && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Skip("no test data in " + testdata)
	}
	return names
}

// testReader opens the named testdata file, decompressing it if it is stored
// gzipped.
func testReader(t testing.TB, name string) io.ReadCloser {
	t.Helper()
	plain := filepath.Join(testdata, name)
	if f, err := os.Open(plain); err == nil {
		return f
	}
	f, err := os.Open(plain + ".gz")
	if err != nil {
		t.Skip("no test data " + name)
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		t.Fatalf("%s.gz: %v", name, err)
	}
	return &gzipFile{zr, f}
}

type gzipFile struct {
	*gzip.Reader
	f *os.File
}

func (g *gzipFile) Close() error {
	g.Reader.Close()
	return g.f.Close()
}

// testBytes returns the uncompressed contents of the named testdata file.
func testBytes(t testing.TB, name string) []byte {
	t.Helper()
	r := testReader(t, name)
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return data
}

// testFile returns a path to the uncompressed named testdata file, for the
// tests that need one (Read, Write, the exiftool command). A plain file is used
// in place; a gzipped one is decompressed into the test's temporary directory.
func testFile(t testing.TB, name string) string {
	t.Helper()
	plain := filepath.Join(testdata, name)
	if _, err := os.Stat(plain); err == nil {
		return plain
	}
	out := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(out, testBytes(t, name), 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}

// testFiles returns testFile for every file in testdata.
func testFiles(t testing.TB) []string {
	t.Helper()
	var files []string
	for _, n := range testNames(t) {
		files = append(files, testFile(t, n))
	}
	return files
}
