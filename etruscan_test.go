package etruscan

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const corpus = "../comp/testdata/corpus"

func corpusFiles(t *testing.T) []string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(corpus, "*"))
	if len(files) == 0 {
		t.Skip("no corpus at " + corpus)
	}
	return files
}

func TestVersion(t *testing.T) {
	if Version() == "" {
		t.Fatal("empty version")
	}
}

func TestReadMissing(t *testing.T) {
	if _, err := Read("/nonexistent/x.jpg", nil); err == nil {
		t.Fatal("expected error")
	}
}

// TestParity compares print values against the system exiftool. It logs the
// match ratio per file and fails only if a file is unreadable or the ratio
// is implausibly low.
func TestParity(t *testing.T) {
	if _, err := exec.LookPath("exiftool"); err != nil {
		t.Skip("exiftool not installed")
	}
	for _, f := range corpusFiles(t) {
		t.Run(filepath.Base(f), func(t *testing.T) {
			m, err := Read(f, nil)
			if err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("exiftool", "-j", "-G0", f).Output()
			if err != nil {
				t.Fatal(err)
			}
			var ref []map[string]any
			if err := json.Unmarshal(out, &ref); err != nil || len(ref) != 1 {
				t.Fatalf("bad exiftool output: %v", err)
			}
			mine := map[string]string{}
			for _, tg := range m.Tags {
				mine[tg.Key()] = tg.Print
			}
			total, same := 0, 0
			for k, v := range ref[0] {
				if k == "SourceFile" || len(k) > 5 && k[:5] == "File:" {
					continue
				}
				total++
				if got, ok := mine[k]; ok && got == fmt.Sprint(v) {
					same++
				}
			}
			t.Logf("%d/%d tags identical (%d total read)", same, total, len(m.Tags))
			if total > 0 && float64(same)/float64(total) < 0.8 {
				t.Errorf("parity too low: %d/%d", same, total)
			}
		})
	}
}

func TestReadBytes(t *testing.T) {
	f := filepath.Join(corpus, "canon-6d-macau.jpg")
	data, err := os.ReadFile(f)
	if err != nil {
		t.Skip("corpus missing")
	}
	a, err := ReadBytes(data, f, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Read(f, nil)
	if a.String("Model") == "" || a.String("Model") != b.String("Model") {
		t.Fatalf("model mismatch %q vs %q", a.String("Model"), b.String("Model"))
	}
}

func TestWriteRoundTrip(t *testing.T) {
	for _, name := range []string{"canon-6d-macau.jpg", "canon-400d.tiff", "canon-rawstudio-thumbnail.png"} {
		t.Run(name, func(t *testing.T) {
			src := filepath.Join(corpus, name)
			if _, err := os.Stat(src); err != nil {
				t.Skip("corpus missing")
			}
			dst := filepath.Join(t.TempDir(), name)
			edits := []Edit{Set("XMP:Title", "Etruscan Test"), Set("Artist", "Jane")}
			// exiftool-rs cannot write XMP into TIFF; it must say so.
			xmp := filepath.Ext(name) != ".tiff"
			res, err := Write(src, dst, edits, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("write result: %+v", res)
			if !xmp {
				if len(res.Warnings) == 0 {
					t.Error("expected a warning for unwritable XMP:Title")
				}
				if m, err := Read(dst, nil); err != nil || m.String("Artist") != "Jane" {
					t.Errorf("Artist not written: %v", err)
				}
				return
			}
			m, err := Read(dst, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := m.String("Title"); got != "Etruscan Test" {
				t.Errorf("Title = %q", got)
			}
			if got := m.String("Artist"); got != "Jane" {
				t.Errorf("Artist = %q", got)
			}
			// delete
			if _, err := Write(dst, dst, []Edit{Delete("XMP:Title")}, nil); err != nil {
				t.Fatal(err)
			}
			m, _ = Read(dst, nil)
			if got := m.String("Title"); got != "" {
				t.Errorf("Title after delete = %q", got)
			}
		})
	}
}
