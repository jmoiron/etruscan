package etruscan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"testing/iotest"
)

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
	for _, f := range testFiles(t) {
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
	f := testFile(t, "canon-6d-macau.jpg")
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

func TestFromReader(t *testing.T) {
	for _, name := range testNames(t) {
		t.Run(name, func(t *testing.T) {
			r := testReader(t, name)
			defer r.Close()
			m, err := FromReader(r, name, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(m.Tags) == 0 {
				t.Fatal("no tags")
			}
			// same result as reading the bytes directly
			b, err := ReadBytes(testBytes(t, name), name, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(m.Map(), b.Map()) {
				t.Fatal("FromReader and ReadBytes disagree")
			}
			// embedded images are read back from the retained data
			if pt, ok := m.Get("PreviewImage"); ok {
				if _, err := pt.Bytes(); err != nil {
					t.Fatalf("Bytes: %v", err)
				}
			}
		})
	}
	// a failing reader is reported, not swallowed
	if _, err := FromReader(iotest.ErrReader(errors.New("boom")), "x.jpg", nil); err == nil {
		t.Fatal("expected read error")
	}
}

func TestWriteRoundTrip(t *testing.T) {
	for _, name := range []string{"canon-6d-macau.jpg", "canon-400d.tiff", "canon-rawstudio-thumbnail.png"} {
		t.Run(name, func(t *testing.T) {
			src := testFile(t, name)
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

func TestNoPrintConversion(t *testing.T) {
	f := testFile(t, "canon-6d-macau.jpg")
	full, err := Read(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	num, err := Read(f, &Options{NoPrintConversion: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Tags) != len(num.Tags) {
		t.Fatalf("tag count %d vs %d", len(full.Tags), len(num.Tags))
	}
	for i, tg := range num.Tags {
		ft := full.Tags[i]
		if tg.Key() != ft.Key() || tg.Print != ft.Raw || tg.Raw != ft.Raw {
			t.Fatalf("tag %d: %s=%q/%q, want %s raw %q", i, tg.Key(), tg.Print, tg.Raw, ft.Key(), ft.Raw)
		}
		if tg.Value() != nil || tg.ID != "" {
			t.Fatalf("compact tag %s carries extra fields", tg.Key())
		}
	}
	if got := num.String("ExposureTime"); got != "0.008" {
		t.Errorf("ExposureTime = %q, want 0.008", got)
	}
	if got := full.String("ExposureTime"); got == "0.008" {
		t.Errorf("print ExposureTime unexpectedly numeric: %q", got)
	}
	// bytes path too
	data, _ := os.ReadFile(f)
	b, err := ReadBytes(data, f, &Options{NoPrintConversion: true})
	if err != nil || b.String("ExposureTime") != "0.008" {
		t.Errorf("ReadBytes: %v %q", err, b.String("ExposureTime"))
	}
}

func TestTagValue(t *testing.T) {
	f := testFile(t, "canon-6d-macau.jpg")
	m, err := Read(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, tg := range m.Tags {
		kinds[fmt.Sprintf("%T", tg.Value())]++
		switch v := tg.Value().(type) {
		case int64:
			if i, ok := tg.Int(); !ok || i != v {
				t.Errorf("%s: Int() = %d,%v want %d", tg.Key(), i, ok, v)
			}
			if f, ok := tg.Float(); !ok || f != float64(v) {
				t.Errorf("%s: Float() = %v,%v want %d", tg.Key(), f, ok, v)
			}
		case float64:
			if f, ok := tg.Float(); !ok || f != v {
				t.Errorf("%s: Float() = %v,%v want %v", tg.Key(), f, ok, v)
			}
			if _, ok := tg.Int(); ok {
				t.Errorf("%s: Int() succeeded on a float", tg.Key())
			}
		default:
			if _, ok := tg.Float(); ok {
				t.Errorf("%s: Float() succeeded on %T", tg.Key(), v)
			}
		}
	}
	t.Logf("value kinds: %v", kinds)
	if kinds["string"] == 0 || kinds["int64"] == 0 || kinds["float64"] == 0 {
		t.Errorf("expected strings, ints and floats, got %v", kinds)
	}
	// rationals come through as their display string, so they are not numbers
	if tg, ok := m.Get("FNumber"); !ok {
		t.Error("no FNumber")
	} else if v, _ := tg.Value().(string); v != "11" {
		t.Errorf("FNumber Value() = %#v, want string \"11\"", tg.Value())
	} else if _, ok := tg.Float(); ok {
		t.Error("Float() succeeded on a rational")
	}
}

// Tags must not alias the C buffer that was freed after the read.
func TestMetadataSurvivesGC(t *testing.T) {
	f := testFile(t, "canon-6d-macau.jpg")
	first, err := Read(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := Read(f, nil)
	var churn [][]byte
	for i := 0; i < 20; i++ {
		runtime.GC()
		for j := 0; j < 20; j++ {
			if _, err := Read(f, nil); err != nil {
				t.Fatal(err)
			}
			churn = append(churn, make([]byte, 1<<16))
		}
	}
	_ = churn
	for i, tg := range first.Tags {
		w := want.Tags[i]
		if tg.Key() != w.Key() || tg.Print != w.Print || tg.Raw != w.Raw || !reflect.DeepEqual(tg.Value(), w.Value()) {
			t.Fatalf("tag %d (%s) changed after GC/free churn", i, tg.Key())
		}
	}
}

func TestReadBinary(t *testing.T) {
	if _, err := exec.LookPath("exiftool"); err != nil {
		t.Skip("no system exiftool")
	}
	f := testFile(t, "canon-400d.cr2")
	got, err := ReadBinary(f, "ThumbnailImage", "PreviewImage", "Nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no binary tags returned")
	}
	for _, b := range got {
		want, err := exec.Command("exiftool", "-b", "-"+b.Name, f).Output()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b.Data, want) {
			t.Errorf("%s: %d bytes, exiftool -b gives %d", b.Name, len(b.Data), len(want))
		}
		if len(b.Data) < 2 || b.Data[0] != 0xff || b.Data[1] != 0xd8 {
			t.Errorf("%s: not a JPEG", b.Name)
		}
	}
	data, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ReadBinaryBytes(data, f, "ThumbnailImage")
	if err != nil || len(again) != 1 || again[0].Name != "ThumbnailImage" {
		t.Fatalf("ReadBinaryBytes: %v %v", err, again)
	}
	for _, b := range got {
		if b.Name == "ThumbnailImage" && !bytes.Equal(again[0].Data, b.Data) {
			t.Error("ReadBinaryBytes differs from ReadBinary")
		}
	}
}

func TestTagBytes(t *testing.T) {
	var n int
	for _, f := range testFiles(t) {
		for _, opts := range []*Options{{Duplicates: true}, {Duplicates: true, NoPrintConversion: true}} {
			m, err := Read(f, opts)
			if err != nil {
				continue
			}
			for _, tg := range m.Tags {
				if _, ok := imageRanges[tg.Name]; !ok {
					continue
				}
				want, err := ReadBinary(f, tg.Group1+":"+tg.Name)
				if err != nil || len(want) == 0 {
					continue
				}
				got, err := tg.Bytes()
				if err != nil || !bytes.Equal(got, want[0].Data) {
					t.Errorf("%s %s: err=%v got %d bytes, want %d", filepath.Base(f), tg.Key(), err, len(got), len(want[0].Data))
				}
				n++
			}
		}
	}
	if n == 0 {
		t.Fatal("no embedded images checked")
	}
}
