// Package etruscan is a Go wrapper around exiftool-rs, a Rust port of
// ExifTool. The Rust library is linked statically through cgo; run `make` in
// this directory before building Go code that imports this package.
package etruscan

/*
#cgo LDFLAGS: -L${SRCDIR}/lib -letruscan -lm -ldl -lpthread
#include <stdlib.h>
#include <string.h>
#include "etruscan.h"
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"unsafe"
)

// Tag is a single metadata value.
type Tag struct {
	ID          string
	Name        string
	Description string
	// Group0..Group3 are ExifTool's group families (e.g. EXIF / IFD0 / Image / Main).
	Group0 string
	Group1 string
	Group2 string
	Group3 string
	// Print is the human-readable value (exiftool's default output). With
	// Options.NoPrintConversion it holds the unconverted value instead.
	Print string
	// Raw is the unconverted value (exiftool -n).
	Raw string
	// val is this tag's typed raw value in CBOR, a substring of the response
	// payload; see Value. Empty with NoPrintConversion.
	val string
	md  *Metadata // owner, for Bytes
}

// imageRanges names, for each embedded-image tag, the sibling tags holding its
// absolute file offset and length. exiftool reports these as ordinary tags.
var imageRanges = map[string][2]string{
	"ThumbnailImage": {"ThumbnailOffset", "ThumbnailLength"},
	"PreviewImage":   {"PreviewImageStart", "PreviewImageLength"},
	"JpgFromRaw":     {"JpgFromRawStart", "JpgFromRawLength"},
	"OtherImage":     {"OtherImageStart", "OtherImageLength"},
}

func (t Tag) intValue() (int64, bool) {
	if t.val != "" {
		return t.Int()
	}
	n, err := strconv.ParseInt(t.Raw, 10, 64)
	return n, err == nil
}

// Bytes returns the data of a binary tag such as ThumbnailImage, PreviewImage
// or JpgFromRaw into a new slice. Read reports only the length of these. For
// embedded images the offset and length are already among the tags Read
// returned (ThumbnailOffset/ThumbnailLength and so on), so this reads just
// those bytes from the file, without parsing it again. A binary tag with no
// offset tags (an MPF image in a JPEG, CR3 images) falls back to a full
// ReadBinary of that one tag.
//
// The file is read again at call time: it must still be at the path given to
// Read and unchanged. For ReadBytes the slice passed in is read, and must not
// have been modified.
func (t Tag) Bytes() ([]byte, error) {
	m := t.md
	if m == nil || (m.path == "" && m.src == nil) {
		return nil, &Error{"tag has no source to read from"}
	}
	if r, ok := imageRanges[t.Name]; ok {
		var off, ln int64 = -1, -1
		for _, s := range m.Tags {
			if s.Group1 != t.Group1 || s.Group3 != t.Group3 {
				continue
			}
			switch s.Name {
			case r[0]:
				off, _ = s.intValue()
			case r[1]:
				ln, _ = s.intValue()
			}
		}
		if off >= 0 && ln > 0 {
			if b, err := m.readRange(off, ln); err == nil {
				return b, nil
			}
		}
	}
	var bt []BinaryTag
	var err error
	if m.path != "" {
		bt, err = ReadBinary(m.path, t.Group1+":"+t.Name)
	} else {
		bt, err = ReadBinaryBytes(m.src, m.name, t.Group1+":"+t.Name)
	}
	if err != nil {
		return nil, err
	}
	for _, b := range bt {
		if b.Name == t.Name && b.Group1 == t.Group1 {
			return b.Data, nil
		}
	}
	return nil, &Error{"no binary data for " + t.Key()}
}

// Value decodes the typed raw value on demand: string, int64, float64, []any,
// map[string]any, or a map{"binary": length} for binary data. It is nil with
// NoPrintConversion. Each call decodes afresh; use Float or Int to read a
// number without allocating.
func (t Tag) Value() any {
	if t.val == "" {
		return nil
	}
	d := decoder{s: t.val}
	v, err := d.value(0)
	if err != nil {
		return nil
	}
	return v
}

// Float returns the value as a float64 if it is a number (integers convert).
func (t Tag) Float() (float64, bool) {
	if t.val == "" {
		return 0, false
	}
	d := decoder{s: t.val}
	m, n, err := d.head()
	switch {
	case err != nil:
		return 0, false
	case m == 0:
		return float64(n), true
	case m == 1:
		return -1 - float64(n), true
	case m == 7 && t.val[0]&0x1f == 27:
		return math.Float64frombits(n), true
	case m == 7 && t.val[0]&0x1f == 26:
		return float64(math.Float32frombits(uint32(n))), true
	}
	return 0, false
}

// Int returns the value as an int64 if it is an integer.
func (t Tag) Int() (int64, bool) {
	if t.val == "" {
		return 0, false
	}
	d := decoder{s: t.val}
	m, n, err := d.head()
	switch {
	case err != nil || n > math.MaxInt64:
		return 0, false
	case m == 0:
		return int64(n), true
	case m == 1:
		return -1 - int64(n), true
	}
	return 0, false
}

// Key returns the "Group0:Name" form.
func (t Tag) Key() string { return t.Group0 + ":" + t.Name }

// Metadata is the result of reading a file.
type Metadata struct {
	Tags []Tag

	path string // set by Read
	src  []byte // set by ReadBytes (not copied)
	name string
}

func (m *Metadata) readRange(off, n int64) ([]byte, error) {
	if m.path == "" {
		if off+n > int64(len(m.src)) {
			return nil, io.ErrUnexpectedEOF
		}
		return append([]byte(nil), m.src[off:off+n]...), nil
	}
	f, err := os.Open(m.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := f.ReadAt(b, off); err != nil {
		return nil, err
	}
	return b, nil
}

// Get returns the first tag with the given name, or "Group:Name" key. Matching
// is case-insensitive on the name only when no group is given.
func (m *Metadata) Get(name string) (Tag, bool) {
	for _, t := range m.Tags {
		if t.Name == name || t.Key() == name || t.Group1+":"+t.Name == name {
			return t, true
		}
	}
	return Tag{}, false
}

// String returns the print value of the named tag, or "".
func (m *Metadata) String(name string) string {
	t, _ := m.Get(name)
	return t.Print
}

// Map returns name -> print value; for duplicate names the first wins.
func (m *Metadata) Map() map[string]string {
	out := make(map[string]string, len(m.Tags))
	for _, t := range m.Tags {
		if _, ok := out[t.Name]; !ok {
			out[t.Name] = t.Print
		}
	}
	return out
}

// Options controls extraction. The zero value matches exiftool's defaults
// except that PrintConv is on (Print is populated); Raw is always populated.
type Options struct {
	// Duplicates keeps same-named tags from different groups.
	Duplicates bool `json:"duplicates"`
	// ExtractEmbedded: 0 off, 1..3 = -ee, -ee2, -ee3.
	ExtractEmbedded uint8 `json:"extract_embedded,omitempty"`
	// ShowUnknown: 0 off, 1 = -u, 2 = -U.
	ShowUnknown       uint8 `json:"show_unknown,omitempty"`
	ProcessCompressed bool  `json:"process_compressed,omitempty"`
	UseMWG            bool  `json:"use_mwg,omitempty"`
	Geolocation       bool  `json:"geolocation,omitempty"`
	StructOutput      bool  `json:"struct_output,omitempty"`
	// NoPrintConversion is exiftool's -n: values are unconverted (numeric),
	// and Print and Raw both hold that value. Only that one string per tag
	// is serialized across the cgo boundary (no ID, Description or typed
	// Value), which makes reads cheaper if you never need print values.
	NoPrintConversion bool `json:"no_print_conversion,omitempty"`
	// RequestedTags limits extraction to these tag names.
	RequestedTags []string `json:"requested_tags,omitempty"`
}

func (o *Options) json() string {
	if o == nil {
		return ""
	}
	b, _ := json.Marshal(o)
	return string(b)
}

// BinaryTag is a binary-valued tag such as an embedded image.
type BinaryTag struct {
	Name   string
	Group0 string
	Group1 string
	Data   []byte
}

// Edit is one tag change. A nil Value deletes the tag. Tag may carry a group
// prefix, e.g. "XMP:Title".
type Edit struct {
	Tag   string  `json:"tag"`
	Value *string `json:"value"`
}

// Set builds an Edit that sets tag to value.
func Set(tag, value string) Edit { return Edit{Tag: tag, Value: &value} }

// Delete builds an Edit that removes tag.
func Delete(tag string) Edit { return Edit{Tag: tag} }

// WriteResult describes a completed write.
type WriteResult struct {
	// Count is the number of files updated (0 means the source was copied unchanged).
	Count uint32 `json:"count"`
	// Warnings lists edits that did not take effect.
	Warnings []string `json:"warnings"`
}

// Error is returned for failures reported by exiftool-rs.
type Error struct{ Msg string }

func (e *Error) Error() string { return "etruscan: " + e.Msg }

// call runs fn over the JSON a C call returned, without copying it into Go
// memory (fn must not retain raw), then frees the C string. Errors come back
// as {"error": "..."}, which is how every payload starts when it is one.
func call(p *C.char, fn func(raw []byte) error) error {
	defer C.etruscan_free(p)
	raw := unsafe.Slice((*byte)(unsafe.Pointer(p)), C.strlen(p))
	if bytes.HasPrefix(raw, errPrefix) {
		var e struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			return fmt.Errorf("etruscan: bad error response: %w", err)
		}
		return &Error{e.Error}
	}
	return fn(raw)
}

var errPrefix = []byte(`{"error":`)

// callBuf is call for reads: the buffer is CBOR of known length, or a JSON
// error. fn must not retain raw.
func callBuf(p *C.uint8_t, n C.size_t, fn func(raw []byte) error) error {
	defer C.etruscan_free_buf(p, n)
	raw := unsafe.Slice((*byte)(unsafe.Pointer(p)), int(n))
	if bytes.HasPrefix(raw, errPrefix) {
		var e struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			return fmt.Errorf("etruscan: bad error response: %w", err)
		}
		return &Error{e.Error}
	}
	return fn(raw)
}

// Read extracts all metadata from the file at path. opts may be nil.
func Read(path string, opts *Options) (*Metadata, error) {
	cp, co := C.CString(path), C.CString(opts.json())
	defer C.free(unsafe.Pointer(cp))
	defer C.free(unsafe.Pointer(co))
	var m *Metadata
	var n C.size_t
	p := C.etruscan_read_file(cp, co, &n)
	err := callBuf(p, n, func(raw []byte) (err error) {
		m, err = decodeMetadata(raw)
		return
	})
	if m != nil {
		m.path = path
	}
	return m, err
}

// ReadBytes extracts metadata from in-memory data. name is used (for its
// extension) to help detect the file type and may be empty.
func ReadBytes(data []byte, name string, opts *Options) (*Metadata, error) {
	cn, co := C.CString(name), C.CString(opts.json())
	defer C.free(unsafe.Pointer(cn))
	defer C.free(unsafe.Pointer(co))
	var ptr *C.uint8_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	var m *Metadata
	var n C.size_t
	p := C.etruscan_read_bytes(ptr, C.size_t(len(data)), cn, co, &n)
	err := callBuf(p, n, func(raw []byte) (err error) {
		m, err = decodeMetadata(raw)
		return
	})
	if m != nil {
		m.src, m.name = data, name
	}
	return m, err
}

// FromReader reads r to the end and extracts metadata from what it returned,
// as ReadBytes does; name is used (for its extension) to help detect the file
// type and may be empty. The data is held in memory, and the Metadata keeps it
// so that Tag.Bytes can read embedded images later. Wrap r to decode on the
// way in, for instance a gzip.Reader for a compressed corpus.
func FromReader(r io.Reader, name string, opts *Options) (*Metadata, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return ReadBytes(data, name, opts)
}

// ReadBinary returns the bytes of the named binary tags, for instance
// "ThumbnailImage", "PreviewImage" or "JpgFromRaw" (what exiftool -b prints).
// Names may be group-qualified ("IFD1:ThumbnailImage"). Normal reads report
// only the length of these values, so this is a separate scan of the file.
// Requested tags that are missing, or not binary, are left out of the result.
func ReadBinary(path string, tags ...string) ([]BinaryTag, error) {
	cp, co := C.CString(path), C.CString((&Options{RequestedTags: tags}).json())
	defer C.free(unsafe.Pointer(cp))
	defer C.free(unsafe.Pointer(co))
	var out []BinaryTag
	var n C.size_t
	p := C.etruscan_read_binary_file(cp, co, &n)
	err := callBuf(p, n, func(raw []byte) (err error) {
		out, err = decodeBinary(raw)
		return
	})
	return out, err
}

// ReadBinaryBytes is ReadBinary for in-memory data; name is as in ReadBytes.
func ReadBinaryBytes(data []byte, name string, tags ...string) ([]BinaryTag, error) {
	cn, co := C.CString(name), C.CString((&Options{RequestedTags: tags}).json())
	defer C.free(unsafe.Pointer(cn))
	defer C.free(unsafe.Pointer(co))
	var ptr *C.uint8_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	var out []BinaryTag
	var n C.size_t
	p := C.etruscan_read_binary_bytes(ptr, C.size_t(len(data)), cn, co, &n)
	err := callBuf(p, n, func(raw []byte) (err error) {
		out, err = decodeBinary(raw)
		return
	})
	return out, err
}

// Write applies edits to src and writes the result to dst. src and dst may be
// the same path to edit in place.
func Write(src, dst string, edits []Edit, opts *Options) (*WriteResult, error) {
	if len(edits) == 0 {
		return nil, errors.New("etruscan: no edits")
	}
	eb, err := json.Marshal(edits)
	if err != nil {
		return nil, err
	}
	cs, cd, ce, co := C.CString(src), C.CString(dst), C.CString(string(eb)), C.CString(opts.json())
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(cd))
	defer C.free(unsafe.Pointer(ce))
	defer C.free(unsafe.Pointer(co))
	var r WriteResult
	err = call(C.etruscan_write_file(cs, cd, ce, co), func(raw []byte) error {
		return json.Unmarshal(raw, &r)
	})
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// Version reports the exiftool-rs version linked into this build.
func Version() string {
	var r struct {
		Version string `json:"version"`
	}
	_ = call(C.etruscan_version(), func(raw []byte) error {
		return json.Unmarshal(raw, &r)
	})
	return r.Version
}
