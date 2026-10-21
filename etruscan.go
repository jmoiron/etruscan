// Package etruscan is a Go wrapper around exiftool-rs, a Rust port of
// ExifTool. The Rust library is linked statically through cgo; build it with
// `make rust` before building Go code that imports this package.
package etruscan

/*
#cgo LDFLAGS: -L${SRCDIR}/lib -letruscan -lm -ldl -lpthread
#include <stdlib.h>
#include "etruscan.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"unsafe"
)

// Tag is a single metadata value.
type Tag struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Group0..Group3 are ExifTool's group families (e.g. EXIF / IFD0 / Image / Main).
	Group0 string `json:"group0"`
	Group1 string `json:"group1"`
	Group2 string `json:"group2"`
	Group3 string `json:"group3"`
	// Print is the human-readable value (exiftool's default output).
	Print string `json:"print"`
	// Raw is the unconverted value (exiftool -n).
	Raw string `json:"raw"`
	// Value is the typed raw value: string, number, []any, map[string]any, or
	// a map{"binary": length} for binary data.
	Value any `json:"value"`
}

// Key returns the "Group0:Name" form.
func (t Tag) Key() string { return t.Group0 + ":" + t.Name }

// Metadata is the result of reading a file.
type Metadata struct {
	Tags []Tag
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
	// FastScan: 0 normal, 1 skip composite, 2 skip maker notes, 3 skip thumbnails.
	FastScan uint8 `json:"fast_scan,omitempty"`
	// ExtractEmbedded: 0 off, 1..3 = -ee, -ee2, -ee3.
	ExtractEmbedded uint8 `json:"extract_embedded,omitempty"`
	// ShowUnknown: 0 off, 1 = -u, 2 = -U.
	ShowUnknown       uint8 `json:"show_unknown,omitempty"`
	ProcessCompressed bool  `json:"process_compressed,omitempty"`
	UseMWG            bool  `json:"use_mwg,omitempty"`
	Geolocation       bool  `json:"geolocation,omitempty"`
	StructOutput      bool  `json:"struct_output,omitempty"`
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

func call(p *C.char) ([]byte, error) {
	defer C.etruscan_free(p)
	raw := []byte(C.GoString(p))
	var probe struct {
		Error *string `json:"error"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("etruscan: bad response: %w", err)
	}
	if probe.Error != nil {
		return nil, &Error{*probe.Error}
	}
	return raw, nil
}

func decodeMetadata(raw []byte) (*Metadata, error) {
	var r struct {
		Tags []Tag `json:"tags"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &Metadata{Tags: r.Tags}, nil
}

// Read extracts all metadata from the file at path. opts may be nil.
func Read(path string, opts *Options) (*Metadata, error) {
	cp, co := C.CString(path), C.CString(opts.json())
	defer C.free(unsafe.Pointer(cp))
	defer C.free(unsafe.Pointer(co))
	raw, err := call(C.etruscan_read_file(cp, co))
	if err != nil {
		return nil, err
	}
	return decodeMetadata(raw)
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
	raw, err := call(C.etruscan_read_bytes(ptr, C.size_t(len(data)), cn, co))
	if err != nil {
		return nil, err
	}
	return decodeMetadata(raw)
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
	raw, err := call(C.etruscan_write_file(cs, cd, ce, co))
	if err != nil {
		return nil, err
	}
	var r WriteResult
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Version reports the exiftool-rs version linked into this build.
func Version() string {
	raw, err := call(C.etruscan_version())
	if err != nil {
		return ""
	}
	var r struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(raw, &r)
	return r.Version
}
