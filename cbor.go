package etruscan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"unsafe"
)

// A read response is CBOR (RFC 8949, definite lengths only):
//
//	[flags, [tag...]]            flags bit 0 = compact (NoPrintConversion)
//	full tag    [name, g0, g1, g2, g3, print, raw, id, description, value]
//	compact tag [name, g0, g1, g2, g3, raw]
//
// The decoder reads only what the encoder in rust/src/lib.rs writes.

const maxDepth = 32

var errCBOR = errors.New("malformed CBOR")

type decoder struct {
	s string // whole payload; text values are substrings of it (no per-string allocation)
	i int
}

func (d *decoder) head() (major byte, n uint64, err error) {
	if d.i >= len(d.s) {
		return 0, 0, errCBOR
	}
	b := d.s[d.i]
	d.i++
	major, ai := b>>5, b&0x1f
	switch {
	case ai < 24:
		return major, uint64(ai), nil
	case ai > 27:
		return 0, 0, errCBOR // indefinite lengths are never written
	}
	size := 1 << (ai - 24)
	if d.i+size > len(d.s) {
		return 0, 0, errCBOR
	}
	var buf [8]byte
	copy(buf[8-size:], d.s[d.i:d.i+size])
	d.i += size
	return major, binary.BigEndian.Uint64(buf[:]), nil
}

func (d *decoder) arrayLen() (int, error) {
	m, n, err := d.head()
	if err != nil || m != 4 || n > uint64(len(d.s)) {
		return 0, errCBOR
	}
	return int(n), nil
}

func (d *decoder) text() (string, error) {
	m, n, err := d.head()
	if err != nil || m != 3 || n > uint64(len(d.s)-d.i) {
		return "", errCBOR
	}
	s := d.s[d.i : d.i+int(n)]
	d.i += int(n)
	return s, nil
}

// value decodes a typed raw value: string, int64, float64, []any, map[string]any
// or nil.
func (d *decoder) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, errCBOR
	}
	start := d.i
	m, n, err := d.head()
	if err != nil {
		return nil, err
	}
	switch m {
	case 0:
		if n > math.MaxInt64 {
			return float64(n), nil
		}
		return int64(n), nil
	case 1:
		if n > math.MaxInt64 {
			return nil, errCBOR
		}
		return -1 - int64(n), nil
	case 3:
		d.i = start
		return d.text()
	case 4:
		if n > uint64(len(d.s)) {
			return nil, errCBOR
		}
		out := make([]any, n)
		for i := range out {
			if out[i], err = d.value(depth + 1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case 5:
		if n > uint64(len(d.s)) {
			return nil, errCBOR
		}
		out := make(map[string]any, n)
		for i := uint64(0); i < n; i++ {
			k, err := d.text()
			if err != nil {
				return nil, err
			}
			if out[k], err = d.value(depth + 1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case 7:
		switch d.s[start] & 0x1f {
		case 27:
			return math.Float64frombits(n), nil
		case 26:
			return float64(math.Float32frombits(uint32(n))), nil
		case 22, 23:
			return nil, nil
		}
	}
	return nil, fmt.Errorf("%w: unsupported item 0x%02x", errCBOR, d.s[start])
}

// skip advances past one item without decoding it.
func (d *decoder) skip(depth int) error {
	if depth > maxDepth {
		return errCBOR
	}
	m, n, err := d.head()
	if err != nil {
		return err
	}
	switch m {
	case 0, 1, 7:
		return nil
	case 3:
		if n > uint64(len(d.s)-d.i) {
			return errCBOR
		}
		d.i += int(n)
		return nil
	case 4, 5:
		if n > uint64(len(d.s)) {
			return errCBOR
		}
		if m == 5 {
			n *= 2
		}
		for i := uint64(0); i < n; i++ {
			if err := d.skip(depth + 1); err != nil {
				return err
			}
		}
		return nil
	}
	return errCBOR
}

func decodeMetadata(raw []byte) (*Metadata, error) {
	d := decoder{s: string(raw)} // the one copy; tag strings alias it
	if n, err := d.arrayLen(); err != nil || n != 2 {
		return nil, errCBOR
	}
	m, flags, err := d.head()
	if err != nil || m != 0 {
		return nil, errCBOR
	}
	compact := flags&1 != 0
	n, err := d.arrayLen()
	if err != nil {
		return nil, err
	}
	want := 10
	if compact {
		want = 6
	}
	tags := make([]Tag, n)
	for i := range tags {
		if k, err := d.arrayLen(); err != nil || k != want {
			return nil, errCBOR
		}
		t := &tags[i]
		for _, f := range []*string{&t.Name, &t.Group0, &t.Group1, &t.Group2, &t.Group3} {
			if *f, err = d.text(); err != nil {
				return nil, err
			}
		}
		if compact {
			if t.Raw, err = d.text(); err != nil {
				return nil, err
			}
			t.Print = t.Raw
			continue
		}
		for _, f := range []*string{&t.Print, &t.Raw, &t.ID, &t.Description} {
			if *f, err = d.text(); err != nil {
				return nil, err
			}
		}
		start := d.i
		if err = d.skip(0); err != nil {
			return nil, err
		}
		t.val = d.s[start:d.i]
	}
	md := &Metadata{Tags: tags}
	for i := range tags {
		tags[i].md = md
	}
	return md, nil
}

// decodeBinary decodes a binary read response, [[name, g0, g1, bytes]...],
// copying every payload into its own Go slice (raw is C memory that is freed
// when the caller returns, so nothing may point into it).
func decodeBinary(raw []byte) ([]BinaryTag, error) {
	if len(raw) == 0 {
		return nil, errCBOR
	}
	d := &decoder{s: unsafe.String(&raw[0], len(raw))}
	n, err := d.arrayLen()
	if err != nil {
		return nil, err
	}
	out := make([]BinaryTag, 0, n)
	for ; n > 0; n-- {
		if m, err := d.arrayLen(); err != nil || m != 4 {
			return nil, errCBOR
		}
		var t BinaryTag
		var f [3]string
		for i := range f {
			s, err := d.text()
			if err != nil {
				return nil, err
			}
			f[i] = strings.Clone(s)
		}
		t.Name, t.Group0, t.Group1 = f[0], f[1], f[2]
		m, l, err := d.head()
		if err != nil || m != 2 || l > uint64(len(d.s)-d.i) {
			return nil, errCBOR
		}
		t.Data = []byte(d.s[d.i : d.i+int(l)])
		d.i += int(l)
		out = append(out, t)
	}
	return out, nil
}
