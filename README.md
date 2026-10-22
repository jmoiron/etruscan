# etruscan

Go bindings for [exiftool-rs](https://github.com/jmoiron/exiftool-rs), a Rust
port of [ExifTool](https://exiftool.org). The Rust library is linked statically
through cgo, so there is no `exiftool` process to spawn and no Perl runtime to
install. The shape is the same as the Go wrappers around libexiv2, but with
ExifTool's tag coverage (maker notes, QuickTime/CR3/HEIF, XMP, ICC and so on).

exiftool-rs is not vendored here. `rust/` is a small `staticlib` crate
(`etruscan-ffi`) that pulls the exiftool-rs fork at a pinned git revision (see
`rust/Cargo.toml`) and exposes a C ABI (`etruscan.h`). `etruscan.go` is the
Go layer on top, and `cbor.go` decodes the wire format.

## Building

You need Rust 1.82 or newer (`cargo`) and a C toolchain. From a fresh
checkout:

    make

That builds the static library and then the Go package. The first build
downloads exiftool-rs from GitHub and takes about a minute; after that, `make`
only rebuilds what changed. Other targets:

    make test         # build, then run the tests
    make rust-local   # build against a local ../exiftool-rs checkout instead
                      # of the pinned revision (EXIFTOOL_RS=/path to override)
    make fmt          # go fmt ./...
    make clean

The Go package links `lib/libetruscan.a`, which is a build product and is not
checked in. `go get` cannot build it, so use etruscan from a checkout:

    require github.com/jmoiron/etruscan v0.0.0
    replace github.com/jmoiron/etruscan => /path/to/etruscan

Run `make` in that checkout before building anything that imports it. A plain
`go build` or `go test` before that fails with a linker error about
`-letruscan`, but afterwards, they work fine.

## Usage

```go
m, err := etruscan.Read("photo.jpg", nil)
if err != nil {
    log.Fatal(err)
}
fmt.Println(m.String("Model"))
for _, t := range m.Tags {
    fmt.Printf("[%s] %s = %s\n", t.Group1, t.Name, t.Print)
}
```

`ReadBytes(data, name, opts)` does the same for data in memory; `name` is used
for its extension when detecting the file type.

### Tags

A `Tag` carries its name, description and the four ExifTool group families
(`Group0` to `Group3`), plus:

- `Print`: the human-readable value, as `exiftool` prints it.
- `Raw`: the unconverted value, as `exiftool -n` prints it.
- `Value()`: the typed raw value (`string`, `int64`, `float64`, `[]any` or
  `map[string]any`), decoded on demand. `Float()` and `Int()` read numbers
  without allocating.

`Metadata.Get(name)` accepts `Name`, `Group0:Name` or `Group1:Name`.
`Metadata.Map()` returns name to print value.

### Options

    etruscan.Read(path, &etruscan.Options{Duplicates: true})

- `Duplicates`: keep same-named tags from different groups, and repeated tags
  within a group (like `exiftool -a`). ExifTool's `-G1` output is closest to
  `Duplicates: true`.
- `NoPrintConversion`: like `exiftool -n`. Only one string per tag is sent
  across the cgo boundary, so reads are cheaper if you do not need `Print`.
- `ExtractEmbedded`, `ShowUnknown`, `ProcessCompressed`, `UseMWG`,
  `Geolocation`, `StructOutput`: the corresponding ExifTool options.
- `RequestedTags`: restrict extraction to the named tags.

### Embedded images

Thumbnails and previews are not read up front: a binary tag reports only its
length. `Tag.Bytes()` reads the data on demand.

```go
if t, ok := m.Get("PreviewImage"); ok {
    jpg, err := t.Bytes()
}
```

For `ThumbnailImage`, `PreviewImage`, `JpgFromRaw` and `OtherImage`, the offset
and length are already among the tags `Read` returned (for example
`PreviewImageStart` and `PreviewImageLength`), so `Bytes` reads just those
bytes from the file without parsing it again. Binary tags without offset tags
(an MPF image in a JPEG, CR3 images) fall back to a full `ReadBinary` of that
one tag. The file must still be at the same path, and unchanged, when you call
`Bytes`; for `ReadBytes`, the slice you passed in is read again.

`ReadBinary(path, tags...)` and `ReadBinaryBytes(data, name, tags...)` are the
lower-level calls and return `[]BinaryTag` with the names, groups and data.

### Writing

```go
res, err := etruscan.Write("in.jpg", "out.jpg", []etruscan.Edit{
    etruscan.Set("XMP:Title", "Hello"),
    etruscan.Delete("Artist"),
}, nil)
```

Anything exiftool-rs declines to write comes back in `res.Warnings`. For
example it cannot write XMP into TIFF. Writes round-trip for JPEG and PNG in
the tests; treat other formats as less well exercised.

## Performance

Reads cross the cgo boundary as a single CBOR buffer (definite lengths, no
JSON). Go copies it once, tag strings are substrings of that copy, and typed
values stay encoded until `Value()` is called. On a 526-file Google Takeout
corpus this took allocations from about 42 MB in 225k allocations per pass to
about 11 MB in 3.2k.

Most of the remaining time is in exiftool-rs, and some of the speed in our
benchmarks comes from changes in the fork (end-anchored JPEG trailer
detection, avoiding clones when building composite tags, memoized group
lookup). In our benchmarks etruscan was roughly 10 to 20 times faster than
go-exiftool and ran at roughly two thirds of the speed of libexiv2.

Your corpus will differ.

## Compatibility with ExifTool

etruscan reports what exiftool-rs reports, and exiftool-rs is a port that is
still catching up with Perl ExifTool. On the test corpus (JPEG, PNG, TIFF, CR2,
CR3, HEIF) most tags match, but some differ:

- Some Canon maker-note tags are missing or decoded differently (for example
  `FileNumber`, `FlashActivity`, `SetButtonCrossKeysFunc`, and the PrintConv of
  `AFAreaMode` on newer bodies).
- Some tags are formatted differently (list separators, a few PrintConv
  tables).
- A few formats lack tags that Perl reports (PNG `SignificantBits`, parts of
  HEIF, ICC profile bodies in some JPEGs).

`TestParity` compares against the system `exiftool` if one is installed, and
fails below 80% agreement. When comparing against `exiftool -j`, remember that
its JSON output turns numeric-looking strings into numbers and lists into
arrays, and without `-a` reports one instance of repeated tags.

It is significantly more "compatible" with ExifTool than any exiv2 based tool.
