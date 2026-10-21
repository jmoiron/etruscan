# etruscan

Go bindings for [exiftool-rs](https://github.com/Le-Syl21/exiftool-rs), the Rust
port of ExifTool, linked statically through cgo (the same shape as the Go
wrappers around libexiv2).

exiftool-rs source is **not** vendored here. `rust/` is a small `staticlib`
crate (`etruscan-ffi`) that pulls exiftool-rs at a pinned git revision (see
`rust/Cargo.toml`) and exposes a C ABI (`etruscan.h`) that speaks JSON.
`etruscan.go` is the idiomatic Go layer on top.

## Build

Needs Rust >= 1.82 and a C toolchain.

    make rust    # builds lib/libetruscan.a
    make test    # runs the corpus parity + write tests

## Use

```go
m, err := etruscan.Read("photo.jpg", nil)
fmt.Println(m.String("Model"))
for _, t := range m.Tags {
    fmt.Printf("[%s] %s = %s\n", t.Group1, t.Name, t.Print)
}

_, err = etruscan.Write("in.jpg", "out.jpg", []etruscan.Edit{
    etruscan.Set("XMP:Title", "Hello"),
    etruscan.Delete("Artist"),
}, nil)
```

`ReadBytes` reads from memory. `Options` exposes duplicates, fast-scan,
embedded-document extraction, MWG, geolocation and `-struct` output. Each tag
carries the print value, the raw value, and a typed JSON value.

## Status

Against the system `exiftool` on `../comp/testdata/corpus` (JPEG, PNG, TIFF,
CR2, CR3, HIF), ~90-95% of non-File tags match exactly (see `TestParity -v`).
Writes round-trip for JPEG and PNG; exiftool-rs cannot write XMP to TIFF and
reports that in `WriteResult.Warnings`.
