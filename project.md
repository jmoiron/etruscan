This is exiftool-rs-go, codenamed 'etruscan'

exiftool is a perl program that parses photo metadata (called exif tags, though exif is not the only type of metadata available these days)

exiftool-rs, (https://github.com/Le-Syl21/exiftool-rs) is an ai agent backed port of exiftool to rust

I want a Go wrapper for exiftool-rs, similar to how there exists Go wrappers to libexiv2, a C++ library.

Feel free to clone https://github.com/Le-Syl21/exiftool-rs into this directory and get it built in whatever manner we need to wrap it and link against it effectively as a Go
library.

There is a test corpus of photos in ../comp/testdata/ that you can use to run against to track your progress. A recent version of exiftool is installed on the system, but
you can also just test against exiftool-rs' command line tool output, as it's meant to be very close to parity.

