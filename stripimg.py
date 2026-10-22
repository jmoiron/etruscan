#!/usr/bin/env python3
"""Strip image data from a corpus while keeping the metadata.

    stripimg.py -o OUTDIR SRC [SRC...] [--gzip | --sparse] [-j N] [-v] [--no-verify]

SRC is a directory (searched recursively) or a file. The tree below it is
reproduced under OUTDIR.

Most formats are blanked IN PLACE: pixel data, embedded previews and thumbnails
are overwritten with zeros and nothing moves, so every offset, length and
pointer in the metadata stays valid and the file keeps its apparent size.
Zeros compress to almost nothing, so --gzip writes NAME.ext.gz (the form to
check in: small in the working tree, and it survives copying). --sparse writes
the zeros as filesystem holes instead, which is only a local convenience: holes
do not survive cp, tar, git checkout or gzip. PNG has no offsets, so it is
rewritten with an all-zero image of the same dimensions instead, which does
shrink it.

What is blanked:
  JPEG    the entropy-coded scan data of every JPEG stream found anywhere in
          the file (main image, EXIF/MPF/CR3/HEIF thumbnails and previews,
          trailing gain maps), with segments and headers kept
  TIFF    every strip, tile and raw-data range listed by exiftool (CR2, DNG,
          NEF, ARW, TIFF, ...) that is not itself a JPEG stream
  ISO BMFF  samples of video tracks (CR3 main image, MP4 video) and image items
          (HEIC/HEIF/AVIF), including an MP4 appended to a JPEG
  PNG     IDAT

Each output is then checked: exiftool's output for the original and the result
must agree, ignoring the System group (file name, times, ...). A difference
means data that exiftool reads was blanked, or the format needs handling here.
Needs `exiftool` on PATH (or --exiftool).
"""
import argparse
import concurrent.futures
import gzip
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

EXTS = {
    ".jpg", ".jpeg", ".png", ".tif", ".tiff", ".cr2", ".cr3", ".crw", ".heic",
    ".heif", ".hif", ".avif", ".dng", ".nef", ".nrw", ".arw", ".orf", ".rw2",
    ".raf", ".pef", ".srw", ".webp", ".mp4", ".m4v", ".mov", ".mp",
}
BLOCK = 4096
MIN_RANGE = 1024  # ignore smaller offset/length pairs, they're metadata

EXIFTOOL = "exiftool"


def exiftool_json(path):
    out = subprocess.run(
        [EXIFTOOL, "-j", "-n", "-G1", "-a", "-u", "-api", "largefilesupport=1", path],
        capture_output=True,
    )
    if not out.stdout.strip():
        raise RuntimeError("exiftool: " + out.stderr.decode(errors="replace").strip())
    return json.loads(out.stdout)[0]


# ---------------------------------------------------------------- JPEG

SOF = set(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}
SCAN_END = re.compile(rb"\xff[\x01-\xcf\xd8-\xfe]")
SOI = re.compile(rb"\xff\xd8\xff")


def jpeg_scans(buf, pos):
    """Entropy-coded ranges of the JPEG starting at pos, or None if it isn't
    a well-formed JPEG (reaching EOI, or the end of a truncated file)."""
    n = len(buf)
    pos += 2
    ranges = []
    seen_sof = False
    while pos + 2 <= n:
        if buf[pos] != 0xFF:
            return None
        while pos + 2 < n and buf[pos + 1] == 0xFF:
            pos += 1
        m = buf[pos + 1]
        if m == 0xD9:
            return ranges if seen_sof else None
        if m == 0x01 or 0xD0 <= m <= 0xD7:
            pos += 2
            continue
        if pos + 4 > n:
            return None
        (length,) = struct.unpack_from(">H", buf, pos + 2)
        if length < 2 or pos + 2 + length > n:
            return None
        if m in SOF:
            seen_sof = True
        pos += 2 + length
        if m == 0xDA:
            if not seen_sof:
                return None
            end = SCAN_END.search(buf, pos)
            if not end:  # truncated file: the scan runs to the end
                ranges.append((pos, n))
                return ranges
            ranges.append((pos, end.start()))
            pos = end.start()
    return None


def jpeg_ranges(buf):
    out = []
    for m in SOI.finditer(buf):
        r = jpeg_scans(buf, m.start())
        if r:
            out.extend(r)
    return out


# ---------------------------------------------------------------- ISO BMFF


def boxes(buf, start, end):
    pos = start
    while pos + 8 <= end:
        size, typ = struct.unpack_from(">I4s", buf, pos)
        hdr = 8
        if size == 1:
            (size,) = struct.unpack_from(">Q", buf, pos + 8)
            hdr = 16
        elif size == 0:
            size = end - pos
        if size < hdr or pos + size > end:
            return
        yield typ, pos + hdr, pos + size
        pos += size


def find(buf, start, end, *path):
    """Payload ranges of the boxes reached by following path (nested boxes)."""
    if not path:
        yield start, end
        return
    for typ, s, e in boxes(buf, start, end):
        if typ == path[0]:
            yield from find(buf, s, e, *path[1:])


def track_ranges(buf, base, ts, te):
    """Sample ranges of a trak whose handler is 'vide'."""
    for s, e in find(buf, ts, te, b"mdia", b"hdlr"):
        if bytes(buf[s + 8 : s + 12]) != b"vide":
            return []
    for ss, se in find(buf, ts, te, b"mdia", b"minf", b"stbl"):
        sizes = chunks = offsets = None
        for typ, s, e in boxes(buf, ss, se):
            if typ == b"stsz":
                fixed, count = struct.unpack_from(">II", buf, s + 4)
                sizes = [fixed] * count if fixed else list(struct.unpack_from(">%dI" % count, buf, s + 12))
            elif typ == b"stsc":
                (count,) = struct.unpack_from(">I", buf, s + 4)
                chunks = [struct.unpack_from(">III", buf, s + 8 + 12 * i) for i in range(count)]
            elif typ == b"stco":
                (count,) = struct.unpack_from(">I", buf, s + 4)
                offsets = list(struct.unpack_from(">%dI" % count, buf, s + 8))
            elif typ == b"co64":
                (count,) = struct.unpack_from(">I", buf, s + 4)
                offsets = list(struct.unpack_from(">%dQ" % count, buf, s + 8))
        if not (sizes is not None and chunks and offsets):
            return []
        out = []
        sample = 0
        for i, off in enumerate(offsets):
            idx = i + 1
            per = 0
            for first, spc, _ in chunks:
                if first <= idx:
                    per = spc
            total = sum(sizes[sample : sample + per])
            sample += per
            out.append((base + off, base + off + total))
        return out
    return []


IMAGE_ITEMS = {b"hvc1", b"hev1", b"av01", b"avc1", b"jpeg", b"j2k1", b"vvc1"}


def heif_ranges(buf, base, ms, me):
    """Extents of image items in a top-level meta box (payload ms..me)."""
    ms += 4  # version/flags
    image_ids = set()
    for s, e in find(buf, ms, me, b"iinf"):
        ver = buf[s]
        p = s + 4 + (2 if ver == 0 else 4)
        for typ, ps, pe in boxes(buf, p, e):
            if typ != b"infe":
                continue
            iv = buf[ps]
            if iv < 2:
                continue
            if iv == 2:
                (iid,) = struct.unpack_from(">H", buf, ps + 4)
                q = ps + 4 + 2 + 2
            else:
                (iid,) = struct.unpack_from(">I", buf, ps + 4)
                q = ps + 4 + 4 + 2
            if bytes(buf[q : q + 4]) in IMAGE_ITEMS:
                image_ids.add(iid)
    out = []
    for s, e in find(buf, ms, me, b"iloc"):
        ver = buf[s]
        osz, lsz = buf[s + 4] >> 4, buf[s + 4] & 15
        bsz, isz = buf[s + 5] >> 4, buf[s + 5] & 15
        p = s + 6
        if ver < 2:
            (count,) = struct.unpack_from(">H", buf, p)
            p += 2
        else:
            (count,) = struct.unpack_from(">I", buf, p)
            p += 4

        def rd(size):
            nonlocal p
            v = int.from_bytes(buf[p : p + size], "big")
            p += size
            return v

        for _ in range(count):
            iid = rd(2 if ver < 2 else 4)
            method = 0
            if ver in (1, 2):
                method = rd(2) & 15
            rd(2)
            baseoff = rd(bsz)
            for _ in range(rd(2)):
                if ver in (1, 2) and isz:
                    rd(isz)
                off, ln = rd(osz), rd(lsz)
                if iid in image_ids and method == 0:
                    out.append((base + baseoff + off, base + baseoff + off + ln))
    return out


def bmff_ranges(buf, base=0, end=None):
    end = len(buf) if end is None else end
    out = []
    for typ, s, e in boxes(buf, base, end):
        if typ == b"moov":
            for ts, te in find(buf, s, e, b"trak"):
                out.extend(track_ranges(buf, base, ts, te))
        elif typ == b"meta":
            out.extend(heif_ranges(buf, base, s, e))
    return out


def bmff_trailer(buf):
    """An MP4 appended to the file (motion photos): ranges inside it."""
    i = buf.rfind(b"ftyp")
    if i < 4:
        return []
    try:
        return bmff_ranges(buf, i - 4)
    except (struct.error, IndexError):
        return []


# ---------------------------------------------------------------- offset tags

# Only these: other offset/size pairs (QuickTime MediaData, VRD, ...) point at
# metadata or whole boxes.
PAIR = re.compile(r"^((?:\w*(?:Strip|Tile|Thumbnail|Preview|RawData|RawImage)\w*?|JpgFromRaw|OtherImage))(Offsets?|Start)$")
LENGTHS = ("ByteCounts", "ByteCount", "Length", "Size")


def ints(v):
    if isinstance(v, (int, float)):
        return [int(v)]
    if isinstance(v, str) and re.fullmatch(r"[\d ]+", v.strip()):
        return [int(x) for x in v.split()]
    return []


def tag_ranges(meta, buf):
    """Ranges named by offset/length tag pairs (strips, tiles, raw data) whose
    content is not a JPEG stream (those are handled by jpeg_ranges)."""
    out = []
    for key, val in meta.items():
        group, _, name = key.rpartition(":")
        m = PAIR.match(name)
        if not m:
            continue
        for suffix in LENGTHS:
            lengths = meta.get(f"{group}:{m.group(1)}{suffix}")
            if lengths is not None:
                break
        else:
            continue
        offs, lens = ints(val), ints(lengths)
        if not offs or len(offs) != len(lens):
            continue
        for o, ln in zip(offs, lens):
            if ln >= MIN_RANGE and o + ln <= len(buf) and bytes(buf[o : o + 3]) != b"\xff\xd8\xff":
                out.append((o, o + ln))
    return out


# ---------------------------------------------------------------- PNG


def png_rewrite(data):
    """Same chunks, but IDAT replaced by an all-zero image of the same size."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    chunks = []
    pos = 8
    idat = bytearray()
    first = None
    while pos + 8 <= len(data):
        ln, typ = struct.unpack_from(">I4s", data, pos)
        body = data[pos + 8 : pos + 8 + ln]
        if typ == b"IDAT":
            if first is None:
                first = len(chunks)
                chunks.append(None)
            idat += body
        else:
            chunks.append((typ, bytes(body)))
        pos += 12 + ln
    if first is None:
        return data
    d = zlib.decompressobj()
    raw = 0
    tail = bytes(idat)
    while tail and not d.eof:
        piece = d.decompress(tail, 1 << 20)
        raw += len(piece)
        tail = d.unconsumed_tail
    raw += len(d.flush())
    c = zlib.compressobj(9)
    z = bytearray()
    zeros = bytes(1 << 20)
    left = raw
    while left > 0:
        k = min(left, len(zeros))
        z += c.compress(zeros[:k])
        left -= k
    z += c.flush()
    chunks[first] = (b"IDAT", bytes(z))
    out = bytearray(data[:8])
    for typ, body in chunks:
        out += struct.pack(">I", len(body)) + typ + body
        out += struct.pack(">I", zlib.crc32(typ + body))
    return bytes(out)


# ---------------------------------------------------------------- driver


def merge(ranges, n):
    ranges = sorted((max(0, a), min(n, b)) for a, b in ranges if b > a)
    out = []
    for a, b in ranges:
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def write_out(path, buf, sparse, gz=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if gz:
        # mtime=0 and no name: the same input always gives the same bytes
        with open(path + ".gz", "wb") as f:
            f.write(gzip.compress(bytes(buf), 9, mtime=0))
        return
    with open(path, "wb") as f:
        if not sparse:
            f.write(buf)
            return
        zero = bytes(BLOCK)
        for i in range(0, len(buf), BLOCK):
            blk = buf[i : i + BLOCK]
            if blk == zero[: len(blk)]:
                f.seek(len(blk), os.SEEK_CUR)
            else:
                f.write(blk)
        f.truncate(len(buf))


IGNORE_GROUPS = {"System", "ExifTool"}


def significant(meta):
    return {
        k: v
        for k, v in meta.items()
        if k != "SourceFile" and k.split(":")[0] not in IGNORE_GROUPS
    }


def diff_meta(a, b):
    a, b = significant(a), significant(b)
    out = []
    for k in sorted(a.keys() | b.keys()):
        if a.get(k) != b.get(k):
            out.append((k, a.get(k), b.get(k)))
    return out


def process(src, dst, args):
    with open(src, "rb") as f:
        data = f.read()
    ext = os.path.splitext(src)[1].lower()
    info = {"src": src, "dst": dst, "size": len(data), "blanked": 0, "notes": [], "diff": []}
    try:
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            out = png_rewrite(data)
            info["blanked"] = len(data) - len(out)  # bytes saved
            info["out_size"] = len(out)
            write_out(dst, out, False, args.gzip)
            final = out
        else:
            meta = exiftool_json(src)
            buf = bytearray(data)
            ranges = jpeg_ranges(buf) + tag_ranges(meta, buf)
            if data[4:8] == b"ftyp":
                ranges += bmff_ranges(buf)
            else:
                ranges += bmff_trailer(buf)
            merged = merge(ranges, len(buf))
            for a, b in merged:
                buf[a:b] = bytes(b - a)
            info["blanked"] = sum(b - a for a, b in merged)
            info["out_size"] = len(buf)
            if not merged:
                info["notes"].append("no image data found to blank")
            write_out(dst, buf, args.sparse, args.gzip)
            final = buf
        if not args.no_verify:
            if args.gzip:  # check what was written, under its real name
                with tempfile.TemporaryDirectory() as td:
                    chk = os.path.join(td, os.path.basename(dst))
                    with open(chk, "wb") as f:
                        f.write(final)
                    after = exiftool_json(chk)
            else:
                after = exiftool_json(dst)
            info["diff"] = diff_meta(exiftool_json(src), after)
    except Exception as e:  # report, keep going
        info["notes"].append(f"{type(e).__name__}: {e}")
        info["error"] = True
    return info


def gather(srcs):
    for s in srcs:
        if os.path.isdir(s):
            root = s.rstrip("/")
            for dp, _, fns in os.walk(root):
                for fn in sorted(fns):
                    if os.path.splitext(fn)[1].lower() in EXTS:
                        p = os.path.join(dp, fn)
                        yield p, os.path.relpath(p, root)
        else:
            yield s, os.path.basename(s)


def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def main():
    global EXIFTOOL
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src", nargs="+")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--gzip", action="store_true", help="write NAME.gz, deterministically (for checking in)")
    ap.add_argument("--sparse", action="store_true", help="write zero blocks as filesystem holes")
    ap.add_argument("-j", "--jobs", type=int, default=os.cpu_count())
    ap.add_argument("--no-verify", action="store_true", help="skip the exiftool before/after comparison")
    ap.add_argument("--exiftool", default="exiftool")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    EXIFTOOL = args.exiftool
    if args.gzip and args.sparse:
        ap.error("--gzip and --sparse are mutually exclusive")
    if not shutil.which(EXIFTOOL):
        sys.exit(f"{EXIFTOOL} not found")

    jobs = [(s, os.path.join(args.out, rel)) for s, rel in gather(args.src)]
    if not jobs:
        sys.exit("no files found")
    total_in = total_out = bad = 0
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as ex:
        for info in ex.map(lambda j: process(j[0], j[1], args), jobs):
            total_in += info["size"]
            total_out += info.get("out_size", info["size"])
            status = "ok"
            if info.get("error") or info["diff"]:
                status = "DIFF" if info["diff"] else "ERROR"
                bad += 1
            if args.verbose or status != "ok" or info["notes"]:
                print(f"{status:5} {info['src']}  {human(info['size'])}, blanked {human(info['blanked'])}")
                for n in info["notes"]:
                    print("      note:", n)
                for k, a, b in info["diff"][:10]:
                    print(f"      {k}: {str(a)[:60]!r} -> {str(b)[:60]!r}")
                if len(info["diff"]) > 10:
                    print(f"      ... {len(info['diff']) - 10} more")
    disk = 0
    for dp, _, fns in os.walk(args.out):
        for fn in fns:
            disk += os.stat(os.path.join(dp, fn)).st_blocks * 512
    print(
        f"{len(jobs)} files: {human(total_in)} -> {human(total_out)} apparent, "
        f"{human(disk)} on disk; {bad} with problems"
    )
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
