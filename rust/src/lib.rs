//! C ABI shim over exiftool-rs. Entry points take UTF-8 strings. Writes and
//! the version return JSON documents (`etruscan_free`); reads return a CBOR
//! document of known length (`etruscan_free_buf`). A failure is always a JSON
//! `{"error": "..."}`, which cannot be mistaken for a CBOR read result because
//! a CBOR read result starts with an array header byte, never `{`.

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use exiftool_rs::exiftool::Options;
use exiftool_rs::tag::Tag;
use exiftool_rs::value::Value;
use exiftool_rs::ExifTool;
use serde_json::{json, Value as Json};

/// Minimal CBOR writer (RFC 8949), definite lengths only.
struct Enc(Vec<u8>);

impl Enc {
    fn head(&mut self, major: u8, n: u64) {
        let m = major << 5;
        if n < 24 {
            self.0.push(m | n as u8);
        } else if n <= 0xff {
            self.0.extend_from_slice(&[m | 24, n as u8]);
        } else if n <= 0xffff {
            self.0.push(m | 25);
            self.0.extend_from_slice(&(n as u16).to_be_bytes());
        } else if n <= 0xffff_ffff {
            self.0.push(m | 26);
            self.0.extend_from_slice(&(n as u32).to_be_bytes());
        } else {
            self.0.push(m | 27);
            self.0.extend_from_slice(&n.to_be_bytes());
        }
    }
    fn uint(&mut self, n: u64) {
        self.head(0, n);
    }
    fn int(&mut self, n: i64) {
        if n >= 0 {
            self.head(0, n as u64);
        } else {
            self.head(1, (-1 - n) as u64);
        }
    }
    fn f64(&mut self, f: f64) {
        self.0.push(0xfb);
        self.0.extend_from_slice(&f.to_be_bytes());
    }
    fn text(&mut self, s: &str) {
        self.head(3, s.len() as u64);
        self.0.extend_from_slice(s.as_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.head(2, b.len() as u64);
        self.0.extend_from_slice(b);
    }
    fn array(&mut self, n: usize) {
        self.head(4, n as u64);
    }
    fn map(&mut self, n: usize) {
        self.head(5, n as u64);
    }
}

fn enc_value(e: &mut Enc, v: &Value) {
    match v {
        Value::String(s) => e.text(s),
        Value::U8(n) => e.uint(*n as u64),
        Value::U16(n) => e.uint(*n as u64),
        Value::U32(n) => e.uint(*n as u64),
        Value::I16(n) => e.int(*n as i64),
        Value::I32(n) => e.int(*n as i64),
        // go through the shortest decimal form so 11.1f32 stays 11.1
        Value::F32(n) => e.f64(n.to_string().parse().unwrap_or(f64::NAN)),
        Value::F64(n) => e.f64(*n),
        Value::URational(..) | Value::IRational(..) => e.text(&v.to_display_string()),
        Value::Binary(b) | Value::Undefined(b) => {
            e.map(1);
            e.text("binary");
            e.uint(b.len() as u64);
        }
        Value::List(l) => {
            e.array(l.len());
            for x in l {
                enc_value(e, x);
            }
        }
        Value::Struct(f) => {
            e.map(f.len());
            for (k, x) in f {
                e.text(k);
                enc_value(e, x);
            }
        }
        other => e.text(&other.to_display_string()),
    }
}

/// Read result: [flags, [tag...]]. flags bit 0 = compact. A full tag is
/// [name, group0..3, print, raw, id, description, value]; a compact one
/// (NoPrintConversion) is [name, group0..3, raw].
fn encode_tags(tags: &[Tag], compact: bool) -> Vec<u8> {
    let mut e = Enc(Vec::with_capacity(tags.len() * if compact { 48 } else { 160 } + 16));
    e.array(2);
    e.uint(compact as u64);
    e.array(tags.len());
    for t in tags {
        e.array(if compact { 6 } else { 10 });
        e.text(&t.name);
        e.text(&t.group.family0);
        e.text(&t.group.family1);
        e.text(&t.group.family2);
        e.text(&t.group.family3);
        if compact {
            e.text(&t.raw_value.to_display_string());
            continue;
        }
        e.text(&t.print_value);
        e.text(&t.raw_value.to_display_string());
        e.text(&t.id.to_string());
        e.text(&t.description);
        enc_value(&mut e, &t.raw_value);
    }
    e.0
}

/// Binary read result: [[name, group0, group1, bytes]...], only for tags whose
/// value is binary.
fn encode_binary(tags: &[Tag]) -> Vec<u8> {
    let bins: Vec<&Tag> = tags
        .iter()
        .filter(|t| matches!(t.raw_value, Value::Binary(_) | Value::Undefined(_)))
        .collect();
    let size: usize = bins
        .iter()
        .map(|t| match &t.raw_value {
            Value::Binary(b) | Value::Undefined(b) => b.len() + 64,
            _ => 0,
        })
        .sum();
    let mut e = Enc(Vec::with_capacity(size + 16));
    e.array(bins.len());
    for t in bins {
        e.array(4);
        e.text(&t.name);
        e.text(&t.group.family0);
        e.text(&t.group.family1);
        if let Value::Binary(b) | Value::Undefined(b) = &t.raw_value {
            e.bytes(b);
        }
    }
    e.0
}

fn err(msg: impl std::fmt::Display) -> Json {
    json!({ "error": msg.to_string() })
}

fn options_from(j: &Json) -> Options {
    let mut o = Options::default();
    let b = |k: &str| j.get(k).and_then(Json::as_bool);
    let n = |k: &str| j.get(k).and_then(Json::as_u64);
    if let Some(v) = b("duplicates") { o.duplicates = v; }
    if b("no_print_conversion") == Some(true) { o.print_conv = false; }
    if let Some(v) = n("extract_embedded") { o.extract_embedded = v as u8; }
    if let Some(v) = n("show_unknown") { o.show_unknown = v as u8; }
    if let Some(v) = b("process_compressed") { o.process_compressed = v; }
    if let Some(v) = b("use_mwg") { o.use_mwg = v; }
    if let Some(v) = b("geolocation") { o.geolocation = v; }
    if let Some(v) = b("struct_output") { o.struct_output = v; }
    if let Some(a) = j.get("requested_tags").and_then(Json::as_array) {
        o.requested_tags = a.iter().filter_map(|s| s.as_str().map(String::from)).collect();
    }
    o
}

unsafe fn cstr<'a>(p: *const c_char) -> Result<&'a str, Json> {
    if p.is_null() {
        return Err(err("null string argument"));
    }
    CStr::from_ptr(p).to_str().map_err(|e| err(e))
}

fn finish(r: std::thread::Result<Json>) -> *mut c_char {
    let j = r.unwrap_or_else(|p| {
        let m = p
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown".into());
        err(format!("panic in exiftool-rs: {m}"))
    });
    let s = serde_json::to_string(&j).unwrap_or_else(|_| "{\"error\":\"encode\"}".into());
    // JSON never contains interior NULs (escaped as \u0000).
    CString::new(s).unwrap().into_raw()
}

fn read_with(opts: &str, f: impl FnOnce(&ExifTool) -> exiftool_rs::error::Result<Vec<Tag>>) -> Vec<u8> {
    read_enc(opts, f, |tags, compact| encode_tags(tags, compact))
}

fn read_enc(
    opts: &str,
    f: impl FnOnce(&ExifTool) -> exiftool_rs::error::Result<Vec<Tag>>,
    enc: impl FnOnce(&[Tag], bool) -> Vec<u8>,
) -> Vec<u8> {
    let oj: Json = if opts.is_empty() { json!({}) } else {
        match serde_json::from_str(opts) { Ok(v) => v, Err(e) => return json_bytes(&err(e)) }
    };
    let opts = options_from(&oj);
    let compact = !opts.print_conv;
    let et = ExifTool::with_options(opts);
    match f(&et) {
        Ok(tags) => enc(&tags, compact),
        Err(e) => json_bytes(&err(e)),
    }
}

fn json_bytes(j: &Json) -> Vec<u8> {
    serde_json::to_vec(j).unwrap_or_else(|_| b"{\"error\":\"encode\"}".to_vec())
}

/// Hand a byte buffer to C: leaks a boxed slice, released by `etruscan_free_buf`.
unsafe fn finish_buf(r: std::thread::Result<Vec<u8>>, out_len: *mut usize) -> *mut u8 {
    let v = r.unwrap_or_else(|p| {
        let m = p
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown".into());
        json_bytes(&err(format!("panic in exiftool-rs: {m}")))
    });
    let b = v.into_boxed_slice();
    *out_len = b.len();
    Box::into_raw(b) as *mut u8
}

/// Read all metadata from a file. `opts` is a JSON object (may be empty).
/// Returns a buffer of `*out_len` bytes; release with `etruscan_free_buf`.
#[no_mangle]
pub unsafe extern "C" fn etruscan_read_file(
    path: *const c_char,
    opts: *const c_char,
    out_len: *mut usize,
) -> *mut u8 {
    finish_buf(
        catch_unwind(AssertUnwindSafe(|| {
            let (path, opts) = match (cstr(path), cstr(opts)) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => return json_bytes(&e),
            };
            read_with(opts, |et| et.extract_info(path))
        })),
        out_len,
    )
}

/// Read metadata from memory. `name` supplies the file name used for type detection.
#[no_mangle]
pub unsafe extern "C" fn etruscan_read_bytes(
    data: *const u8,
    len: usize,
    name: *const c_char,
    opts: *const c_char,
    out_len: *mut usize,
) -> *mut u8 {
    finish_buf(
        catch_unwind(AssertUnwindSafe(|| {
            let (name, opts) = match (cstr(name), cstr(opts)) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => return json_bytes(&e),
            };
            let buf: &[u8] = if len == 0 { &[] } else { std::slice::from_raw_parts(data, len) };
            read_with(opts, |et| et.extract_info_from_bytes(buf, Path::new(name)))
        })),
        out_len,
    )
}

/// Read the bytes of binary tags (`opts.requested_tags` names them) from a file.
#[no_mangle]
pub unsafe extern "C" fn etruscan_read_binary_file(
    path: *const c_char,
    opts: *const c_char,
    out_len: *mut usize,
) -> *mut u8 {
    finish_buf(
        catch_unwind(AssertUnwindSafe(|| {
            let (path, opts) = match (cstr(path), cstr(opts)) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => return json_bytes(&e),
            };
            read_enc(opts, |et| et.extract_info(path), |t, _| encode_binary(t))
        })),
        out_len,
    )
}

/// As `etruscan_read_binary_file`, from memory.
#[no_mangle]
pub unsafe extern "C" fn etruscan_read_binary_bytes(
    data: *const u8,
    len: usize,
    name: *const c_char,
    opts: *const c_char,
    out_len: *mut usize,
) -> *mut u8 {
    finish_buf(
        catch_unwind(AssertUnwindSafe(|| {
            let (name, opts) = match (cstr(name), cstr(opts)) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => return json_bytes(&e),
            };
            let buf: &[u8] = if len == 0 { &[] } else { std::slice::from_raw_parts(data, len) };
            read_enc(
                opts,
                |et| et.extract_info_from_bytes(buf, Path::new(name)),
                |t, _| encode_binary(t),
            )
        })),
        out_len,
    )
}

/// Apply edits (`[{"tag": "...", "value": "..."|null}]`) writing `src` to `dst`.
#[no_mangle]
pub unsafe extern "C" fn etruscan_write_file(
    src: *const c_char,
    dst: *const c_char,
    edits: *const c_char,
    opts: *const c_char,
) -> *mut c_char {
    finish(catch_unwind(AssertUnwindSafe(|| {
        let (src, dst, edits, opts) = match (cstr(src), cstr(dst), cstr(edits), cstr(opts)) {
            (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d),
            (Err(e), ..) | (_, Err(e), ..) | (_, _, Err(e), _) | (.., Err(e)) => return e,
        };
        let edits: Vec<Json> = match serde_json::from_str(edits) { Ok(v) => v, Err(e) => return err(e) };
        let oj: Json = if opts.is_empty() { json!({}) } else {
            match serde_json::from_str(opts) { Ok(v) => v, Err(e) => return err(e) }
        };
        let mut et = ExifTool::with_options(options_from(&oj));
        for e in &edits {
            let Some(tag) = e.get("tag").and_then(Json::as_str) else {
                return err("edit without \"tag\"");
            };
            et.set_new_value(tag, e.get("value").and_then(Json::as_str));
        }
        match et.write_info(src, dst) {
            Ok(n) => json!({ "count": n, "warnings": et.write_warnings() }),
            Err(e) => err(e),
        }
    })))
}

/// Version of the exiftool-rs this shim was built against.
#[no_mangle]
pub extern "C" fn etruscan_version() -> *mut c_char {
    finish(Ok(json!({ "version": exiftool_rs::VERSION })))
}

/// Release a string returned by any etruscan_* function.
#[no_mangle]
pub unsafe extern "C" fn etruscan_free(p: *mut c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p));
    }
}

/// Release a buffer returned by etruscan_read_*.
#[no_mangle]
pub unsafe extern "C" fn etruscan_free_buf(p: *mut u8, len: usize) {
    if !p.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(p, len)));
    }
}
