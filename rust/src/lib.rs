//! C ABI shim over exiftool-rs. Every entry point takes and returns UTF-8
//! strings; results are JSON documents owned by Rust and released with
//! `etruscan_free`. A failure is reported as `{"error": "..."}`.

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use exiftool_rs::exiftool::Options;
use exiftool_rs::tag::Tag;
use exiftool_rs::value::Value;
use exiftool_rs::ExifTool;
use serde_json::{json, Map, Value as Json};

fn value_json(v: &Value) -> Json {
    match v {
        Value::String(s) => json!(s),
        Value::U8(n) => json!(n),
        Value::U16(n) => json!(n),
        Value::U32(n) => json!(n),
        Value::I16(n) => json!(n),
        Value::I32(n) => json!(n),
        Value::F32(n) => json!(n),
        Value::F64(n) => json!(n),
        Value::URational(..) | Value::IRational(..) => json!(v.to_display_string()),
        Value::Binary(b) | Value::Undefined(b) => json!({ "binary": b.len() }),
        Value::List(l) => Json::Array(l.iter().map(value_json).collect()),
        Value::Struct(f) => {
            let mut m = Map::new();
            for (k, v) in f {
                m.insert(k.clone(), value_json(v));
            }
            Json::Object(m)
        }
        other => json!(other.to_display_string()),
    }
}

fn tag_json(t: &Tag) -> Json {
    json!({
        "id": t.id.to_string(),
        "name": t.name,
        "description": t.description,
        "group0": t.group.family0,
        "group1": t.group.family1,
        "group2": t.group.family2,
        "group3": t.group.family3,
        "print": t.print_value,
        "raw": t.raw_value.to_display_string(),
        "value": value_json(&t.raw_value),
    })
}

fn err(msg: impl std::fmt::Display) -> Json {
    json!({ "error": msg.to_string() })
}

fn options_from(j: &Json) -> Options {
    let mut o = Options::default();
    let b = |k: &str| j.get(k).and_then(Json::as_bool);
    let n = |k: &str| j.get(k).and_then(Json::as_u64);
    if let Some(v) = b("duplicates") { o.duplicates = v; }
    if let Some(v) = b("print_conv") { o.print_conv = v; }
    if let Some(v) = n("fast_scan") { o.fast_scan = v as u8; }
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

fn read_with(opts: &str, f: impl FnOnce(&ExifTool) -> exiftool_rs::error::Result<Vec<Tag>>) -> Json {
    let oj: Json = if opts.is_empty() { json!({}) } else {
        match serde_json::from_str(opts) { Ok(v) => v, Err(e) => return err(e) }
    };
    let et = ExifTool::with_options(options_from(&oj));
    match f(&et) {
        Ok(tags) => json!({ "tags": tags.iter().map(tag_json).collect::<Vec<_>>() }),
        Err(e) => err(e),
    }
}

/// Read all metadata from a file. `opts` is a JSON object (may be empty).
#[no_mangle]
pub unsafe extern "C" fn etruscan_read_file(path: *const c_char, opts: *const c_char) -> *mut c_char {
    finish(catch_unwind(AssertUnwindSafe(|| {
        let (path, opts) = match (cstr(path), cstr(opts)) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => return e,
        };
        read_with(opts, |et| et.extract_info(path))
    })))
}

/// Read metadata from memory. `name` supplies the file name used for type detection.
#[no_mangle]
pub unsafe extern "C" fn etruscan_read_bytes(
    data: *const u8,
    len: usize,
    name: *const c_char,
    opts: *const c_char,
) -> *mut c_char {
    finish(catch_unwind(AssertUnwindSafe(|| {
        let (name, opts) = match (cstr(name), cstr(opts)) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => return e,
        };
        let buf: &[u8] = if len == 0 { &[] } else { std::slice::from_raw_parts(data, len) };
        read_with(opts, |et| et.extract_info_from_bytes(buf, Path::new(name)))
    })))
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
