//! C2PA image-signing middleware for the LLM response pipeline.
//!
//! # What this module does
//!
//! When an upstream LLM returns a response containing **base64-encoded images**,
//! this module detects them, decodes them, signs them with C2PA metadata via the
//! `c2pa-signing` crate (using `tokio::task::spawn_blocking` to avoid blocking
//! the async event loop), and splices the signed base64 back into the JSON.
//!
//! If no images are found, or if signing fails for any reason, the **original
//! unmodified response** is returned with zero latency overhead.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use http_body::Frame as HttpFrame;
use http_body_util::BodyStream;
use serde_json::Value;
use tempfile::Builder as TempBuilder;
use tokio::task::spawn_blocking;
use tracing::{debug, warn};

use crate::http::Body;

// ──────────────────────────────────────────────────────────────────────────────
// Public entry-point (buffered / non-streaming path)
// ──────────────────────────────────────────────────────────────────────────────

/// Attempt to sign all base64 images found inside `body` (a full, buffered JSON response).
///
/// Returns the (possibly mutated) `Bytes`. On any error the original bytes are returned
/// unchanged so the caller never has to handle a failure path.
pub async fn stamp_images_in_response_body(body: Bytes) -> Bytes {
	match try_stamp_images_in_body(body.clone()).await {
		Ok(stamped) => stamped,
		Err(e) => {
			warn!(error = %e, "c2pa: failed to stamp image(s); returning original body");
			body
		},
	}
}

async fn try_stamp_images_in_body(body: Bytes) -> anyhow::Result<Bytes> {
	let mut root: Value = serde_json::from_slice(&body)?;
	let count = stamp_images_in_value(&mut root).await?;
	if count == 0 {
		return Ok(body);
	}
	debug!(
		images_stamped = count,
		"c2pa: stamped {count} image(s) in response"
	);
	let new_body = serde_json::to_vec(&root)?;
	Ok(Bytes::from(new_body))
}

// ──────────────────────────────────────────────────────────────────────────────
// JSON tree walker (async)
// ──────────────────────────────────────────────────────────────────────────────

#[allow(clippy::collapsible_if)]
async fn stamp_images_in_value(value: &mut Value) -> anyhow::Result<usize> {
	let mut count = 0usize;
	match value {
		Value::Object(map) => {
			if map.get("type").and_then(Value::as_str) == Some("image_file")
				&& let Some(b64) = map
					.get("image_file")
					.and_then(|v| v.get("data"))
					.and_then(Value::as_str)
					.map(str::to_owned)
			{
				if let Some(signed_b64) = try_sign_b64(&b64).await
					&& let Some(data_val) = map.get_mut("image_file").and_then(|v| v.get_mut("data"))
				{
					*data_val = Value::String(signed_b64);
					count += 1;
				}
			}
			if map.get("type").and_then(Value::as_str) == Some("image_url")
				&& let Some(url) = map
					.get("image_url")
					.and_then(|v| v.get("url"))
					.and_then(Value::as_str)
					.map(str::to_owned)
			{
				if let Some(stamped_uri) = try_stamp_data_uri_str(&url).await
					&& let Some(url_val) = map.get_mut("image_url").and_then(|v| v.get_mut("url"))
				{
					*url_val = Value::String(stamped_uri);
					count += 1;
				}
			}
			if let Some(b64) = map
				.get("b64_json")
				.and_then(Value::as_str)
				.map(str::to_owned)
				&& let Some(signed_b64) = try_sign_b64(&b64).await
			{
				*map.get_mut("b64_json").unwrap() = Value::String(signed_b64);
				count += 1;
			}
			let keys: Vec<String> = map.keys().cloned().collect();
			for k in keys {
				if let Some(v) = map.get_mut(&k) {
					count += Box::pin(stamp_images_in_value(v)).await?;
				}
			}
		},
		Value::Array(arr) => {
			for v in arr.iter_mut() {
				count += Box::pin(stamp_images_in_value(v)).await?;
			}
		},
		Value::String(s) => {
			if s.starts_with("data:image/")
				&& let Some(stamped) = try_stamp_data_uri_str(s).await
			{
				*s = stamped;
				count += 1;
			}
		},
		_ => {},
	}
	Ok(count)
}

// ──────────────────────────────────────────────────────────────────────────────
// Streaming body wrapper
// ──────────────────────────────────────────────────────────────────────────────

/// Wrap a streaming `Body` so that any SSE chunks containing base64 images
/// are transparently C2PA-signed before being forwarded to the client.
pub fn wrap_streaming_body(body: Body) -> Body {
	use futures_util::StreamExt;

	let stream = BodyStream::new(body).map(|frame_result| match frame_result {
		Err(e) => Err(e),
		Ok(frame) => {
			if let Some(data) = frame.data_ref()
				&& sse_event_likely_has_image(data)
			{
				let stamped = stamp_sse_event_blocking(data.clone());
				return Ok(HttpFrame::data(stamped));
			}
			Ok(frame)
		},
	});
	Body::new(http_body_util::StreamBody::new(stream))
}

// ──────────────────────────────────────────────────────────────────────────────
// SSE helpers
// ──────────────────────────────────────────────────────────────────────────────

fn sse_event_likely_has_image(chunk: &[u8]) -> bool {
	chunk
		.windows(b"image_file".len())
		.any(|w| w == b"image_file")
		|| chunk.windows(b"image_url".len()).any(|w| w == b"image_url")
		|| chunk.windows(b"b64_json".len()).any(|w| w == b"b64_json")
		|| chunk
			.windows(b"data:image".len())
			.any(|w| w == b"data:image")
}

fn stamp_sse_event_blocking(chunk: Bytes) -> Bytes {
	let text = match std::str::from_utf8(&chunk) {
		Ok(s) => s,
		Err(_) => return chunk,
	};
	let mut output = String::with_capacity(text.len() + 64);
	let mut changed = false;
	for line in text.lines() {
		if let Some(json_str) = line.strip_prefix("data: ") {
			if json_str.trim() == "[DONE]" {
				output.push_str(line);
				output.push('\n');
				continue;
			}
			match serde_json::from_str::<Value>(json_str) {
				Ok(mut val) => {
					let c = stamp_images_in_value_sync(&mut val);
					if c > 0 {
						changed = true;
					}
					match serde_json::to_string(&val) {
						Ok(new_json) => {
							output.push_str("data: ");
							output.push_str(&new_json);
							output.push('\n');
						},
						Err(_) => {
							output.push_str(line);
							output.push('\n');
						},
					}
				},
				Err(_) => {
					output.push_str(line);
					output.push('\n');
				},
			}
		} else {
			output.push_str(line);
			output.push('\n');
		}
	}
	if !output.ends_with('\n') {
		output.push('\n');
	}
	if changed {
		Bytes::from(output.into_bytes())
	} else {
		chunk
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Synchronous JSON tree walker (for SSE blocking path)
// ──────────────────────────────────────────────────────────────────────────────

#[allow(clippy::collapsible_if)]
fn stamp_images_in_value_sync(value: &mut Value) -> usize {
	let mut count = 0usize;
	match value {
		Value::Object(map) => {
			if map.get("type").and_then(Value::as_str) == Some("image_file")
				&& let Some(b64) = map
					.get("image_file")
					.and_then(|v| v.get("data"))
					.and_then(Value::as_str)
					.map(str::to_owned)
			{
				if let Some(signed) = try_sign_b64_sync(&b64)
					&& let Some(v) = map.get_mut("image_file").and_then(|v| v.get_mut("data"))
				{
					*v = Value::String(signed);
					count += 1;
				}
			}
			if map.get("type").and_then(Value::as_str) == Some("image_url")
				&& let Some(url) = map
					.get("image_url")
					.and_then(|v| v.get("url"))
					.and_then(Value::as_str)
					.map(str::to_owned)
			{
				if let Some(stamped) = try_stamp_data_uri_str_sync(&url)
					&& let Some(v) = map.get_mut("image_url").and_then(|v| v.get_mut("url"))
				{
					*v = Value::String(stamped);
					count += 1;
				}
			}
			if let Some(b64) = map
				.get("b64_json")
				.and_then(Value::as_str)
				.map(str::to_owned)
				&& let Some(signed) = try_sign_b64_sync(&b64)
			{
				*map.get_mut("b64_json").unwrap() = Value::String(signed);
				count += 1;
			}
			let keys: Vec<String> = map.keys().cloned().collect();
			for k in keys {
				if let Some(v) = map.get_mut(&k) {
					count += stamp_images_in_value_sync(v);
				}
			}
		},
		Value::Array(arr) => {
			for v in arr.iter_mut() {
				count += stamp_images_in_value_sync(v);
			}
		},
		Value::String(s) => {
			if s.starts_with("data:image/")
				&& let Some(stamped) = try_stamp_data_uri_str_sync(s)
			{
				*s = stamped;
				count += 1;
			}
		},
		_ => {},
	}
	count
}

// ──────────────────────────────────────────────────────────────────────────────
// C2PA signing helpers (async — via spawn_blocking)
// ──────────────────────────────────────────────────────────────────────────────

async fn try_sign_b64(b64: &str) -> Option<String> {
	let b64_owned = b64.to_owned();
	match spawn_blocking(move || try_sign_b64_sync(&b64_owned)).await {
		Ok(result) => result,
		Err(e) => {
			warn!(error = %e, "c2pa: spawn_blocking panicked during image signing");
			None
		},
	}
}

async fn try_stamp_data_uri_str(data_uri: &str) -> Option<String> {
	let uri_owned = data_uri.to_owned();
	match spawn_blocking(move || try_stamp_data_uri_str_sync(&uri_owned)).await {
		Ok(result) => result,
		Err(e) => {
			warn!(error = %e, "c2pa: spawn_blocking panicked during data URI signing");
			None
		},
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// C2PA signing helpers (sync — called inside spawn_blocking or SSE path)
// ──────────────────────────────────────────────────────────────────────────────

/// Decode `b64` → temp file → C2PA sign → re-encode → return new base64.
fn try_sign_b64_sync(b64: &str) -> Option<String> {
	let image_bytes = match B64.decode(b64.trim()) {
		Ok(b) => b,
		Err(e) => {
			debug!(error = %e, "c2pa: base64 decode failed; skipping");
			return None;
		},
	};
	let ext = detect_image_format(&image_bytes)?;
	let signed = sign_raw_image(&image_bytes, ext)?;
	Some(B64.encode(&signed))
}

fn try_stamp_data_uri_str_sync(data_uri: &str) -> Option<String> {
	let b64_part = extract_data_uri_b64(data_uri)?;
	let mime = extract_data_uri_mime(data_uri).unwrap_or("image/jpeg");
	let image_bytes = B64.decode(b64_part.trim()).ok()?;
	let ext = detect_image_format(&image_bytes)?;
	let signed = sign_raw_image(&image_bytes, ext)?;
	Some(format!("data:{};base64,{}", mime, B64.encode(&signed)))
}

/// Write raw image bytes to a temp file, sign via `c2pa_signing::sign_image`,
/// read back the signed bytes.
fn sign_raw_image(image_bytes: &[u8], ext: &str) -> Option<Vec<u8>> {
	let suffix = format!(".{ext}");

	let input_tmp = TempBuilder::new()
		.prefix("agw-c2pa-in-")
		.suffix(&suffix)
		.tempfile()
		.map_err(|e| warn!(error = %e, "c2pa: failed to create temp input file"))
		.ok()?;

	// c2pa 0.78 requires the output path to NOT exist yet, so we create a
	// temp dir and construct a path inside it rather than using tempfile().
	let output_dir = TempBuilder::new()
		.prefix("agw-c2pa-out-")
		.tempdir()
		.map_err(|e| warn!(error = %e, "c2pa: failed to create temp output dir"))
		.ok()?;
	let output_path = output_dir.path().join(format!("signed{suffix}"));

	std::fs::write(input_tmp.path(), image_bytes)
		.map_err(|e| warn!(error = %e, "c2pa: failed to write temp input file"))
		.ok()?;

	use c2pa_signing::{SignOutcome, sign_image};
	match sign_image(input_tmp.path(), &output_path) {
		Ok(SignOutcome::Signed) => {},
		Ok(SignOutcome::NoChange) => {
			debug!("c2pa: image already signed; no change");
			return None;
		},
		Err(e) => {
			warn!(error = %e, "c2pa: signing failed");
			return None;
		},
	}

	std::fs::read(&output_path)
		.map_err(|e| warn!(error = %e, "c2pa: failed to read signed output file"))
		.ok()
}

// ──────────────────────────────────────────────────────────────────────────────
// Utility helpers
// ──────────────────────────────────────────────────────────────────────────────

fn detect_image_format(bytes: &[u8]) -> Option<&'static str> {
	if bytes.starts_with(&[0xFF, 0xD8]) {
		Some("jpg")
	} else if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
		Some("png")
	} else {
		None
	}
}

fn extract_data_uri_b64(data_uri: &str) -> Option<&str> {
	let comma = data_uri.find(',')?;
	if !data_uri[..comma].contains("base64") {
		return None;
	}
	Some(&data_uri[comma + 1..])
}

fn extract_data_uri_mime(data_uri: &str) -> Option<&str> {
	let without_data = data_uri.strip_prefix("data:")?;
	let semi = without_data.find(';')?;
	Some(&without_data[..semi])
}

#[cfg(test)]
fn find_sse_boundary(buf: &[u8]) -> Option<usize> {
	buf.windows(2).position(|w| w == b"\n\n")
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_detect_image_format_jpeg() {
		assert_eq!(detect_image_format(&[0xFF, 0xD8, 0x00]), Some("jpg"));
	}

	#[test]
	fn test_detect_image_format_png() {
		assert_eq!(
			detect_image_format(&[0x89, 0x50, 0x4E, 0x47, 0x00]),
			Some("png")
		);
	}

	#[test]
	fn test_detect_image_format_unknown() {
		assert_eq!(detect_image_format(b"hello"), None);
	}

	#[test]
	fn test_extract_data_uri_b64() {
		assert_eq!(
			extract_data_uri_b64("data:image/jpeg;base64,/9j/abc"),
			Some("/9j/abc")
		);
	}

	#[test]
	fn test_extract_data_uri_b64_no_marker() {
		assert_eq!(extract_data_uri_b64("data:image/svg+xml,<svg/>"), None);
	}

	#[test]
	fn test_extract_data_uri_mime() {
		assert_eq!(
			extract_data_uri_mime("data:image/png;base64,abc"),
			Some("image/png")
		);
	}

	#[test]
	fn test_sse_boundary() {
		assert_eq!(find_sse_boundary(b"data: {}\n\ndata:"), Some(8));
		assert_eq!(find_sse_boundary(b"data: {}"), None);
	}

	#[test]
	fn test_sse_likely_has_image() {
		assert!(sse_event_likely_has_image(
			b"data: {\"type\":\"image_file\"}"
		));
		assert!(sse_event_likely_has_image(b"data: {\"b64_json\":\"abc\"}"));
		assert!(!sse_event_likely_has_image(b"data: {\"type\":\"text\"}"));
	}

	#[tokio::test]
	async fn test_stamp_no_images_passthrough() {
		let body = Bytes::from(r#"{"model":"gpt-4o","choices":[{"message":{"content":"hi"}}]}"#);
		let result = stamp_images_in_response_body(body.clone()).await;
		assert_eq!(result, body, "body with no images should be unchanged");
	}

	#[tokio::test]
	async fn test_stamp_non_json_passthrough() {
		let body = Bytes::from("not json");
		let result = stamp_images_in_response_body(body.clone()).await;
		assert_eq!(result, body, "non-JSON body should be unchanged");
	}

	#[tokio::test]
	async fn test_stamp_invalid_b64_passthrough() {
		let body = Bytes::from(r#"{"data":[{"b64_json":"!!!not-valid-base64!!!"}]}"#);
		let result = stamp_images_in_response_body(body.clone()).await;
		assert_eq!(result, body, "invalid base64 should be unchanged");
	}

	// ── End-to-end tests using real JPEG ─────────────────────────────────

	fn load_test_image_b64() -> String {
		let fixture =
			std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_image.jpg");
		assert!(
			fixture.exists(),
			"Test fixture missing: {}",
			fixture.display()
		);
		let raw = std::fs::read(&fixture).expect("read test image");
		B64.encode(&raw)
	}

	#[tokio::test]
	async fn test_e2e_b64_json_image_signed() {
		let b64 = load_test_image_b64();
		let body_json = serde_json::json!({
			"created": 1234567890,
			"data": [{"b64_json": b64, "revised_prompt": "a test image"}]
		});
		let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());
		let result = stamp_images_in_response_body(body.clone()).await;
		assert_ne!(result, body, "body should be modified after C2PA stamping");

		let result_json: Value = serde_json::from_slice(&result).expect("parse result JSON");
		let signed_b64 = result_json["data"][0]["b64_json"]
			.as_str()
			.expect("b64_json string");
		assert_ne!(signed_b64, b64, "base64 should differ after signing");

		let signed_bytes = B64.decode(signed_b64).expect("decode signed base64");
		assert!(
			signed_bytes.starts_with(&[0xFF, 0xD8]),
			"should be valid JPEG"
		);
		let original_bytes = B64.decode(&b64).expect("decode original");
		assert!(
			signed_bytes.len() > original_bytes.len(),
			"signed JPEG ({}) should be larger than original ({})",
			signed_bytes.len(),
			original_bytes.len(),
		);
	}

	#[tokio::test]
	async fn test_e2e_image_file_response_api() {
		let b64 = load_test_image_b64();
		let body_json = serde_json::json!({
			"id": "resp_001", "status": "completed", "model": "gpt-4o",
			"output": [{"type": "message", "content": [{
				"type": "image_file",
				"image_file": {"data": b64, "mime_type": "image/jpeg"}
			}]}]
		});
		let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());
		let result = stamp_images_in_response_body(body.clone()).await;
		assert_ne!(result, body);
		let result_json: Value = serde_json::from_slice(&result).expect("parse");
		let signed_b64 = result_json["output"][0]["content"][0]["image_file"]["data"]
			.as_str()
			.expect("image_file.data");
		assert_ne!(signed_b64, b64);
		let signed_bytes = B64.decode(signed_b64).expect("decode");
		assert!(signed_bytes.starts_with(&[0xFF, 0xD8]));
	}

	#[tokio::test]
	async fn test_e2e_data_uri_string() {
		let b64 = load_test_image_b64();
		let data_uri = format!("data:image/jpeg;base64,{b64}");
		let body_json = serde_json::json!({
			"model": "gpt-4o",
			"choices": [{"message": {"content": data_uri, "role": "assistant"}}]
		});
		let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());
		let result = stamp_images_in_response_body(body.clone()).await;
		assert_ne!(result, body);
		let result_json: Value = serde_json::from_slice(&result).expect("parse");
		let signed_uri = result_json["choices"][0]["message"]["content"]
			.as_str()
			.expect("content");
		assert!(signed_uri.starts_with("data:image/jpeg;base64,"));
		assert_ne!(signed_uri, data_uri);
	}

	#[tokio::test]
	async fn test_e2e_no_double_sign() {
		let b64 = load_test_image_b64();
		let body_json = serde_json::json!({"data": [{"b64_json": b64}]});
		let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());
		let first_result = stamp_images_in_response_body(body).await;

		let second_result = stamp_images_in_response_body(first_result.clone()).await;
		assert_eq!(
			first_result, second_result,
			"already-signed should not change again"
		);
	}

	#[tokio::test]
	async fn test_e2e_mixed_content_only_images_signed() {
		let b64 = load_test_image_b64();
		let body_json = serde_json::json!({
			"model": "gpt-4o",
			"choices": [{"message": {"content": "Hello world", "role": "assistant"}}],
			"data": [{"b64_json": b64, "revised_prompt": "a cat"}]
		});
		let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());
		let result = stamp_images_in_response_body(body.clone()).await;
		assert_ne!(result, body);
		let result_json: Value = serde_json::from_slice(&result).expect("parse");
		assert_eq!(
			result_json["choices"][0]["message"]["content"],
			"Hello world"
		);
		assert_ne!(result_json["data"][0]["b64_json"].as_str().unwrap(), b64);
	}
}
