use std::path::Path;
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Context, Result};
use c2pa::{create_signer, Builder, Reader, SigningAlg};

// ── Core signing library ───────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub enum SignOutcome {
	Signed,
	NoChange,
}

pub struct SignerContext {
	manifest_json: Mutex<serde_json::Value>,
	private_key: Vec<u8>,
	certificate: Vec<u8>,
}

static SIGNER_CONTEXT: OnceLock<Result<SignerContext>> = OnceLock::new();

fn load_signer_context() -> Result<SignerContext> {
	// Prefer runtime-configured assets directory (useful for containers).
	// Falls back to the crate-local `assets` directory when running from source.
	let assets_dir = std::env::var_os("C2PA_ASSETS_DIR")
		.map(std::path::PathBuf::from)
		.unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("assets"));

	let load_asset = |filename: &str| {
		let path = assets_dir.join(filename);
		std::fs::read(&path).with_context(|| format!("Failed to read {}", path.display()))
	};

	let manifest_path = assets_dir.join("manifest.json");
	let file = std::fs::File::open(&manifest_path)
		.with_context(|| format!("Failed to open {}", manifest_path.display()))?;
	let manifest_json: serde_json::Value =
		serde_json::from_reader(file).context("Failed to parse manifest JSON")?;

	Ok(SignerContext {
		manifest_json: Mutex::new(manifest_json),
		private_key: load_asset("private.key")?,
		certificate: load_asset("certificate.pem")?,
	})
}

pub fn get_signer_context() -> Result<&'static SignerContext> {
	SIGNER_CONTEXT
		.get_or_init(load_signer_context)
		.as_ref()
		.map_err(|e| anyhow!("Signer context initialization failed: {:#}", e))
}

impl SignerContext {
	fn build_manifest_json(&self) -> Result<String> {
		let mut template = self
			.manifest_json
			.lock()
			.map_err(|_| anyhow!("Failed to lock manifest template"))?
			.clone();

		// Update the "when" timestamp in the c2pa.created action
		if let Some(assertions) = template
			.get_mut("assertions")
			.and_then(|v| v.as_array_mut())
		{
			for assertion in assertions.iter_mut() {
				if assertion.get("label").and_then(|l| l.as_str()) == Some("c2pa.actions") {
					if let Some(actions) = assertion
						.pointer_mut("/data/actions")
						.and_then(|v| v.as_array_mut())
					{
						for action in actions.iter_mut() {
							if action.get("action").and_then(|s| s.as_str()) == Some("c2pa.created") {
								if let Some(when) = action.get_mut("when") {
									*when = serde_json::Value::String(chrono::Utc::now().to_rfc3339());
								}
							}
						}
					}
				}
			}
		}

		serde_json::to_string(&template).context("Failed to serialize manifest JSON")
	}

	pub fn sign(&self, input_path: &Path, output_path: &Path) -> Result<SignOutcome> {
		// Check if the image already has a C2PA manifest
		if let Ok(reader) = Reader::from_file(input_path) {
			if reader.active_manifest().is_some() {
				return Ok(SignOutcome::NoChange);
			}
		}

		let manifest_json = self.build_manifest_json()?;

		let mut builder =
			Builder::from_json(&manifest_json).context("Failed to create Builder from JSON")?;

		let signer = create_signer::from_keys(
			&self.certificate,
			&self.private_key,
			SigningAlg::Es256,
			None,
		)
		.context("Failed to create signer")?;

		builder
			.sign_file(signer.as_ref(), input_path, output_path)
			.context("Failed to sign file")?;

		Ok(SignOutcome::Signed)
	}
}

pub fn sign_image(input_path: &Path, output_path: &Path) -> Result<SignOutcome> {
	get_signer_context()?.sign(input_path, output_path)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use std::path::PathBuf;

	#[test]
	fn test_sign_image_generates_manifest() {
		let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		let input_path = manifest_dir.join("tests/fixtures/image.jpg");
		let output_path = std::env::temp_dir().join("test_signed_c2pa_signing.jpg");

		assert!(
			input_path.exists(),
			"Test image not found at {:?}",
			input_path
		);
		let _ = std::fs::remove_file(&output_path);

		let result = sign_image(&input_path, &output_path).expect("Failed to sign image");
		assert_eq!(result, SignOutcome::Signed);
		assert!(output_path.exists());

		// Verify the signed image has an active manifest
		let reader = Reader::from_file(&output_path).expect("Failed to read signed image");
		assert!(reader.active_manifest().is_some());

		// Idempotency: already-signed image → NoChange
		let result_again = sign_image(&output_path, &output_path).expect("Failed to sign again");
		assert_eq!(result_again, SignOutcome::NoChange);
	}
}
