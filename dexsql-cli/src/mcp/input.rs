//! Input classification and native-load error envelopes for MCP workers.
use super::{tool_error_result, Config};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

/// Validate source formats and the small DEX headers before preparing indexes.
/// Only headers are read here; the dataset loader owns parsing and inflation.
pub(super) fn validate(paths: &[PathBuf], config: &Config) -> Option<Value> {
    validate_inner(paths, config).map(|mut result| {
        if paths.len() != 1 {
            if let Some(error) = result
                .get_mut("structuredContent")
                .and_then(|value| value.get_mut("error"))
            {
                if error.get("kind").and_then(Value::as_str) == Some("load_failed") {
                    error["input"] = Value::Null;
                }
            }
            if let Some(value) = result.get("structuredContent") {
                let text = value.to_string();
                result["content"][0]["text"] = json!(text);
            }
        }
        result
    })
}

fn validate_inner(paths: &[PathBuf], config: &Config) -> Option<Value> {
    let mut dex_bytes = 0u64;
    for path in paths {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        match extension.as_str() {
            "dex" => {
                let mut input = match File::open(path) {
                    Ok(input) => input,
                    Err(error) => {
                        return Some(tool_error_result(
                            "input_error",
                            &format!("input_error: {error}"),
                        ))
                    }
                };
                let length = input.metadata().map_or(0, |metadata| metadata.len());
                dex_bytes = dex_bytes.saturating_add(length);
                if dex_bytes > config.max_dex_bytes {
                    return Some(dex_quota());
                }
                let mut header = Vec::with_capacity(120);
                if let Err(error) = input.by_ref().take(120).read_to_end(&mut header) {
                    return Some(tool_error_result(
                        "input_error",
                        &format!("input_error: {error}"),
                    ));
                }
                if length < 64 {
                    return Some(load_failed(
                        path,
                        "failed to parse native cache inputs: truncated DEX header field",
                    ));
                }
                let entry = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("classes.dex");
                if let Some(error) = header_error(&header, length) {
                    let source = if error.starts_with("DEX 041")
                        || error == "file too small for DEX 041 header"
                    {
                        format!("failed to load native cache inputs: {error}")
                    } else {
                        format!("failed to parse native cache inputs: failed to parse dex {}:{entry}: {error}", path.display())
                    };
                    return Some(load_failed(path, &source));
                }
            }
            "apk" | "jar" | "zip" => {
                let input = match File::open(path) {
                    Ok(input) => input,
                    Err(error) => {
                        return Some(tool_error_result(
                            "input_error",
                            &format!("input_error: {error}"),
                        ))
                    }
                };
                let mut archive = match ZipArchive::new(input) {
                    Ok(archive) => archive,
                    Err(error) => {
                        let message = match error {
                            zip::result::ZipError::InvalidArchive(message)
                                if message.contains("central directory")
                                    || message.contains("EOCD") =>
                            {
                                "invalid_input: failed to find zip end-of-central-directory"
                                    .to_owned()
                            }
                            _ => format!("invalid_input: {error}"),
                        };
                        return Some(tool_error_result("input_error", &message));
                    }
                };
                let mut saw_dex_suffix = false;
                let mut readable_dex = false;
                let mut first_error = None;
                for index in 0..archive.len() {
                    let mut item = match archive.by_index(index) {
                        Ok(item) => item,
                        Err(error) => {
                            return Some(tool_error_result(
                                "input_error",
                                &format!("invalid_input: {error}"),
                            ))
                        }
                    };
                    let name = item.name().to_owned();
                    saw_dex_suffix |= name.ends_with(".dex");
                    if !dex_member(&name) {
                        continue;
                    }
                    let length = item.size();
                    dex_bytes = dex_bytes.saturating_add(length);
                    if dex_bytes > config.max_dex_bytes {
                        return Some(dex_quota());
                    }
                    let mut header = Vec::with_capacity(120);
                    let read = item.by_ref().take(120).read_to_end(&mut header);
                    let error = match read {
                        Err(error) => Some(format!("failed to read archive member {}:{name}: {error}", path.display())),
                        Ok(_) if length < 8 => Some(format!("invalid DEX header in archive member {}:{name}: file too small for DEX magic", path.display())),
                        Ok(_) if header.get(..4) != Some(b"dex\n") || header.get(7) != Some(&0) =>
                            Some(format!("invalid DEX header in archive member {}:{name}: not a dex file", path.display())),
                        Ok(_) => header_error(&header, length).map(|error|
                            format!("failed to parse dex {}:{name}: {error}", path.display())),
                    };
                    if let Some(error) = error {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    } else {
                        readable_dex = true;
                    }
                }
                if !readable_dex {
                    if let Some(error) = first_error {
                        return Some(load_failed(path, &format!("failed to load+parse native cache inputs: APK/ZIP contains no readable DEX members: {error}")));
                    }
                    if saw_dex_suffix {
                        return Some(load_failed(path, "no dex files found in input"));
                    }
                }
            }
            _ => {
                return Some(tool_error_result(
                    "input_error",
                    &format!("input_error: unsupported input extension: {extension}"),
                ))
            }
        }
    }
    None
}

fn dex_quota() -> Value {
    tool_error_result(
        "input_error",
        "input_error: dataset exceeds --max-dex-bytes (uncompressed DEX bytes)",
    )
}

fn load_failed(path: &Path, source: &str) -> Value {
    let value = json!({"error":{
        "input":{"entry_name":null,"source_name":path},"kind":"load_failed",
        "message":"failed to prepare native input cache","source":source,
        "stage":"load_inputs","statement_index":null,
    }});
    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":true})
}

fn dex_member(name: &str) -> bool {
    name == "classes.dex"
        || name
            .strip_prefix("classes")
            .and_then(|suffix| suffix.strip_suffix(".dex"))
            .is_some_and(|digits| {
                !digits.is_empty() && digits.bytes().all(|digit| digit.is_ascii_digit())
            })
}

fn header_error(header: &[u8], length: u64) -> Option<String> {
    if length < 112 {
        return Some("file too small for dex header".to_owned());
    }
    if header.get(..4) != Some(b"dex\n") || header.get(7) != Some(&0) {
        return Some("not a dex file".to_owned());
    }
    let version = String::from_utf8_lossy(&header[4..7]);
    if !matches!(
        version.as_ref(),
        "035" | "037" | "038" | "039" | "040" | "041"
    ) {
        return Some(format!("unsupported DEX version {version}"));
    }
    let word = |offset: usize| {
        u32::from_le_bytes(
            header[offset..offset + 4]
                .try_into()
                .expect("DEX header word"),
        )
    };
    let expected_size = if version == "041" { 120 } else { 112 };
    if length < expected_size {
        return Some("file too small for DEX 041 header".to_owned());
    }
    if version == "041" && u64::from(word(112)) != length {
        return Some(format!(
            "DEX 041 container_size {} does not match input length {length}",
            word(112)
        ));
    }
    if word(36) != expected_size as u32 {
        return Some(format!(
            "DEX {version} header_size is 0x{:x}, expected 0x{expected_size:x}",
            word(36)
        ));
    }
    if u64::from(word(32)) > length {
        return Some("dex file_size exceeds input bytes".to_owned());
    }
    if word(40) != 0x12345678 {
        return Some("only little-endian dex files are supported".to_owned());
    }
    for (count, offset, width, label) in [
        (word(56), word(60), 4, "string_ids"),
        (word(64), word(68), 4, "type_ids"),
        (word(72), word(76), 12, "proto_ids"),
        (word(80), word(84), 8, "field_ids"),
        (word(88), word(92), 8, "method_ids"),
        (word(96), word(100), 32, "class_defs"),
    ] {
        if count > 0 && u64::from(offset).saturating_add(u64::from(count) * width) > length {
            return Some(format!("{label} exceeds dex file bounds"));
        }
    }
    if word(52) > 0 && u64::from(word(52)).saturating_add(4) > length {
        return Some(format!("read_u32 out of bounds at {}", word(52)));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_members_follow_native_classes_pattern() {
        for name in [
            "classes.dex",
            "classes0.dex",
            "classes1.dex",
            "classes01.dex",
        ] {
            assert!(dex_member(name));
        }
        for name in [
            "CLASSES.dex",
            "classes.DEX",
            "assets/classes.dex",
            "other.dex",
            "classesx.dex",
        ] {
            assert!(!dex_member(name));
        }
    }

    #[test]
    fn header_validation_keeps_native_failure_messages() {
        assert_eq!(
            header_error(&[0; 64], 64).as_deref(),
            Some("file too small for dex header")
        );
        assert_eq!(
            header_error(&[0; 112], 112).as_deref(),
            Some("not a dex file")
        );
        let mut header = [0u8; 120];
        header[..8].copy_from_slice(b"dex\n035\0");
        header[32..36].copy_from_slice(&112u32.to_le_bytes());
        header[36..40].copy_from_slice(&112u32.to_le_bytes());
        header[40..44].copy_from_slice(&0x12345678u32.to_le_bytes());
        assert!(header_error(&header, 112).is_none());
        header[4..7].copy_from_slice(b"999");
        assert_eq!(
            header_error(&header, 112).as_deref(),
            Some("unsupported DEX version 999")
        );
    }
}
