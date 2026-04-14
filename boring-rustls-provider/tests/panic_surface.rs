use std::fs;
use std::path::{Path, PathBuf};

const BANNED_TOKENS: &[&str] = &[
    "unwrap(",
    "expect(",
    "assert!(",
    "assert_eq!(",
    "assert_ne!(",
    "panic!(",
    "unreachable!(",
    "unimplemented!(",
];

struct AllowlistedPanic {
    path_suffix: &'static str,
    message_fragment: &'static str,
    reason: &'static str,
}

const ALLOWLIST: &[AllowlistedPanic] = &[
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/lib.rs",
        message_fragment:
            "boring-rustls-provider is built with the 'fips' feature, but the underlying BoringSSL library is not in FIPS mode",
        reason: "FIPS runtime check; this panic is intentional and required for compliance",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/hash.rs",
        message_fragment: "failed getting hash digest",
        reason: "rustls hash trait is infallible; provider currently cannot surface this as Result",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/hash.rs",
        message_fragment: "failed getting hasher",
        reason: "rustls hash trait is infallible; provider currently cannot surface this as Result",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/hash.rs",
        message_fragment: "hash::Hash is only instantiated with SHA-2 digests",
        reason: "constructor invariant over static hash-provider constants",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/hash.rs",
        message_fragment: "failed getting digest",
        reason: "rustls hash trait is infallible; provider currently cannot surface this as Result",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/hash.rs",
        message_fragment: "failed finishing hash",
        reason: "rustls hash trait is infallible; provider currently cannot surface this as Result",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/hash.rs",
        message_fragment: "failed adding data to hash",
        reason: "rustls hash trait is infallible; provider currently cannot surface this as Result",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/hkdf.rs",
        message_fragment: "HKDF_extract failed",
        reason: "rustls hkdf trait is infallible at this call site",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/hkdf.rs",
        message_fragment: "HMAC failed",
        reason: "rustls hkdf trait is infallible at this call site",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/hkdf.rs",
        message_fragment: "failed hkdf expand",
        reason: "expand_block API is infallible in rustls",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/hmac.rs",
        message_fragment: "failed getting digest",
        reason: "rustls hmac trait is infallible at this call site",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/hmac.rs",
        message_fragment: "failed initializing hmac",
        reason: "rustls hmac trait is infallible at this call site",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/hmac.rs",
        message_fragment: "failed updating hmac",
        reason: "rustls hmac trait is infallible at this call site",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/hmac.rs",
        message_fragment: "failed hmac final",
        reason: "rustls hmac trait is infallible at this call site",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/hmac.rs",
        message_fragment: "failed creating HMAC_CTX",
        reason: "rustls hmac trait is infallible at this call site",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/prf.rs",
        message_fragment: "failed getting digest",
        reason: "rustls tls12::Prf::for_secret is infallible",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/prf.rs",
        message_fragment: "failed calculating prf",
        reason: "rustls tls12::Prf::for_secret is infallible",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/verify/rsa.rs",
        message_fragment: "BoringRsaVerifier only supports configured RSA schemes",
        reason: "static verifier configuration invariant",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/verify/ec.rs",
        message_fragment: "BoringEcVerifier only supports configured ECDSA schemes",
        reason: "static verifier configuration invariant",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/verify/ed.rs",
        message_fragment: "BoringEdVerifier only supports configured EdDSA schemes",
        reason: "static verifier configuration invariant",
    },
    AllowlistedPanic {
        path_suffix: "boring-rustls-provider/src/kx/ex.rs",
        message_fragment: "unsupported key type",
        reason: "static KX type invariant",
    },
];

#[test]
fn no_unreviewed_runtime_panic_constructs() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .expect("crate must be within repository root");

    let mut violations = Vec::new();
    for root in [
        repo_root.join("boring-rustls-provider/src"),
        repo_root.join("boring-additions/src"),
    ] {
        collect_rs_files(&root)
            .expect("must be able to enumerate source files")
            .into_iter()
            .for_each(|path| {
                let rel = path
                    .strip_prefix(repo_root)
                    .expect("path should be under repo root")
                    .to_string_lossy()
                    .to_string();

                let content = fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("failed to read {}: {e}", rel));

                let lines = runtime_lines_only(&content);
                for (i, &(line_no, line)) in lines.iter().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("//") {
                        continue;
                    }

                    for token in BANNED_TOKENS {
                        if !line.contains(token) {
                            continue;
                        }

                        // Collect the full expression for multiline
                        // macros (e.g. panic! spanning several lines)
                        // so the allowlist fragment can match anywhere
                        // in the call, not just the opening line.
                        let full_expr = collect_expression(&lines, i);

                        let allowed = ALLOWLIST.iter().find(|allow| {
                            rel.ends_with(allow.path_suffix)
                                && full_expr.contains(allow.message_fragment)
                        });
                        if allowed.is_none() {
                            violations.push(format!("{rel}:{line_no}: {trimmed}"));
                        }
                    }
                }
            });
    }

    if !violations.is_empty() {
        violations.sort();
        panic!(
            "found unreviewed panic constructs in runtime code:\n{}\n\nIf intentional, add a targeted allowlist entry with rationale.",
            violations.join("\n")
        );
    }
}

#[test]
fn allowlist_entries_have_matching_runtime_call_sites() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .expect("crate must be within repository root");

    let mut missing = Vec::new();
    for entry in ALLOWLIST {
        let path = repo_root.join(entry.path_suffix);
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", entry.path_suffix));
        let lines = runtime_lines_only(&content);
        let found = lines.iter().enumerate().any(|(i, &(_, line))| {
            if !BANNED_TOKENS.iter().any(|t| line.contains(t)) {
                return false;
            }
            let full_expr = collect_expression(&lines, i);
            full_expr.contains(entry.message_fragment)
        });
        if !found {
            missing.push(format!(
                "{} :: '{}' ({})",
                entry.path_suffix, entry.message_fragment, entry.reason
            ));
        }
    }

    if !missing.is_empty() {
        missing.sort();
        panic!(
            "panic allowlist entries no longer match runtime code:\n{}",
            missing.join("\n")
        );
    }
}

fn runtime_lines_only(content: &str) -> Vec<(usize, &str)> {
    let mut lines = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            break;
        }
        lines.push((index + 1, line));
    }
    lines
}

fn collect_rs_files(root: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut files = Vec::new();
    collect_rs_files_rec(root, &mut files)?;
    Ok(files)
}

fn collect_rs_files_rec(root: &Path, acc: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files_rec(&path, acc)?;
            continue;
        }

        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            acc.push(path);
        }
    }

    Ok(())
}

/// Starting from `lines[start]`, join lines until parentheses balance.
/// This lets allowlist fragments match against multiline macro invocations
/// like `panic!("...\n...")`.
fn collect_expression(lines: &[(usize, &str)], start: usize) -> String {
    let mut depth: i32 = 0;
    let mut parts = Vec::new();
    for &(_, line) in &lines[start..] {
        for ch in line.chars() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
        }
        parts.push(line);
        if depth <= 0 {
            break;
        }
    }
    let joined = parts.join(" ");
    // Collapse Rust string-literal line continuations (`\` at end of a
    // string line followed by whitespace on the next) so allowlist
    // fragments can naturally span across them.
    let mut result = String::with_capacity(joined.len());
    let mut chars = joined.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            // If every char from here to the next non-whitespace is
            // whitespace, this is a continuation — drop the `\` and the
            // gap. Otherwise keep the backslash as-is.
            let rest: String = chars.clone().collect();
            if let Some(pos) = rest.find(|c: char| !c.is_whitespace()) {
                for _ in 0..pos {
                    chars.next();
                }
                // don't push the backslash
            } else {
                result.push(ch);
            }
        } else {
            result.push(ch);
        }
    }
    result
}
