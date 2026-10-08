//! Pure Steam transformations. The lifecycle adapter owns quiescence and backups.
use crate::vdf::Document;
use std::io;
use wolf_core::{GameSettings, Settings};
fn invalid() -> io::Error {
    io::Error::other("invalid Steam configuration")
}
pub fn launch_options(game: &GameSettings, settings: &Settings) -> io::Result<String> {
    settings.validate().map_err(|_| invalid())?;
    let mut fragments = Vec::new();
    for id in &game.parameters {
        let definition = settings.parameters.get(id).ok_or_else(invalid)?;
        let fragment = definition
            .launch_options
            .replace("%command%", " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if !fragment.is_empty() {
            fragments.push(fragment);
        }
    }
    if !fragments.is_empty() {
        fragments.push("%command%".into());
    }
    Ok(fragments.join(" "))
}
pub fn localconfig(original: &str, settings: &Settings) -> io::Result<String> {
    settings.validate().map_err(|_| invalid())?;
    let mut doc = Document::parse(original)?;
    for (app, game) in &settings.games {
        let options = launch_options(game, settings)?;
        if !options.is_empty() {
            doc.set(
                &[
                    "UserLocalConfigStore",
                    "Software",
                    "Valve",
                    "Steam",
                    "apps",
                    app.as_str(),
                    "LaunchOptions",
                ],
                &options,
            )?;
        }
    }
    Ok(doc.text().to_owned())
}
pub fn compatibility(original: &str, settings: &Settings, proton: &str) -> io::Result<String> {
    settings.validate().map_err(|_| invalid())?;
    if proton.is_empty() || proton.len() > 256 || proton.contains(['\0', '\r', '\n']) {
        return Err(invalid());
    }
    let mut doc = Document::parse(original)?;
    for (app, game) in &settings.games {
        let mut path = vec![
            "InstallConfigStore",
            "Software",
            "Valve",
            "Steam",
            "CompatToolMapping",
            app.as_str(),
        ];
        if game.proton_cachyos {
            for (key, value) in [("name", proton), ("config", ""), ("priority", "250")] {
                path.push(key);
                doc.set(&path, value)?;
                path.pop();
            }
        } else {
            path.push("name");
            let managed = doc.get(&path)?.as_deref() == Some(proton);
            path.pop();
            if managed {
                doc.remove(&path)?;
            }
        }
    }
    Ok(doc.text().to_owned())
}
// Only recognize marker comments outside TOML strings, including multiline strings.
fn markers(text: &str, marker: &str) -> Vec<(usize, usize)> {
    let mut matches = Vec::new();
    let mut delimiter: Option<&[u8]> = None;
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        if delimiter.is_none() && line.trim() == marker {
            matches.push((offset, offset + line.len()));
        }
        let bytes = line.as_bytes();
        let mut at = 0;
        while at < bytes.len() {
            if let Some(quote) = delimiter {
                if quote[0] == b'"' && bytes[at] == b'\\' {
                    at = (at + 2).min(bytes.len());
                    continue;
                }
                if bytes[at..].starts_with(quote) {
                    at += quote.len();
                    delimiter = None;
                } else {
                    at += 1;
                }
            } else {
                if bytes[at] == b'#' {
                    break;
                }
                if bytes[at..].starts_with(b"\"\"\"") {
                    delimiter = Some(b"\"\"\"");
                    at += 3;
                } else if bytes[at..].starts_with(&[39; 3]) {
                    delimiter = Some(&[39; 3]);
                    at += 3;
                } else if bytes[at] == b'"' {
                    delimiter = Some(b"\"");
                    at += 1;
                } else if bytes[at] == b'\'' {
                    delimiter = Some(b"'");
                    at += 1;
                } else {
                    at += 1;
                }
            }
        }
        offset += line.len();
    }
    matches
}
fn section(text: &str, name: &str, generated: &str) -> io::Result<String> {
    let begin = format!("# BEGIN HA-WOLF-MANAGER GENERATED {name} APPS");
    let end = format!("# END HA-WOLF-MANAGER GENERATED {name} APPS");
    let legacy_begin = begin.replace("HA-WOLF-MANAGER", "MACHINE-SETUP");
    let legacy_end = end.replace("HA-WOLF-MANAGER", "MACHINE-SETUP");
    let starts = [markers(text, &begin), markers(text, &legacy_begin)].concat();
    let ends = [markers(text, &end), markers(text, &legacy_end)].concat();
    if starts.len() != ends.len() || starts.len() > 1 {
        return Err(invalid());
    }
    let replacement = format!(
        "{begin}\n{}{end}\n",
        if generated.is_empty() {
            String::new()
        } else {
            format!("{}\n", generated.trim_end())
        }
    );
    let mut result = text.to_owned();
    if let (Some(start), Some(end)) = (starts.first(), ends.first()) {
        if start.0 >= end.0 {
            return Err(invalid());
        }
        result.replace_range(start.0..end.1, &replacement);
    } else {
        let profile_id = match name {
            "MOONLIGHT" => "moonlight-profile-id",
            "USER" => "user",
            _ => return Err(invalid()),
        };
        let headers = markers(text, "[[profiles]]");
        let mut insertion = None;
        for (index, header) in headers.iter().enumerate() {
            let end = headers.get(index + 1).map_or(text.len(), |next| next.0);
            let profile: toml::Table =
                toml::from_str(&text[header.0..end]).map_err(|_| invalid())?;
            let id = profile
                .get("profiles")
                .and_then(toml::Value::as_array)
                .and_then(|profiles| profiles.first())
                .and_then(|profile| profile.get("id"))
                .and_then(toml::Value::as_str);
            if id == Some(profile_id) {
                if insertion.is_some() {
                    return Err(invalid());
                }
                insertion = Some(end);
            }
        }
        let Some(position) = insertion else {
            // Empty sections do not require inventing a missing profile.
            if generated.is_empty() {
                return Ok(result);
            }
            return Err(invalid());
        };
        result.insert_str(position, &format!("\n{replacement}"));
    }
    Ok(result)
}
pub fn generated_sections(original: &str, moonlight: &str, user: &str) -> io::Result<String> {
    original.parse::<toml::Table>().map_err(|_| invalid())?;
    let result = section(&section(original, "MOONLIGHT", moonlight)?, "USER", user)?;
    result.parse::<toml::Table>().map_err(|_| invalid())?;
    Ok(result)
}
