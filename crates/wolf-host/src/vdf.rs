//! Lossless KeyValues edits: only selected token spans are changed.
use std::{io, ops::Range};
fn invalid() -> io::Error {
    io::Error::other("invalid or ambiguous VDF")
}
#[derive(Clone)]
struct Entry {
    key: String,
    span: Range<usize>,
    value: Value,
}
#[derive(Clone)]
enum Value {
    Text(String, Range<usize>),
    Object(Object),
}
#[derive(Clone)]
struct Object {
    entries: Vec<Entry>,
    close: usize,
}
struct Parser<'a> {
    text: &'a str,
    position: usize,
    count: usize,
}
impl Parser<'_> {
    fn skip(&mut self) {
        loop {
            while self
                .text
                .as_bytes()
                .get(self.position)
                .is_some_and(u8::is_ascii_whitespace)
            {
                self.position += 1;
            }
            if self.text[self.position..].starts_with("//") {
                self.position += self.text[self.position..]
                    .find('\n')
                    .unwrap_or(self.text.len() - self.position);
            } else {
                break;
            }
        }
    }
    fn string(&mut self) -> io::Result<(String, Range<usize>)> {
        self.skip();
        let start = self.position;
        let bytes = self.text.as_bytes();
        if bytes.get(start) == Some(&b'"') {
            self.position += 1;
            let mut decoded = String::new();
            loop {
                let ch = self.text[self.position..]
                    .chars()
                    .next()
                    .ok_or_else(invalid)?;
                self.position += ch.len_utf8();
                match ch {
                    '"' => break,
                    '\\' => {
                        let escaped = self.text[self.position..]
                            .chars()
                            .next()
                            .ok_or_else(invalid)?;
                        self.position += escaped.len_utf8();
                        match escaped {
                            'n' => decoded.push('\n'),
                            'r' => decoded.push('\r'),
                            't' => decoded.push('\t'),
                            '"' | '\\' => decoded.push(escaped),
                            other => {
                                decoded.push('\\');
                                decoded.push(other);
                            }
                        }
                    }
                    '\0' => return Err(invalid()),
                    other => decoded.push(other),
                }
            }
            Ok((decoded, start..self.position))
        } else {
            while let Some(byte) = bytes.get(self.position) {
                if byte.is_ascii_whitespace() || b"{}".contains(byte) {
                    break;
                }
                self.position += 1;
            }
            if self.position == start {
                return Err(invalid());
            }
            Ok((
                self.text[start..self.position].to_owned(),
                start..self.position,
            ))
        }
    }
    fn object(&mut self, nested: bool, depth: usize) -> io::Result<Object> {
        if depth > 64 {
            return Err(invalid());
        }
        let mut entries = Vec::new();
        loop {
            self.skip();
            let next = self.text.as_bytes().get(self.position);
            if next == Some(&b'}') {
                if !nested {
                    return Err(invalid());
                }
                let close = self.position;
                self.position += 1;
                return Ok(Object { entries, close });
            }
            if next.is_none() {
                if nested {
                    return Err(invalid());
                }
                return Ok(Object {
                    entries,
                    close: self.position,
                });
            }
            self.count += 1;
            if self.count > 100000 {
                return Err(invalid());
            }
            let (key, key_span) = self.string()?;
            self.skip();
            let value = if self.text.as_bytes().get(self.position) == Some(&b'{') {
                self.position += 1;
                Value::Object(self.object(true, depth + 1)?)
            } else {
                let (value, span) = self.string()?;
                Value::Text(value, span)
            };
            entries.push(Entry {
                key,
                span: key_span.start..self.position,
                value,
            });
        }
    }
}
fn find<'a>(object: &'a Object, key: &str) -> io::Result<Option<&'a Entry>> {
    let mut matches = object
        .entries
        .iter()
        .filter(|e| e.key.eq_ignore_ascii_case(key));
    let first = matches.next();
    if matches.next().is_some() {
        return Err(invalid());
    }
    Ok(first)
}
fn quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    )
}
pub struct Document {
    text: String,
    root: Object,
}
impl Document {
    pub fn parse(text: &str) -> io::Result<Self> {
        if text.len() > 16 * 1024 * 1024 || text.contains('\0') {
            return Err(invalid());
        }
        let root = Parser {
            text,
            position: 0,
            count: 0,
        }
        .object(false, 0)?;
        Ok(Self {
            text: text.to_owned(),
            root,
        })
    }
    pub fn get(&self, path: &[&str]) -> io::Result<Option<String>> {
        if path.is_empty() {
            return Err(invalid());
        }
        let mut object = &self.root;
        for (i, key) in path.iter().enumerate() {
            let Some(entry) = find(object, key)? else {
                return Ok(None);
            };
            match &entry.value {
                Value::Text(value, _) if i + 1 == path.len() => return Ok(Some(value.clone())),
                Value::Object(child) => object = child,
                _ => return Err(invalid()),
            }
        }
        Ok(None)
    }
    pub fn set(&mut self, path: &[&str], value: &str) -> io::Result<()> {
        if path.is_empty()
            || path.iter().any(|k| k.is_empty() || k.contains('\0'))
            || value.contains('\0')
        {
            return Err(invalid());
        }
        let mut object = &self.root;
        let mut replacement = None;
        for (i, key) in path.iter().enumerate() {
            match find(object, key)? {
                Some(entry) => match &entry.value {
                    Value::Text(_, span) if i + 1 == path.len() => {
                        replacement = Some((span.clone(), quote(value)));
                        break;
                    }
                    Value::Object(child) if i + 1 < path.len() => object = child,
                    _ => return Err(invalid()),
                },
                None => {
                    let mut block = format!("{}\t{}", quote(path.last().unwrap()), quote(value));
                    for key in path[i..path.len() - 1].iter().rev() {
                        block = format!(
                            "{}\n{{\n{}\n}}",
                            quote(key),
                            block
                                .lines()
                                .map(|line| format!("\t{line}"))
                                .collect::<Vec<_>>()
                                .join("\n")
                        );
                    }
                    replacement = Some((object.close..object.close, format!("\n{block}\n")));
                    break;
                }
            }
        }
        let (span, value) = replacement.ok_or_else(invalid)?;
        let mut text = self.text.clone();
        text.replace_range(span, &value);
        *self = Self::parse(&text)?;
        Ok(())
    }
    pub fn remove(&mut self, path: &[&str]) -> io::Result<()> {
        if path.is_empty() {
            return Err(invalid());
        }
        let mut object = &self.root;
        for (i, key) in path.iter().enumerate() {
            let Some(entry) = find(object, key)? else {
                return Ok(());
            };
            if i + 1 == path.len() {
                let mut text = self.text.clone();
                text.replace_range(entry.span.clone(), "");
                *self = Self::parse(&text)?;
                return Ok(());
            }
            match &entry.value {
                Value::Object(child) => object = child,
                _ => return Err(invalid()),
            }
        }
        Err(invalid())
    }
    pub fn text(&self) -> &str {
        &self.text
    }
}
