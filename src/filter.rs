//! Display-only filtering for decoded PostgreSQL messages.
//!
//! Expressions contain whitespace-separated conditions with AND semantics:
//! `client=127.0.0.1 port=40005 type=Query|DataRow keyword="order id"`.
//! Message-type lists use `,` or `|` and accept `*` / `?` globs. Bare terms
//! are treated as keywords. Matching is case-insensitive for types and text.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageDirection {
    FrontendToBackend,
    BackendToFrontend,
}

/// A decoded message plus the structured fields used by display filters.
#[derive(Clone, Debug)]
pub struct DisplayMessage {
    pub rendered: String,
    pub client: SocketAddr,
    pub direction: MessageDirection,
    pub kind: String,
    pub text: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DisplayFilter {
    expression: String,
    client_ip: Option<IpAddr>,
    client_port: Option<u16>,
    message_types: Vec<String>,
    keywords: Vec<String>,
    direction: Option<MessageDirection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterParseError(String);

impl fmt::Display for FilterParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FilterParseError {}

impl DisplayFilter {
    pub fn parse(expression: &str) -> Result<Self, FilterParseError> {
        let mut filter = Self {
            expression: expression.trim().to_string(),
            ..Self::default()
        };
        for term in tokenize(expression)? {
            let Some((field, value)) = split_condition(&term) else {
                filter.keywords.push(term.to_lowercase());
                continue;
            };
            if value.is_empty() {
                return Err(FilterParseError(format!(
                    "filter field '{field}' requires a value"
                )));
            }
            match field.to_ascii_lowercase().as_str() {
                "client" | "ip" | "client-ip" | "client_ip" => {
                    filter.client_ip =
                        Some(value.parse().map_err(|_| {
                            FilterParseError(format!("invalid client IP '{value}'"))
                        })?);
                }
                "port" | "client-port" | "client_port" => {
                    filter.client_port =
                        Some(value.parse().map_err(|_| {
                            FilterParseError(format!("invalid client port '{value}'"))
                        })?);
                }
                "type" | "kind" | "message" => {
                    let patterns: Vec<String> = value
                        .split([',', '|'])
                        .map(str::trim)
                        .filter(|part| !part.is_empty())
                        .map(str::to_lowercase)
                        .collect();
                    if patterns.is_empty() {
                        return Err(FilterParseError("message type list cannot be empty".into()));
                    }
                    filter.message_types.extend(patterns);
                }
                "keyword" | "text" | "contains" => {
                    filter.keywords.push(value.to_lowercase());
                }
                "direction" | "dir" => {
                    filter.direction = Some(parse_direction(value)?);
                }
                _ => {
                    return Err(FilterParseError(format!("unknown filter field '{field}'")));
                }
            }
        }
        Ok(filter)
    }

    pub fn expression(&self) -> &str {
        &self.expression
    }

    pub fn is_empty(&self) -> bool {
        self.client_ip.is_none()
            && self.client_port.is_none()
            && self.message_types.is_empty()
            && self.keywords.is_empty()
            && self.direction.is_none()
    }

    pub fn matches(&self, message: &DisplayMessage) -> bool {
        if self.client_ip.is_some_and(|ip| message.client.ip() != ip)
            || self
                .client_port
                .is_some_and(|port| message.client.port() != port)
            || self
                .direction
                .is_some_and(|direction| message.direction != direction)
        {
            return false;
        }

        if !self.message_types.is_empty() {
            let kind = message.kind.to_lowercase();
            if !self
                .message_types
                .iter()
                .any(|pattern| glob_matches(pattern, &kind))
            {
                return false;
            }
        }

        if self.keywords.is_empty() {
            return true;
        }
        let text = message.text.to_lowercase();
        self.keywords.iter().all(|keyword| text.contains(keyword))
    }
}

impl FromStr for DisplayFilter {
    type Err = FilterParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn split_condition(term: &str) -> Option<(&str, &str)> {
    term.find(['=', ':'])
        .map(|index| (&term[..index], &term[index + 1..]))
}

fn parse_direction(value: &str) -> Result<MessageDirection, FilterParseError> {
    match value.to_ascii_lowercase().as_str() {
        "in" | "f2b" | "frontend" | "frontend-to-backend" | "f→b" => {
            Ok(MessageDirection::FrontendToBackend)
        }
        "out" | "b2f" | "backend" | "backend-to-frontend" | "b→f" => {
            Ok(MessageDirection::BackendToFrontend)
        }
        _ => Err(FilterParseError(format!(
            "invalid direction '{value}' (expected in/f2b or out/b2f)"
        ))),
    }
}

fn tokenize(expression: &str) -> Result<Vec<String>, FilterParseError> {
    let mut terms = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for ch in expression.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                terms.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if escaped {
        return Err(FilterParseError("filter ends with an escape".into()));
    }
    if quote.is_some() {
        return Err(FilterParseError("unterminated quoted filter value".into()));
    }
    if !current.is_empty() {
        terms.push(current);
    }
    Ok(terms)
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v) = (0, 0);
    let (mut star, mut retry) = (None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            retry += 1;
            v = retry;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> DisplayMessage {
        DisplayMessage {
            rendered: "line".into(),
            client: "127.0.0.1:40005".parse().unwrap(),
            direction: MessageDirection::FrontendToBackend,
            kind: "Query".into(),
            text: "SELECT * FROM orders WHERE id = 42".into(),
        }
    }

    #[test]
    fn combines_conditions_with_and_semantics() {
        let filter = DisplayFilter::parse(
            "client=127.0.0.1 port=40005 type=Query|DataRow keyword=orders dir=in",
        )
        .unwrap();
        assert!(filter.matches(&message()));

        let mut other = message();
        other.client = "127.0.0.1:40006".parse().unwrap();
        assert!(!filter.matches(&other));
    }

    #[test]
    fn supports_quoted_keywords_bare_terms_and_type_globs() {
        let filter = DisplayFilter::parse("type=Qu* keyword='from orders' 42").unwrap();
        assert!(filter.matches(&message()));
    }

    #[test]
    fn matching_is_case_insensitive() {
        let filter = DisplayFilter::parse("type=query keyword=select").unwrap();
        assert!(filter.matches(&message()));
    }

    #[test]
    fn rejects_invalid_fields_and_values() {
        assert!(DisplayFilter::parse("client=localhost").is_err());
        assert!(DisplayFilter::parse("port=99999").is_err());
        assert!(DisplayFilter::parse("unknown=value").is_err());
        assert!(DisplayFilter::parse("keyword='unterminated").is_err());
    }
}
