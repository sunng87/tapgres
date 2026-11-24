//! Display-only filtering for decoded PostgreSQL messages.
//!
//! The language is a deliberately small, typed subset of Wireshark display
//! filters. It supports comparisons, set membership, substring and regular
//! expression matching, boolean operators, and parentheses:
//!
//! ```text
//! client.ip == 127.0.0.1 and client.port == 40005
//! client.port >= 40000 and client.port < 50000
//! message.type in {"Query", "DataRow"} and message.text contains "orders"
//! not (message.direction == "b2f" or message.type matches r"^Error")
//! ```
//!
//! Ordered comparisons (`<`, `<=`, `>`, `>=`) apply to the numeric
//! `client.port` field only.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use regex::{Regex, RegexBuilder};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageDirection {
    FrontendToBackend,
    BackendToFrontend,
}

/// A decoded message plus the structured fields used by display filters.
#[derive(Clone, Debug)]
pub struct DisplayMessage {
    /// Original capture time in RFC 3339 with millisecond precision. Kept
    /// separately from `rendered` so saved sessions preserve real timestamps.
    pub timestamp: String,
    pub rendered: String,
    pub client: SocketAddr,
    pub direction: MessageDirection,
    pub kind: String,
    pub text: String,
}

/// A parsed display filter. Parsing and regular-expression compilation happen
/// once; evaluating a message performs no allocation.
#[derive(Clone, Debug, Default)]
pub struct DisplayFilter {
    expression: String,
    root: Option<Expr>,
}

#[derive(Clone, Debug)]
enum Expr {
    Predicate(Predicate),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

impl Expr {
    fn matches(&self, message: &DisplayMessage) -> bool {
        match self {
            Self::Predicate(predicate) => predicate.matches(message),
            Self::And(left, right) => left.matches(message) && right.matches(message),
            Self::Or(left, right) => left.matches(message) || right.matches(message),
            Self::Not(inner) => !inner.matches(message),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Field {
    ClientIp,
    ClientPort,
    MessageType,
    MessageText,
    MessageDirection,
}

impl Field {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "client.ip" => Some(Self::ClientIp),
            "client.port" => Some(Self::ClientPort),
            "message.type" => Some(Self::MessageType),
            "message.text" => Some(Self::MessageText),
            "message.direction" => Some(Self::MessageDirection),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::ClientIp => "client.ip",
            Self::ClientPort => "client.port",
            Self::MessageType => "message.type",
            Self::MessageText => "message.text",
            Self::MessageDirection => "message.direction",
        }
    }

    fn is_text(self) -> bool {
        matches!(self, Self::MessageType | Self::MessageText)
    }

    fn equals(self, value: &Value, message: &DisplayMessage) -> bool {
        match (self, value) {
            (Self::ClientIp, Value::Ip(expected)) => message.client.ip() == *expected,
            (Self::ClientPort, Value::Port(expected)) => message.client.port() == *expected,
            (Self::MessageType, Value::Text(expected)) => message.kind == *expected,
            (Self::MessageText, Value::Text(expected)) => message.text == *expected,
            (Self::MessageDirection, Value::Direction(expected)) => message.direction == *expected,
            _ => false,
        }
    }

    fn text(self, message: &DisplayMessage) -> Option<&str> {
        match self {
            Self::MessageType => Some(&message.kind),
            Self::MessageText => Some(&message.text),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
enum Value {
    Ip(IpAddr),
    Port(u16),
    Text(String),
    Direction(MessageDirection),
}

/// Ordered comparison operator, for numeric fields (`client.port`).
#[derive(Clone, Copy, Debug)]
enum OrdOp {
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

impl OrdOp {
    fn test(self, actual: u16, bound: u16) -> bool {
        match self {
            Self::Less => actual < bound,
            Self::LessEqual => actual <= bound,
            Self::Greater => actual > bound,
            Self::GreaterEqual => actual >= bound,
        }
    }
}

#[derive(Clone, Debug)]
enum Comparison {
    Equal(Value),
    NotEqual(Value),
    /// An ordered comparison against a port number (`client.port > 40000`).
    Ordered(OrdOp, u16),
    Contains(String),
    Matches(Regex),
    In(Vec<Value>),
}

#[derive(Clone, Debug)]
struct Predicate {
    field: Field,
    comparison: Comparison,
}

impl Predicate {
    fn matches(&self, message: &DisplayMessage) -> bool {
        match &self.comparison {
            Comparison::Equal(value) => self.field.equals(value, message),
            Comparison::NotEqual(value) => !self.field.equals(value, message),
            Comparison::Ordered(op, bound) => op.test(message.client.port(), *bound),
            Comparison::Contains(needle) => self
                .field
                .text(message)
                .is_some_and(|value| value.contains(needle)),
            Comparison::Matches(regex) => self
                .field
                .text(message)
                .is_some_and(|value| regex.is_match(value)),
            Comparison::In(values) => values.iter().any(|value| self.field.equals(value, message)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterParseError {
    message: String,
    position: usize,
}

impl FilterParseError {
    fn new(position: usize, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            position,
        }
    }
}

impl fmt::Display for FilterParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.message, self.position)
    }
}

impl std::error::Error for FilterParseError {}

impl DisplayFilter {
    pub fn parse(expression: &str) -> Result<Self, FilterParseError> {
        let expression = expression.trim();
        if expression.is_empty() {
            return Ok(Self::default());
        }
        let tokens = lex(expression)?;
        let root = Parser::new(tokens).parse()?;
        Ok(Self {
            expression: expression.to_string(),
            root: Some(root),
        })
    }

    pub fn expression(&self) -> &str {
        &self.expression
    }

    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    pub fn matches(&self, message: &DisplayMessage) -> bool {
        self.root
            .as_ref()
            .is_none_or(|expression| expression.matches(message))
    }
}

impl FromStr for DisplayFilter {
    type Err = FilterParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TokenKind {
    Word(String),
    String(String),
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Contains,
    Matches,
    In,
    And,
    Or,
    Not,
    LeftParen,
    RightParen,
    LeftBrace,
    RightBrace,
    Comma,
    End,
}

#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    position: usize,
}

fn lex(input: &str) -> Result<Vec<Token>, FilterParseError> {
    let mut tokens = Vec::new();
    let mut position = 0;
    while position < input.len() {
        let current = input[position..].chars().next().unwrap();
        if current.is_whitespace() {
            position += current.len_utf8();
            continue;
        }

        let start = position;
        let simple = match current {
            '(' => Some(TokenKind::LeftParen),
            ')' => Some(TokenKind::RightParen),
            '{' => Some(TokenKind::LeftBrace),
            '}' => Some(TokenKind::RightBrace),
            ',' => Some(TokenKind::Comma),
            _ => None,
        };
        if let Some(kind) = simple {
            position += current.len_utf8();
            tokens.push(Token {
                kind,
                position: start,
            });
            continue;
        }

        if input[start..].starts_with("==") {
            position += 2;
            tokens.push(Token {
                kind: TokenKind::Equal,
                position: start,
            });
            continue;
        }
        if input[start..].starts_with("!=") {
            position += 2;
            tokens.push(Token {
                kind: TokenKind::NotEqual,
                position: start,
            });
            continue;
        }
        // Ordered comparisons (two-char forms before one-char).
        for (symbol, kind) in [
            ("<=", TokenKind::LessEqual),
            (">=", TokenKind::GreaterEqual),
            ("<", TokenKind::Less),
            (">", TokenKind::Greater),
        ] {
            if input[start..].starts_with(symbol) {
                position += symbol.len();
                tokens.push(Token {
                    kind: kind.clone(),
                    position: start,
                });
                break;
            }
        }
        if position != start {
            continue;
        }
        if input[start..].starts_with("&&") {
            position += 2;
            tokens.push(Token {
                kind: TokenKind::And,
                position: start,
            });
            continue;
        }
        if input[start..].starts_with("||") {
            position += 2;
            tokens.push(Token {
                kind: TokenKind::Or,
                position: start,
            });
            continue;
        }
        if current == '!' {
            position += 1;
            tokens.push(Token {
                kind: TokenKind::Not,
                position: start,
            });
            continue;
        }
        if current == '=' || current == '&' || current == '|' {
            return Err(FilterParseError::new(
                start,
                format!("unexpected operator '{current}'"),
            ));
        }

        if current == '"' {
            let (value, next) = lex_string(input, start, false)?;
            position = next;
            tokens.push(Token {
                kind: TokenKind::String(value),
                position: start,
            });
            continue;
        }
        if input[start..].starts_with("r\"") {
            let (value, next) = lex_string(input, start, true)?;
            position = next;
            tokens.push(Token {
                kind: TokenKind::String(value),
                position: start,
            });
            continue;
        }

        while position < input.len() {
            let ch = input[position..].chars().next().unwrap();
            // A quote or comparison operator ends the bare word, so
            // `message.text contains"x"` and `client.port<40000` lex correctly
            // instead of swallowing the operator into the field/word.
            if ch.is_whitespace()
                || matches!(
                    ch,
                    '(' | ')' | '{' | '}' | ',' | '=' | '!' | '&' | '|' | '<' | '>' | '"'
                )
            {
                break;
            }
            position += ch.len_utf8();
        }
        if position == start {
            return Err(FilterParseError::new(
                start,
                format!("unexpected character '{current}'"),
            ));
        }
        let word = &input[start..position];
        let kind = if word.eq_ignore_ascii_case("and") {
            TokenKind::And
        } else if word.eq_ignore_ascii_case("or") {
            TokenKind::Or
        } else if word.eq_ignore_ascii_case("not") {
            TokenKind::Not
        } else if word.eq_ignore_ascii_case("contains") {
            TokenKind::Contains
        } else if word.eq_ignore_ascii_case("matches") {
            TokenKind::Matches
        } else if word.eq_ignore_ascii_case("in") {
            TokenKind::In
        } else {
            TokenKind::Word(word.to_string())
        };
        tokens.push(Token {
            kind,
            position: start,
        });
    }
    tokens.push(Token {
        kind: TokenKind::End,
        position: input.len(),
    });
    Ok(tokens)
}

fn lex_string(input: &str, start: usize, raw: bool) -> Result<(String, usize), FilterParseError> {
    let mut position = start + if raw { 2 } else { 1 };
    let mut value = String::new();
    while position < input.len() {
        let ch = input[position..].chars().next().unwrap();
        position += ch.len_utf8();
        if ch == '"' {
            return Ok((value, position));
        }
        if ch != '\\' || raw {
            value.push(ch);
            continue;
        }
        if position == input.len() {
            return Err(FilterParseError::new(start, "unterminated string literal"));
        }
        let escaped = input[position..].chars().next().unwrap();
        position += escaped.len_utf8();
        match escaped {
            '"' => value.push('"'),
            '\\' => value.push('\\'),
            'n' => value.push('\n'),
            'r' => value.push('\r'),
            't' => value.push('\t'),
            _ => {
                return Err(FilterParseError::new(
                    position - escaped.len_utf8() - 1,
                    format!("unsupported escape '\\{escaped}' (use a raw string for regexes)"),
                ));
            }
        }
    }
    Err(FilterParseError::new(start, "unterminated string literal"))
}

struct Parser {
    tokens: Vec<Token>,
    cursor: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, cursor: 0 }
    }

    fn parse(mut self) -> Result<Expr, FilterParseError> {
        let expression = self.parse_or()?;
        if !matches!(self.peek().kind, TokenKind::End) {
            return Err(self.error_here("expected a boolean operator or end of expression"));
        }
        Ok(expression)
    }

    fn parse_or(&mut self) -> Result<Expr, FilterParseError> {
        let mut expression = self.parse_and()?;
        while self.take_if(|kind| matches!(kind, TokenKind::Or)) {
            expression = Expr::Or(Box::new(expression), Box::new(self.parse_and()?));
        }
        Ok(expression)
    }

    fn parse_and(&mut self) -> Result<Expr, FilterParseError> {
        let mut expression = self.parse_not()?;
        while self.take_if(|kind| matches!(kind, TokenKind::And)) {
            expression = Expr::And(Box::new(expression), Box::new(self.parse_not()?));
        }
        Ok(expression)
    }

    fn parse_not(&mut self) -> Result<Expr, FilterParseError> {
        if self.take_if(|kind| matches!(kind, TokenKind::Not)) {
            return Ok(Expr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, FilterParseError> {
        if self.take_if(|kind| matches!(kind, TokenKind::LeftParen)) {
            let expression = self.parse_or()?;
            self.expect(|kind| matches!(kind, TokenKind::RightParen), "expected ')'")?;
            return Ok(expression);
        }
        self.parse_predicate().map(Expr::Predicate)
    }

    fn parse_predicate(&mut self) -> Result<Predicate, FilterParseError> {
        let field_token = self.take();
        let TokenKind::Word(field_name) = &field_token.kind else {
            return Err(FilterParseError::new(
                field_token.position,
                "expected a filter field",
            ));
        };
        let Some(field) = Field::parse(field_name) else {
            return Err(FilterParseError::new(
                field_token.position,
                format!("unknown filter field '{field_name}'"),
            ));
        };

        let operator = self.take();
        let comparison = match operator.kind {
            TokenKind::Equal => Comparison::Equal(self.parse_value(field)?),
            TokenKind::NotEqual => Comparison::NotEqual(self.parse_value(field)?),
            TokenKind::Less
            | TokenKind::LessEqual
            | TokenKind::Greater
            | TokenKind::GreaterEqual => {
                let op = match operator.kind {
                    TokenKind::Less => OrdOp::Less,
                    TokenKind::LessEqual => OrdOp::LessEqual,
                    TokenKind::Greater => OrdOp::Greater,
                    _ => OrdOp::GreaterEqual,
                };
                if !matches!(field, Field::ClientPort) {
                    return Err(FilterParseError::new(
                        operator.position,
                        format!(
                            "ordered comparison is only valid for 'client.port', not '{}'",
                            field.name()
                        ),
                    ));
                }
                Comparison::Ordered(op, self.parse_port()?)
            }
            TokenKind::Contains => {
                self.require_text_field(field, operator.position, "contains")?;
                Comparison::Contains(self.parse_string("contains requires a quoted string")?)
            }
            TokenKind::Matches => {
                self.require_text_field(field, operator.position, "matches")?;
                let token = self.peek().clone();
                let pattern = self.parse_string("matches requires a quoted string")?;
                let regex = RegexBuilder::new(&pattern)
                    .case_insensitive(true)
                    .build()
                    .map_err(|error| {
                        FilterParseError::new(token.position, format!("invalid regex: {error}"))
                    })?;
                Comparison::Matches(regex)
            }
            TokenKind::In => Comparison::In(self.parse_set(field)?),
            _ => {
                return Err(FilterParseError::new(
                    operator.position,
                    format!(
                        "expected an operator after '{}' (==, !=, <, <=, >, >=, contains, matches, or in)",
                        field.name()
                    ),
                ));
            }
        };
        Ok(Predicate { field, comparison })
    }

    fn parse_set(&mut self, field: Field) -> Result<Vec<Value>, FilterParseError> {
        self.expect(
            |kind| matches!(kind, TokenKind::LeftBrace),
            "expected '{' after 'in'",
        )?;
        if matches!(self.peek().kind, TokenKind::RightBrace) {
            return Err(self.error_here("set cannot be empty"));
        }
        let mut values = Vec::new();
        loop {
            values.push(self.parse_value(field)?);
            if self.take_if(|kind| matches!(kind, TokenKind::Comma)) {
                if matches!(self.peek().kind, TokenKind::RightBrace) {
                    return Err(self.error_here("expected a value after ','"));
                }
                continue;
            }
            self.expect(
                |kind| matches!(kind, TokenKind::RightBrace),
                "expected ',' or '}' in set",
            )?;
            break;
        }
        Ok(values)
    }

    fn parse_value(&mut self, field: Field) -> Result<Value, FilterParseError> {
        let token = self.take();
        match field {
            Field::ClientIp => {
                let value = token_value(&token).ok_or_else(|| {
                    FilterParseError::new(token.position, "client.ip requires an IP address")
                })?;
                value.parse().map(Value::Ip).map_err(|_| {
                    FilterParseError::new(token.position, format!("invalid IP address '{value}'"))
                })
            }
            Field::ClientPort => {
                // Accept both `client.port == 40005` and the quoted form
                // `== "40005"`, mirroring client.ip's leniency.
                let value = token_value(&token).ok_or_else(|| {
                    FilterParseError::new(token.position, "client.port requires an integer")
                })?;
                value.parse().map(Value::Port).map_err(|_| {
                    FilterParseError::new(token.position, format!("invalid client port '{value}'"))
                })
            }
            Field::MessageType | Field::MessageText => {
                let TokenKind::String(value) = token.kind else {
                    return Err(FilterParseError::new(
                        token.position,
                        format!("{} requires a quoted string", field.name()),
                    ));
                };
                Ok(Value::Text(value))
            }
            Field::MessageDirection => {
                let TokenKind::String(value) = &token.kind else {
                    return Err(FilterParseError::new(
                        token.position,
                        "message.direction requires a quoted string",
                    ));
                };
                parse_direction(value).map(Value::Direction).ok_or_else(|| {
                    FilterParseError::new(
                        token.position,
                        format!("invalid direction '{value}' (expected f2b or b2f)"),
                    )
                })
            }
        }
    }

    fn parse_string(&mut self, error: &str) -> Result<String, FilterParseError> {
        let token = self.take();
        let TokenKind::String(value) = token.kind else {
            return Err(FilterParseError::new(token.position, error));
        };
        Ok(value)
    }

    /// Parse a port number (bare or quoted) for an ordered comparison.
    fn parse_port(&mut self) -> Result<u16, FilterParseError> {
        let token = self.take();
        let value = token_value(&token).ok_or_else(|| {
            FilterParseError::new(token.position, "expected a port number after the operator")
        })?;
        value.parse().map_err(|_| {
            FilterParseError::new(token.position, format!("invalid client port '{value}'"))
        })
    }

    fn require_text_field(
        &self,
        field: Field,
        position: usize,
        operator: &str,
    ) -> Result<(), FilterParseError> {
        if field.is_text() {
            Ok(())
        } else {
            Err(FilterParseError::new(
                position,
                format!("operator '{operator}' is not valid for '{}'", field.name()),
            ))
        }
    }

    fn expect(
        &mut self,
        predicate: impl FnOnce(&TokenKind) -> bool,
        message: &str,
    ) -> Result<(), FilterParseError> {
        if predicate(&self.peek().kind) {
            self.cursor += 1;
            Ok(())
        } else {
            Err(self.error_here(message))
        }
    }

    fn take_if(&mut self, predicate: impl FnOnce(&TokenKind) -> bool) -> bool {
        if predicate(&self.peek().kind) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn take(&mut self) -> Token {
        let token = self.peek().clone();
        if !matches!(token.kind, TokenKind::End) {
            self.cursor += 1;
        }
        token
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.cursor]
    }

    fn error_here(&self, message: impl Into<String>) -> FilterParseError {
        FilterParseError::new(self.peek().position, message)
    }
}

fn token_value(token: &Token) -> Option<&str> {
    match &token.kind {
        TokenKind::Word(value) | TokenKind::String(value) => Some(value),
        _ => None,
    }
}

fn parse_direction(value: &str) -> Option<MessageDirection> {
    if value.eq_ignore_ascii_case("f2b") || value == "F→B" {
        Some(MessageDirection::FrontendToBackend)
    } else if value.eq_ignore_ascii_case("b2f") || value == "B→F" {
        Some(MessageDirection::BackendToFrontend)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> DisplayMessage {
        DisplayMessage {
            timestamp: "2026-07-17T12:34:56.789+01:00".into(),
            rendered: "line".into(),
            client: "127.0.0.1:40005".parse().unwrap(),
            direction: MessageDirection::FrontendToBackend,
            kind: "Query".into(),
            text: "SELECT * FROM orders WHERE id = 42".into(),
        }
    }

    #[test]
    fn ordered_port_comparisons() {
        // message() has client.port 40005.
        for (expr, expected) in [
            ("client.port > 40000", true),
            ("client.port < 40000", false),
            ("client.port >= 40005", true),
            ("client.port <= 40005", true),
            ("client.port < 40005", false),
            ("client.port >= 40000 and client.port < 50000", true),
        ] {
            assert_eq!(
                DisplayFilter::parse(expr).unwrap().matches(&message()),
                expected,
                "{expr}"
            );
        }
        // Ordered comparison is rejected on non-numeric fields.
        assert!(DisplayFilter::parse("message.type > \"Query\"").is_err());
        assert!(DisplayFilter::parse("client.ip < 127.0.0.1").is_err());
    }

    #[test]
    fn quoted_port_is_accepted_symmetrically_with_ip() {
        // Both quoted and bare forms parse and match, like client.ip.
        assert!(
            DisplayFilter::parse("client.port == \"40005\"")
                .unwrap()
                .matches(&message())
        );
        assert!(
            DisplayFilter::parse("client.port == 40005")
                .unwrap()
                .matches(&message())
        );
    }

    #[test]
    fn quote_terminates_a_bare_word() {
        // `contains"orders"` (no space) must still recognise the operator.
        let filter = DisplayFilter::parse("message.text contains\"orders\"").unwrap();
        assert!(filter.matches(&message()));
        // And a comparison operator glued to the field lexes correctly.
        assert!(
            DisplayFilter::parse("client.port<50000")
                .unwrap()
                .matches(&message())
        );
    }

    #[test]
    fn combines_typed_conditions_with_boolean_operators() {
        let filter = DisplayFilter::parse(
            "client.ip == 127.0.0.1 and client.port == 40005 && \
             message.type in {\"Query\", \"DataRow\"} and \
             message.text contains \"orders\" and message.direction == \"f2b\"",
        )
        .unwrap();
        assert!(filter.matches(&message()));

        let mut other = message();
        other.client = "127.0.0.1:40006".parse().unwrap();
        assert!(!filter.matches(&other));
    }

    #[test]
    fn applies_not_and_and_or_precedence() {
        let filter = DisplayFilter::parse(
            "message.type == \"DataRow\" or \
             message.type == \"Query\" and not message.text contains \"users\"",
        )
        .unwrap();
        assert!(filter.matches(&message()));

        let grouped = DisplayFilter::parse(
            "(message.type == \"DataRow\" or message.type == \"Query\") and \
             not client.ip == 127.0.0.1",
        )
        .unwrap();
        assert!(!grouped.matches(&message()));
    }

    #[test]
    fn supports_symbolic_boolean_operators_and_not_equal() {
        let filter = DisplayFilter::parse(
            "message.type != \"DataRow\" && \
             !(client.port == 40006 || client.ip == ::1)",
        )
        .unwrap();
        assert!(filter.matches(&message()));
    }

    #[test]
    fn matches_regexes_case_insensitively_and_accepts_raw_strings() {
        let filter = DisplayFilter::parse(
            "message.type matches \"^qu.*$\" and message.text matches r\"orders\\s+WHERE\"",
        )
        .unwrap();
        assert!(filter.matches(&message()));
    }

    #[test]
    fn equality_and_contains_are_case_sensitive() {
        assert!(
            !DisplayFilter::parse("message.type == \"query\"")
                .unwrap()
                .matches(&message())
        );
        assert!(
            !DisplayFilter::parse("message.text contains \"ORDERS\"")
                .unwrap()
                .matches(&message())
        );
    }

    #[test]
    fn supports_ip_port_and_direction_sets() {
        assert!(
            DisplayFilter::parse("client.ip in {127.0.0.1, ::1}")
                .unwrap()
                .matches(&message())
        );
        assert!(
            DisplayFilter::parse("client.port in {40005, 40006}")
                .unwrap()
                .matches(&message())
        );
        assert!(
            DisplayFilter::parse("message.direction in {\"b2f\", \"f2b\"}")
                .unwrap()
                .matches(&message())
        );
    }

    #[test]
    fn rejects_unknown_fields_invalid_types_and_invalid_regexes() {
        let cases = [
            "client == 127.0.0.1",
            "client.ip contains \"127\"",
            "client.port == \"not-a-number\"",
            "message.type == Query",
            "message.direction == \"sideways\"",
            "message.type in {}",
            "message.type matches \"[\"",
            "message.type == \"unterminated",
            "type=Query",
        ];
        for expression in cases {
            assert!(
                DisplayFilter::parse(expression).is_err(),
                "expected '{expression}' to fail"
            );
        }
    }

    #[test]
    fn parse_errors_include_the_byte_position() {
        let error = DisplayFilter::parse("message.type == Query").unwrap_err();
        assert!(error.to_string().contains("at byte 16"));
    }

    #[test]
    fn empty_expression_matches_every_message() {
        let filter = DisplayFilter::parse("   ").unwrap();
        assert!(filter.is_empty());
        assert!(filter.matches(&message()));
    }
}
