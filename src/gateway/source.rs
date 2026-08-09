use base64::{engine::general_purpose::STANDARD, Engine};

use crate::gateway::proxy::RequestHead;

/// A TDX quote is a few kilobytes. Past this the input is hostile and
/// decoding it would allocate on an attacker's say-so.
pub const MAX_ATTESTATION_B64: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("attestation header is not valid UTF-8")]
    NotUtf8,
    #[error("attestation header is not valid base64: {0}")]
    NotBase64(String),
    #[error("attestation header is {got} bytes; the cap is {MAX_ATTESTATION_B64}")]
    TooLarge { got: usize },
}

/// Whether the transport ties the attestation to *this* session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionBinding {
    Bound,
    Unbound { why: &'static str },
}

#[derive(Clone, Debug)]
pub struct RawAttestation {
    pub bytes: Vec<u8>,
}

/// Where an attestation comes out of a request. Pluggable because C7.2.4
/// says the evidence key digest goes in the attested report body and says
/// nothing about how the report reaches a relying party.
///
/// `extract` takes an owned `RequestHead` snapshot rather than the live
/// request: Task 1's proxy consumes the request in `forward` before any hook
/// runs, so by the time a source could see it, only the snapshot exists.
pub trait AttestationSource: Send + Sync {
    fn extract(&self, head: &RequestHead) -> Result<Option<RawAttestation>, SourceError>;
    fn session_binding(&self) -> SessionBinding;
    fn name(&self) -> &'static str;
}

/// Reads a base64 quote from a request header.
///
/// The simplest transport that works with any client stack, and the weakest:
/// nothing ties the quote to the TLS session it arrived on, so a quote
/// captured once can be replayed forever. `RaTlsSource` in phase 1b is the
/// answer; until then the gateway reports the gap.
pub struct HeaderSource {
    header: String,
}

impl HeaderSource {
    pub fn new(header: &str) -> Self {
        HeaderSource {
            header: header.to_ascii_lowercase(),
        }
    }
}

impl AttestationSource for HeaderSource {
    fn extract(&self, head: &RequestHead) -> Result<Option<RawAttestation>, SourceError> {
        let Some(v) = head.headers.get(&self.header) else {
            return Ok(None);
        };
        let s = v.to_str().map_err(|_| SourceError::NotUtf8)?;
        if s.len() > MAX_ATTESTATION_B64 {
            return Err(SourceError::TooLarge { got: s.len() });
        }
        let bytes = STANDARD
            .decode(s)
            .map_err(|e| SourceError::NotBase64(e.to_string()))?;
        Ok(Some(RawAttestation { bytes }))
    }

    fn session_binding(&self) -> SessionBinding {
        SessionBinding::Unbound {
            why: "the quote arrived in a header and is not bound to this TLS \
                  session, so a captured quote is replayable",
        }
    }

    fn name(&self) -> &'static str {
        "header"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};
    use hyper::HeaderMap;

    /// Builds a `RequestHead` directly, since `hyper::body::Incoming` has no
    /// public constructor a test could use instead.
    fn head_with(header: Option<(&str, &str)>) -> RequestHead {
        let mut headers = HeaderMap::new();
        if let Some((k, v)) = header {
            headers.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        RequestHead {
            method: hyper::Method::GET,
            path_and_query: "/".to_string(),
            headers,
        }
    }

    #[test]
    fn a_base64_header_yields_its_bytes() {
        let s = HeaderSource::new("x-attestation");
        let h = head_with(Some(("x-attestation", "aGVsbG8="))); // "hello"
        assert_eq!(s.extract(&h).unwrap().unwrap().bytes, b"hello");
    }

    #[test]
    fn an_absent_header_is_none_not_an_error() {
        // No attestation is a legitimate state the gateway reports on. It is
        // not a malformed request.
        assert!(HeaderSource::new("x-attestation")
            .extract(&head_with(None))
            .unwrap()
            .is_none());
    }

    #[test]
    fn undecodable_base64_is_an_error_not_a_panic() {
        let s = HeaderSource::new("x-attestation");
        assert!(s
            .extract(&head_with(Some(("x-attestation", "not!base64"))))
            .is_err());
    }

    #[test]
    fn a_non_ascii_header_value_is_an_error_not_a_panic() {
        // Header values can carry arbitrary bytes; to_str() fails on them.
        let s = HeaderSource::new("x-attestation");
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-attestation"),
            HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        let head = RequestHead {
            method: hyper::Method::GET,
            path_and_query: "/".to_string(),
            headers,
        };
        assert!(s.extract(&head).is_err());
    }

    #[test]
    fn an_oversized_header_is_refused_rather_than_allocated() {
        // A quote is a few kilobytes. Anything past the cap is hostile input,
        // and decoding it would allocate on an attacker's say-so.
        let s = HeaderSource::new("x-attestation");
        let huge = "A".repeat(MAX_ATTESTATION_B64 + 4);
        assert!(s
            .extract(&head_with(Some(("x-attestation", &huge))))
            .is_err());
    }

    #[test]
    fn header_transport_declares_itself_unbound() {
        // The finding depends on this being honest.
        match HeaderSource::new("x-attestation").session_binding() {
            SessionBinding::Unbound { why } => assert!(why.contains("replay")),
            SessionBinding::Bound => panic!("a header cannot bind a TLS session"),
        }
    }

    #[test]
    fn the_configured_header_name_matches_case_insensitively() {
        // Header names are case-insensitive on the wire, and `new` lowercases
        // what it is given. Pin both directions: a differently-cased
        // configured name still finds a differently-cased stored header.
        let configured_mixed = HeaderSource::new("X-Attestation");
        let stored_lower = head_with(Some(("x-attestation", "aGVsbG8=")));
        assert!(configured_mixed.extract(&stored_lower).unwrap().is_some());

        let configured_lower = HeaderSource::new("x-attestation");
        let stored_mixed = head_with(Some(("X-Attestation", "aGVsbG8=")));
        assert!(configured_lower.extract(&stored_mixed).unwrap().is_some());
    }
}
