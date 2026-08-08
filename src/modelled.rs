use serde::Serialize;

/// Printed by the binary before any modelled code runs, and logged by every
/// modelled invocation.
pub const MODELLED_WARNING: &str = "\
WARNING: MODELLED COMPONENT IN USE. ECDAA and threshold ElGamal escrow are
stubs providing no security: no anonymity, no soundness, no confidentiality
and no accountability. Their cost profile is representative; nothing else
about them is. Any result depending on them is an estimate of cost, not
evidence of security.";

#[derive(Debug, thiserror::Error)]
pub enum ModelledError {
    #[error(
        "this path runs a modelled component, which provides no security; \
         pass --allow-modelled to run it anyway"
    )]
    PermitRequired,
    #[error("a {k}-of-{n} committee is not openable ({reason})")]
    BadThreshold {
        k: usize,
        n: usize,
        reason: &'static str,
    },
}

/// Whether a value came from real cryptography or from a stub.
///
/// Carried on every value that crosses the boundary, so the report layer can
/// label it without knowing which implementation produced it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provenance {
    Real {
        component: &'static str,
    },
    Modelled {
        component: &'static str,
        reason: &'static str,
    },
}

impl std::fmt::Display for Provenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Provenance::Real { component } => write!(f, "{component}"),
            Provenance::Modelled { component, reason } => {
                write!(f, "{component} [MODELLED — no security: {reason}]")
            }
        }
    }
}

/// Proof that the operator explicitly asked to run code that provides no
/// security.
///
/// The unit field is private, so `from_flag` is the only way to obtain one and
/// a modelled constructor is the only thing that consumes one. The gate cannot
/// be bypassed by a caller forgetting to check a boolean, because there is no
/// boolean to forget.
#[derive(Clone, Copy, Debug)]
pub struct ModelledPermit(());

impl ModelledPermit {
    pub fn from_flag(allow_modelled: bool) -> Result<Self, ModelledError> {
        if allow_modelled {
            Ok(ModelledPermit(()))
        } else {
            Err(ModelledError::PermitRequired)
        }
    }
}

/// The result of checking an attestation.
///
/// `Valid` is deliberately unreachable from any modelled implementation. A
/// caller writing `if verdict.is_valid()` gets `false` from a stub, and a
/// caller matching exhaustively is forced to handle `ModelledNoSecurity`
/// explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    Invalid,
    ModelledNoSecurity,
}

impl AttestationVerdict {
    pub fn is_valid(self) -> bool {
        matches!(self, AttestationVerdict::Valid)
    }
}

/// An anonymous platform attestation.
#[derive(Clone, Debug)]
pub struct Attestation {
    pub bytes: Vec<u8>,
    pub provenance: Provenance,
}

/// An escrow tag binding an action to a recoverable identity.
#[derive(Clone, Debug)]
pub struct Tag {
    pub bytes: Vec<u8>,
    pub provenance: Provenance,
}

/// Prove membership in a valid TEE group without emitting a platform
/// identifier. P05's hardware attestation layer; ECDAA in the construction.
///
/// The only implementation in this crate is modelled.
pub trait AnonymousAttestation {
    /// Whether this implementation provides security. Checked by test for
    /// every implementation in the crate.
    const MODELLED: bool;

    fn provenance(&self) -> Provenance;
    fn attest(&self, measurement: &[u8]) -> Result<Attestation, ModelledError>;
    fn verify(&self, measurement: &[u8], attestation: &Attestation) -> AttestationVerdict;
}

/// Bind an action to an identity recoverable only by a k-of-n quorum.
/// P05's accountability layer; threshold ElGamal in the construction.
///
/// The only implementation in this crate is modelled.
pub trait EscrowTag {
    const MODELLED: bool;

    fn provenance(&self) -> Provenance;
    fn tag(&self, identity: &[u8]) -> Result<Tag, ModelledError>;
    /// Recover the identity given `shares` cooperating nodes.
    fn open(&self, tag: &Tag, shares: usize) -> Result<String, ModelledError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_permit_cannot_be_had_without_the_flag() {
        assert!(ModelledPermit::from_flag(false).is_err());
        assert!(ModelledPermit::from_flag(true).is_ok());
    }

    #[test]
    fn the_permit_error_says_what_to_do_and_why() {
        let e = ModelledPermit::from_flag(false).unwrap_err();
        let s = format!("{e}");
        assert!(s.contains("--allow-modelled"), "must name the flag: {s}");
        assert!(s.contains("no security"), "must say what is missing: {s}");
    }

    #[test]
    fn the_warning_text_is_unambiguous() {
        let w = MODELLED_WARNING;
        assert!(w.contains("MODELLED"));
        assert!(w.contains("no security"));
        assert!(
            !w.to_lowercase().contains("simulat"),
            "'simulated' reads as 'nearly real'"
        );
    }

    #[test]
    fn modelled_provenance_renders_the_word_modelled() {
        let p = Provenance::Modelled {
            component: "ECDAA",
            reason: "not implemented",
        };
        assert!(format!("{p}").contains("MODELLED"));
    }

    #[test]
    fn real_provenance_does_not_render_the_word_modelled() {
        let p = Provenance::Real {
            component: "BBS+ proof verification",
        };
        assert!(!format!("{p}").contains("MODELLED"));
    }

    #[test]
    fn a_modelled_verdict_is_not_equal_to_a_valid_one() {
        assert_ne!(
            AttestationVerdict::ModelledNoSecurity,
            AttestationVerdict::Valid
        );
        assert!(!AttestationVerdict::ModelledNoSecurity.is_valid());
        assert!(!AttestationVerdict::Invalid.is_valid());
        assert!(AttestationVerdict::Valid.is_valid());
    }
}
