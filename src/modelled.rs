use serde::Serialize;

/// Logged by every modelled invocation, and printed by the binary before any
/// modelled code runs once the CLI is wired (Task 7).
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
///
/// `provenance` is private with a `pub(crate)` constructor so that downstream
/// code cannot build an `Attestation` that claims to be `Real` from a value a
/// stub produced. Barrier 4 is then structural rather than conventional.
/// `bytes` stays public: a test needs to tamper with it.
#[derive(Clone, Debug)]
pub struct Attestation {
    pub bytes: Vec<u8>,
    provenance: Provenance,
}

impl Attestation {
    pub(crate) fn new(bytes: Vec<u8>, provenance: Provenance) -> Self {
        Attestation { bytes, provenance }
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }
}

/// An escrow tag binding an action to a recoverable identity.
#[derive(Clone, Debug)]
pub struct Tag {
    pub bytes: Vec<u8>,
    provenance: Provenance,
}

impl Tag {
    pub(crate) fn new(bytes: Vec<u8>, provenance: Provenance) -> Self {
        Tag { bytes, provenance }
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }
}

/// The result of an escrow opening.
///
/// A distinct type rather than a `String`, for the same reason
/// `AttestationVerdict` has a `ModelledNoSecurity` variant: generic code
/// written against `EscrowTag` — which is exactly the shape a future real
/// implementation invites — would otherwise bind `Ok(s)` as "the recovered
/// identity", and the only thing stopping it would be the *content* of the
/// string, which no type checks and no caller is obliged to read.
#[derive(Clone, Debug)]
pub struct Opening {
    /// What the opening produced. For a modelled implementation this is a
    /// statement that nothing was recovered, never an identity.
    pub description: String,
    provenance: Provenance,
}

impl Opening {
    pub(crate) fn new(description: String, provenance: Provenance) -> Self {
        Opening {
            description,
            provenance,
        }
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// Whether this opening recovered an identity. Always false for a
    /// modelled implementation, and the only honest way to ask.
    pub fn recovered_identity(&self) -> bool {
        matches!(self.provenance, Provenance::Real { .. })
    }
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
    /// Attempt to recover the identity given `shares` cooperating nodes.
    ///
    /// Returns an `Opening`, not a `String`: a caller must ask
    /// `Opening::recovered_identity()` rather than assume `Ok` means an
    /// identity came back.
    fn open(&self, tag: &Tag, shares: usize) -> Result<Opening, ModelledError>;
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
    fn independently_built_identical_provenances_compare_equal() {
        // The report layer groups and deduplicates on this value, so
        // semantically identical inputs must compare equal.
        let a = Provenance::Modelled {
            component: "ECDAA",
            reason: "stub",
        };
        let b = Provenance::Modelled {
            component: "ECDAA",
            reason: "stub",
        };
        assert_eq!(a, b);
        assert_ne!(
            a,
            Provenance::Modelled {
                component: "escrow",
                reason: "stub",
            }
        );
        assert_ne!(
            a,
            Provenance::Modelled {
                component: "ECDAA",
                reason: "other",
            }
        );
        assert_ne!(a, Provenance::Real { component: "ECDAA" });
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
