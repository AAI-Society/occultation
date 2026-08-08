//! Barrier 3: every modelled invocation warns.
//!
//! Its own integration test binary, because a logger can only be installed
//! once per process and the unit tests share one.

use log::{Level, Log, Metadata, Record};
use occultation::ecdaa::ModelledEcdaa;
use occultation::escrow::ModelledThresholdElGamal;
use occultation::modelled::{AnonymousAttestation, EscrowTag, ModelledPermit, MODELLED_WARNING};
use std::sync::Mutex;

static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Capture;

impl Log for Capture {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }
    fn log(&self, record: &Record) {
        if record.level() <= Level::Warn {
            CAPTURED
                .lock()
                .expect("not poisoned")
                .push(record.args().to_string());
        }
    }
    fn flush(&self) {}
}

fn drain() -> Vec<String> {
    std::mem::take(&mut *CAPTURED.lock().expect("not poisoned"))
}

/// One test, not four: the logger installs once, and splitting these would
/// race on the shared buffer.
///
/// `checks`' type is flagged by `clippy::type_complexity`, but a named alias
/// does not work here: a type alias resolves an elided trait-object lifetime
/// to `'static` at the alias's own definition, which would then reject the
/// closures below for borrowing `ecdaa`/`escrow` for less than `'static`. The
/// inline local annotation infers a shorter, correct lifetime instead.
#[test]
#[allow(clippy::type_complexity)]
fn every_modelled_invocation_warns() {
    log::set_boxed_logger(Box::new(Capture)).expect("first and only install");
    log::set_max_level(log::LevelFilter::Trace);

    let permit = ModelledPermit::from_flag(true).expect("flag is set");
    let ecdaa = ModelledEcdaa::new(permit);
    let escrow = ModelledThresholdElGamal::new(permit, 3, 5).expect("3-of-5 is openable");

    let checks: Vec<(&str, Box<dyn Fn()>)> = vec![
        (
            "ModelledEcdaa::attest",
            Box::new(|| {
                ecdaa.attest(b"measurement").expect("stub cannot fail");
            }),
        ),
        (
            "ModelledEcdaa::verify",
            Box::new(|| {
                let a = ecdaa.attest(b"measurement").expect("stub cannot fail");
                drain(); // discard the attest warning; we are testing verify
                ecdaa.verify(b"measurement", &a);
            }),
        ),
        (
            "ModelledThresholdElGamal::tag",
            Box::new(|| {
                escrow.tag(b"did:web:agent-42").expect("stub cannot fail");
            }),
        ),
        (
            "ModelledThresholdElGamal::open",
            Box::new(|| {
                let tag = escrow.tag(b"did:web:agent-42").expect("stub cannot fail");
                drain(); // discard the tag warning
                escrow
                    .open(&tag, 3)
                    .expect("3 shares meets a 3-of-5 threshold");
            }),
        ),
    ];

    for (path, run) in checks {
        drain();
        run();
        let warnings = drain();
        assert!(!warnings.is_empty(), "{path} ran without warning");
        assert!(
            warnings
                .iter()
                .all(|w| w.contains("MODELLED") && w.contains("no security")),
            "{path} warned, but not with the modelled warning: {warnings:?}"
        );
    }

    // And a refused opening must warn too — the caller still touched a stub.
    drain();
    let tag = escrow.tag(b"x").expect("stub cannot fail");
    drain();
    assert!(
        escrow.open(&tag, 1).is_err(),
        "1 share is below a 3-of-5 threshold"
    );
    assert!(!drain().is_empty(), "a refused opening ran without warning");

    // The constant itself must carry both markers, or every check above is
    // asserting against a string that says nothing.
    assert!(MODELLED_WARNING.contains("MODELLED"));
    assert!(MODELLED_WARNING.contains("no security"));
}
