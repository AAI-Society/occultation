use crate::cost::Source;
use crate::modelled::Provenance;
use serde_json::json;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "table" => Ok(Format::Table),
            "json" => Ok(Format::Json),
            other => Err(format!(
                "unknown format `{other}`; expected `table` or `json`"
            )),
        }
    }
}

/// One measured or published cost.
#[derive(Clone, Debug)]
pub struct Row {
    pub label: String,
    pub cost: Duration,
    pub source: Source,
    pub provenance: Provenance,
    /// Multiple of the Ed25519 baseline, when a baseline is available.
    pub ratio: Option<f64>,
    /// The 95th percentile of the same sample, when there was one.
    ///
    /// Carried so dispersion reaches the reader. Every ratio this tool
    /// publishes is divided by the Ed25519 round trip, which is the smallest
    /// and therefore noisiest thing in the table; without a spread column, an
    /// unstable denominator is invisible and the headline multiple silently
    /// moves between runs. Task 10 also quotes tail latencies, and this is
    /// the field they travel in.
    pub p95: Option<Duration>,
}

impl Row {
    pub fn new(
        label: impl Into<String>,
        cost: Duration,
        source: Source,
        provenance: Provenance,
    ) -> Self {
        Row {
            label: label.into(),
            cost,
            source,
            provenance,
            ratio: None,
            p95: None,
        }
    }

    /// Attach the sample's 95th percentile so dispersion is visible.
    pub fn with_p95(mut self, p95: Duration) -> Self {
        self.p95 = Some(p95);
        self
    }

    pub fn real(label: impl Into<String>, cost: Duration, source: Source) -> Self {
        let label = label.into();
        let component: &'static str = Box::leak(label.clone().into_boxed_str());
        Row::new(label, cost, source, Provenance::Real { component })
    }

    /// Attach the multiple of a baseline. A zero baseline yields `None` rather
    /// than an infinity, because printing `inf` in a results table is worse
    /// than printing nothing.
    pub fn against(mut self, baseline: Duration) -> Self {
        self.ratio = if baseline.is_zero() {
            None
        } else {
            Some(self.cost.as_secs_f64() / baseline.as_secs_f64())
        };
        self
    }

    pub fn is_modelled(&self) -> bool {
        matches!(self.provenance, Provenance::Modelled { .. })
    }
}

#[derive(Clone, Debug)]
pub struct Table {
    pub title: String,
    pub rows: Vec<Row>,
    pub notes: Vec<String>,
}

impl Table {
    pub fn new(title: impl Into<String>) -> Self {
        Table {
            title: title.into(),
            rows: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn with(mut self, row: Row) -> Self {
        self.rows.push(row);
        self
    }

    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    pub fn render(&self) -> String {
        let mut out = format!("{}\n\n", self.title);
        out.push_str(&format!(
            "{:<40} {:>12} {:>12} {:>10}  {}\n",
            "OPERATION", "COST", "P95", "xED25519", "PROVENANCE"
        ));
        for r in &self.rows {
            let ratio = match r.ratio {
                Some(x) => format!("{x:.1}"),
                None => "-".to_string(),
            };
            // Both labels come from Display impls, so a new Source or
            // Provenance variant cannot silently render as blank.
            let tag = match (&r.provenance, &r.source) {
                (Provenance::Modelled { .. }, s) => format!("{} · {s}", r.provenance),
                (_, s) => format!("{s}"),
            };
            let p95 = match r.p95 {
                Some(d) => format!("{:.3} ms", d.as_secs_f64() * 1e3),
                None => "-".to_string(),
            };
            out.push_str(&format!(
                "{:<40} {:>9.3} ms {:>12} {:>10}  {}\n",
                r.label,
                r.cost.as_secs_f64() * 1e3,
                p95,
                ratio,
                tag
            ));
        }
        for n in &self.notes {
            out.push_str(&format!("\n{n}\n"));
        }
        if self.rows.iter().any(Row::is_modelled) {
            out.push('\n');
            out.push_str(Self::MODELLED_FOOTER);
            out.push('\n');
        }
        out
    }

    /// The same warning `render` puts in its footer. A machine-readable
    /// export that omitted it would honour the constraint in one format and
    /// not the other.
    pub const MODELLED_FOOTER: &'static str =
        "Rows marked MODELLED come from stubs that provide no security. \
         Their cost is representative; nothing else about them is.";

    pub fn to_json(&self) -> serde_json::Value {
        let mut notes = self.notes.clone();
        if self.rows.iter().any(Row::is_modelled) {
            notes.push(Self::MODELLED_FOOTER.to_string());
        }
        json!({
            "title": self.title,
            "notes": notes,
            "rows": self.rows.iter().map(|r| json!({
                "label": r.label,
                "cost_us": r.cost.as_secs_f64() * 1e6,
                "p95_us": r.p95.map(|d| d.as_secs_f64() * 1e6),
                "source": r.source,
                "provenance": r.provenance,
                "ratio_to_ed25519": r.ratio,
            })).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cost::Source;
    use crate::modelled::Provenance;
    use std::time::Duration;

    fn real_row() -> Row {
        Row::real(
            "BBS+ verify",
            Duration::from_micros(500),
            Source::MeasuredHere { iters: 100 },
        )
    }

    fn modelled_row() -> Row {
        Row::new(
            "escrow tag + DLEQ",
            Duration::from_micros(300),
            Source::MeasuredHere { iters: 100 },
            Provenance::Modelled {
                component: "escrow",
                reason: "stub",
            },
        )
    }

    /// Assert on the ROW's own line, not on the whole rendering.
    ///
    /// `render()` appends a footer whose fixed text contains the word
    /// MODELLED whenever any row is modelled, so a whole-output
    /// `contains("MODELLED")` passes even with the per-row tag deleted. The
    /// difference between "one line at the bottom says some rows are stubs"
    /// and "*this* number is a stub" is the entire point of per-row marking
    /// in a twelve-row table, and it is the visible half of a security
    /// barrier.
    #[test]
    fn a_modelled_row_renders_the_word_modelled_on_its_own_line() {
        let out = Table::new("costs")
            .with(real_row())
            .with(modelled_row())
            .render();
        let line = out
            .lines()
            .find(|l| l.starts_with("escrow tag"))
            .unwrap_or_else(|| panic!("no row line found in:\n{out}"));
        assert!(
            line.contains("MODELLED"),
            "the row itself must say so: {line}"
        );

        let real_line = out
            .lines()
            .find(|l| l.starts_with("BBS+ verify"))
            .unwrap_or_else(|| panic!("no real row line found in:\n{out}"));
        assert!(
            !real_line.contains("MODELLED"),
            "a real row must not: {real_line}"
        );
    }

    #[test]
    fn a_real_measured_row_does_not_say_modelled_or_published() {
        let out = Table::new("costs").with(real_row()).render();
        assert!(!out.contains("MODELLED"), "{out}");
        assert!(!out.contains("PUBLISHED"), "{out}");
    }

    #[test]
    fn a_published_row_renders_the_word_published_and_its_citation() {
        let row = Row::real(
            "BBS+ presentation",
            Duration::from_micros(13_800),
            Source::Published {
                citation: "the desk study",
            },
        );
        let out = Table::new("costs").with(row).render();
        assert!(out.contains("PUBLISHED"), "{out}");
        assert!(out.contains("the desk study"), "{out}");
    }

    #[test]
    fn a_ratio_is_rendered_against_the_baseline() {
        let t = Table::new("costs")
            .with(real_row().against(Duration::from_micros(25)))
            .render();
        assert!(
            t.contains("20.0"),
            "500 us against a 25 us baseline is 20x: {t}"
        );
    }

    #[test]
    fn a_zero_baseline_does_not_divide_by_zero() {
        let r = real_row().against(Duration::ZERO);
        assert!(r.ratio.is_none(), "a zero baseline has no meaningful ratio");
        assert!(!Table::new("c").with(r).render().contains("inf"));
    }

    #[test]
    fn json_carries_the_source_and_provenance_as_data_not_prose() {
        let v = Table::new("costs").with(modelled_row()).to_json();
        let row = &v["rows"][0];
        assert_eq!(row["provenance"]["kind"], "modelled");
        assert_eq!(row["provenance"]["component"], "escrow");
        assert_eq!(row["source"]["kind"], "measured_here");
        assert_eq!(row["label"], "escrow tag + DLEQ");
        assert!(row["cost_us"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn json_carries_the_modelled_warning_too_not_just_the_table() {
        let v = Table::new("costs").with(modelled_row()).to_json();
        let notes = v["notes"].as_array().unwrap();
        assert!(
            notes
                .iter()
                .any(|n| n.as_str().unwrap().contains("no security")),
            "the machine-readable form must carry the warning as well: {notes:?}"
        );
        let clean = Table::new("costs").with(real_row()).to_json();
        assert!(clean["notes"].as_array().unwrap().is_empty());
    }

    #[test]
    fn a_real_rows_component_name_survives_into_json() {
        // `Row::real` leaks its label to satisfy Provenance's &'static str.
        // Substituting a placeholder would silently rewrite every real row's
        // component in machine-readable output.
        let v = Table::new("costs").with(real_row()).to_json();
        assert_eq!(v["rows"][0]["provenance"]["component"], "BBS+ verify");
    }

    #[test]
    fn p95_is_carried_into_both_renderings() {
        let r = real_row().with_p95(Duration::from_micros(900));
        assert!(Table::new("c")
            .with(r.clone())
            .render()
            .contains("0.900 ms"));
        let v = Table::new("c").with(r).to_json();
        assert_eq!(v["rows"][0]["p95_us"].as_f64().unwrap(), 900.0);
    }

    #[test]
    fn a_table_notes_every_modelled_component_in_its_footer() {
        let out = Table::new("costs")
            .with(real_row())
            .with(modelled_row())
            .render();
        assert!(
            out.contains("no security"),
            "a table containing a modelled row must warn in prose too: {out}"
        );
    }

    #[test]
    fn a_table_with_no_modelled_rows_has_no_warning_footer() {
        let out = Table::new("costs").with(real_row()).render();
        assert!(!out.contains("no security"), "{out}");
    }
}
