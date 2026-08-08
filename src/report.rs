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
        }
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
            "{:<40} {:>12} {:>10}  {}\n",
            "OPERATION", "COST", "xED25519", "PROVENANCE"
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
            out.push_str(&format!(
                "{:<40} {:>9.3} ms {:>10}  {}\n",
                r.label,
                r.cost.as_secs_f64() * 1e3,
                ratio,
                tag
            ));
        }
        for n in &self.notes {
            out.push_str(&format!("\n{n}\n"));
        }
        if self.rows.iter().any(Row::is_modelled) {
            out.push_str(
                "\nRows marked MODELLED come from stubs that provide no security. \
                 Their cost is representative; nothing else about them is.\n",
            );
        }
        out
    }

    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "title": self.title,
            "notes": self.notes,
            "rows": self.rows.iter().map(|r| json!({
                "label": r.label,
                "cost_us": r.cost.as_secs_f64() * 1e6,
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

    #[test]
    fn a_modelled_row_renders_the_word_modelled() {
        let t = Table::new("costs").with(modelled_row());
        assert!(t.render().contains("MODELLED"), "{}", t.render());
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
        assert_eq!(row["source"]["kind"], "measured_here");
        assert_eq!(row["label"], "escrow tag + DLEQ");
        assert!(row["cost_us"].as_f64().unwrap() > 0.0);
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
