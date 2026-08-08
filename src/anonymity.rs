use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum AnonymityError {
    #[error("could not read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("the fleet declares no hosts")]
    EmptyFleet,
    #[error("host `{0}` declares count = 0")]
    ZeroCount(String),
    #[error("host `{0}` declares no TCB attributes; an empty TCB describes nothing")]
    EmptyTcb(String),
}

/// A group of identically configured hosts.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub id: String,
    /// How many machines share this configuration. Lets a 5000-host fleet be
    /// described in a handful of lines.
    #[serde(default = "one")]
    pub count: usize,
    /// The TCB fingerprint: TDX module version, CPU SVN, PCE SVN, microcode
    /// revision, QE identity, PCS chain — whatever the operator can observe.
    /// Free-form on purpose; the tool partitions on whatever it is given.
    pub tcb: BTreeMap<String, String>,
}

fn one() -> usize {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fleet {
    pub name: String,
    #[serde(default)]
    pub host: Vec<Host>,
}

impl Fleet {
    pub fn load(path: &Path) -> Result<Self, AnonymityError> {
        let text = std::fs::read_to_string(path).map_err(|source| AnonymityError::Io {
            path: path.display().to_string(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| AnonymityError::Parse {
            path: path.display().to_string(),
            source,
        })
    }

    pub fn size(&self) -> usize {
        self.host.iter().map(|h| h.count).sum()
    }
}

/// One anonymity set: the hosts an observer cannot tell apart.
#[derive(Clone, Debug, Serialize)]
pub struct Partition {
    pub tcb: BTreeMap<String, String>,
    pub host_groups: Vec<String>,
    pub size: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct AnonymityReport {
    pub fleet: String,
    pub fleet_size: usize,
    /// Largest first, then by fingerprint for stable output.
    pub partitions: Vec<Partition>,
    pub min_set: usize,
    pub median_set: usize,
    pub max_set: usize,
    /// Hosts alone on their configuration. Their anonymity set is themselves.
    pub singletons: usize,
    /// Expected anonymity set size for a uniformly chosen host,
    /// `sum(n_i^2) / N`. Larger partitions contain more hosts and so are
    /// weighted more heavily, which the arithmetic mean of partition sizes
    /// fails to do.
    pub effective_set: f64,
    /// Shannon entropy over the partition distribution, in bits. Zero when
    /// every host looks alike.
    pub entropy_bits: f64,
    /// The TCB attributes that actually take more than one value across the
    /// fleet. **Not** necessarily the fields doing the deanonymizing: an
    /// attribute can vary without splitting anything another attribute does
    /// not already split (see `render`'s note on this distinction, and
    /// `it_names_the_attributes_that_actually_split_the_fleet` below).
    pub distinguishing_attributes: Vec<String>,
}

/// Canonical, unambiguous rendering of a TCB map — this string **is** a
/// partition's identity, so every attribute in the map contributes to it and
/// the derivation is spelled out here rather than left to a reader.
///
/// `BTreeMap` sorts the keys, so TOML table order cannot manufacture a
/// partition. The separators are length-prefixed so `{a: "b=c"}` cannot
/// collide with `{a: "b", c: ""}`.
///
/// Values are compared as **opaque byte strings**. `"0x0E"` and `"0x0e"` are
/// different configurations here, as are `"13"` and `"013"`. That is a choice,
/// not an oversight: these strings come from quote collateral, and normalizing
/// them would mean deciding which textual differences a relying party's parser
/// ignores — which this tool cannot know, and guessing wrong would merge two
/// genuinely distinguishable populations into one and overstate the anonymity
/// set. Normalize upstream if your collateral needs it.
fn fingerprint(tcb: &BTreeMap<String, String>) -> String {
    tcb.iter()
        .map(|(k, v)| format!("{}:{k}={}:{v}", k.len(), v.len()))
        .collect::<Vec<_>>()
        .join("|")
}

pub fn partition(fleet: &Fleet) -> Result<AnonymityReport, AnonymityError> {
    if fleet.host.is_empty() {
        return Err(AnonymityError::EmptyFleet);
    }
    for h in &fleet.host {
        if h.count == 0 {
            return Err(AnonymityError::ZeroCount(h.id.clone()));
        }
        if h.tcb.is_empty() {
            return Err(AnonymityError::EmptyTcb(h.id.clone()));
        }
    }

    let mut by_fp: BTreeMap<String, Partition> = BTreeMap::new();
    for h in &fleet.host {
        let e = by_fp
            .entry(fingerprint(&h.tcb))
            .or_insert_with(|| Partition {
                tcb: h.tcb.clone(),
                host_groups: Vec::new(),
                size: 0,
            });
        e.host_groups.push(h.id.clone());
        e.size += h.count;
    }

    let mut partitions: Vec<Partition> = by_fp.into_values().collect();
    // Largest first; ties broken by fingerprint, which BTreeMap already
    // ordered, so `sort_by_key` must be stable — it is.
    partitions.sort_by_key(|p| std::cmp::Reverse(p.size));

    let fleet_size = fleet.size();
    let sizes: Vec<usize> = partitions.iter().map(|p| p.size).collect();
    let n = fleet_size as f64;

    let mut sorted = sizes.clone();
    sorted.sort_unstable();

    // Which attributes take more than one value across the fleet? A key that
    // is absent from some hosts counts as varying, because absence is
    // observable.
    let all_keys: BTreeSet<&String> = fleet.host.iter().flat_map(|h| h.tcb.keys()).collect();
    let distinguishing_attributes = all_keys
        .into_iter()
        .filter(|k| {
            let values: BTreeSet<Option<&String>> =
                fleet.host.iter().map(|h| h.tcb.get(*k)).collect();
            values.len() > 1
        })
        .cloned()
        .collect();

    Ok(AnonymityReport {
        fleet: fleet.name.clone(),
        fleet_size,
        min_set: *sorted.first().expect("non-empty"),
        median_set: sorted[sorted.len() / 2],
        max_set: *sorted.last().expect("non-empty"),
        singletons: sizes.iter().filter(|&&s| s == 1).count(),
        // Cast to f64 before multiplying: `(s * s)` in `usize` panics on
        // overflow in debug and silently wraps in release for a hostile
        // user-supplied `count` (e.g. 5_000_000_000), which would violate the
        // no-panics-on-malformed-input constraint.
        effective_set: sizes.iter().map(|&s| (s as f64) * (s as f64)).sum::<f64>() / n,
        // `+ 0.0` so a zero-leakage fleet stores (and therefore serializes,
        // via both `render` and `to_json`) positive zero rather than
        // negative zero: the sum below is negated, and IEEE 754 gives
        // `-0.0 + 0.0 == 0.0`. Fixed at the source rather than only in
        // `render`'s formatting, because `to_json` serializes this field
        // directly (`derive(Serialize)`) and previously carried the raw
        // negated sum into the committed `results/deterministic/
        // anonymity-uniform.json` artifact as `"entropy_bits": -0.0`.
        entropy_bits: -sizes
            .iter()
            .map(|&s| {
                let p = s as f64 / n;
                p * p.log2()
            })
            .sum::<f64>()
            + 0.0,
        distinguishing_attributes,
        partitions,
    })
}

impl AnonymityReport {
    pub fn render(&self) -> String {
        let mut out = format!(
            "Anonymity sets for fleet `{}`\n\n  fleet size            {}\n  \
             distinct TCB configs  {}\n",
            self.fleet,
            self.fleet_size,
            self.partitions.len()
        );
        out.push_str(&format!(
            "  smallest set          {}\n  median set            {}\n  largest set           {}\n  \
             singletons            {}\n  effective set size    {:.2}\n  entropy               {:.3} bits\n\n",
            self.min_set,
            self.median_set,
            self.max_set,
            self.singletons,
            self.effective_set,
            // `entropy_bits` is already guaranteed non-negative-zero at
            // construction (see `partition`'s `+ 0.0`), so this is a plain
            // field read, not a second correction.
            self.entropy_bits
        ));

        out.push_str(&format!(
            "  {:<8} {:<10} {}\n",
            "SIZE", "GROUPS", "TCB CONFIGURATION"
        ));
        for p in &self.partitions {
            let tcb = p
                .tcb
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&format!(
                "  {:<8} {:<10} {}\n",
                p.size,
                p.host_groups.join(","),
                tcb
            ));
        }

        if self.distinguishing_attributes.is_empty() {
            out.push_str(
                "\nNo TCB attribute varies across this fleet, so quote collateral does not \
                 partition it.\n",
            );
        } else {
            // "that vary", not "doing the deanonymizing": the computation
            // finds attributes taking more than one value, which is not the
            // same as attributes that split anything another attribute does
            // not already split — in the drifted example `pcs_chain` and
            // `qe_identity` vary but partition nothing new, and an operator
            // reading the stronger claim would remediate the wrong field.
            out.push_str(&format!(
                "\nThe attributes that vary across this fleet: {}.\n\
                 (Varying is not the same as partitioning: some of these may split nothing\n\
                 that another attribute does not already split.)\n",
                self.distinguishing_attributes.join(", ")
            ));
        }
        if self.singletons > 0 {
            out.push_str(&format!(
                "\n{} host(s) are alone on their TCB configuration. Their anonymity set is \
                 themselves,\nand no credential scheme can help them: the quote collateral \
                 identifies the machine\nbefore the credential is even presented.\n",
                self.singletons
            ));
        }
        out
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("AnonymityReport is serializable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNIFORM: &str = r#"
name = "uniform"

[[host]]
id = "pool-a"
count = 12
[host.tcb]
tdx_module = "1.5.05"
cpu_svn = "0x0e"
pce_svn = "13"
"#;

    const DRIFTED: &str = r#"
name = "drifted"

[[host]]
id = "pool-a"
count = 8
[host.tcb]
tdx_module = "1.5.05"
cpu_svn = "0x0e"
pce_svn = "13"

[[host]]
id = "pool-b"
count = 3
[host.tcb]
tdx_module = "1.5.05"
cpu_svn = "0x0e"
pce_svn = "12"

[[host]]
id = "straggler"
[host.tcb]
tdx_module = "1.5.03"
cpu_svn = "0x0d"
pce_svn = "12"
"#;

    #[test]
    fn a_single_tcb_fleet_is_one_partition_the_size_of_the_fleet() {
        let f: Fleet = toml::from_str(UNIFORM).unwrap();
        let r = partition(&f).unwrap();
        assert_eq!(r.fleet_size, 12);
        assert_eq!(r.partitions.len(), 1);
        assert_eq!(r.partitions[0].size, 12);
        assert_eq!(r.min_set, 12);
        assert_eq!(r.singletons, 0);
        assert!(r.distinguishing_attributes.is_empty(), "nothing varies");
    }

    #[test]
    fn a_drifted_fleet_reports_its_partition_sizes() {
        let f: Fleet = toml::from_str(DRIFTED).unwrap();
        let r = partition(&f).unwrap();
        assert_eq!(r.fleet_size, 12);
        let sizes: Vec<usize> = r.partitions.iter().map(|p| p.size).collect();
        assert_eq!(sizes, vec![8, 3, 1], "partitions are ordered largest first");
        assert_eq!(r.min_set, 1);
        assert_eq!(r.max_set, 8);
        assert_eq!(
            r.singletons, 1,
            "one host is alone on its TCB configuration"
        );
    }

    #[test]
    fn it_names_the_attributes_that_actually_split_the_fleet() {
        let f: Fleet = toml::from_str(DRIFTED).unwrap();
        let r = partition(&f).unwrap();
        let mut got = r.distinguishing_attributes.clone();
        got.sort();
        assert_eq!(got, vec!["cpu_svn", "pce_svn", "tdx_module"]);
    }

    #[test]
    fn an_attribute_that_is_constant_is_not_reported_as_distinguishing() {
        let src = r#"
name = "one-field-varies"
[[host]]
id = "a"
count = 5
[host.tcb]
tdx_module = "1.5.05"
pce_svn = "13"
[[host]]
id = "b"
count = 5
[host.tcb]
tdx_module = "1.5.05"
pce_svn = "12"
"#;
        let f: Fleet = toml::from_str(src).unwrap();
        let r = partition(&f).unwrap();
        assert_eq!(r.distinguishing_attributes, vec!["pce_svn".to_string()]);
    }

    #[test]
    fn effective_set_size_is_the_size_weighted_mean_not_the_arithmetic_one() {
        // 8/3/1: the arithmetic mean of the partition sizes is 4, but a
        // randomly chosen host sits in a set of expected size
        // (8*8 + 3*3 + 1*1)/12 = 6.17. Reporting 4 would understate it and
        // reporting 12 would overstate it wildly.
        let f: Fleet = toml::from_str(DRIFTED).unwrap();
        let r = partition(&f).unwrap();
        assert!(
            (r.effective_set - 74.0 / 12.0).abs() < 1e-9,
            "got {}",
            r.effective_set
        );
    }

    #[test]
    fn entropy_is_zero_for_a_uniform_fleet_and_positive_otherwise() {
        let uniform: Fleet = toml::from_str(UNIFORM).unwrap();
        assert!(partition(&uniform).unwrap().entropy_bits.abs() < 1e-12);
        let drifted: Fleet = toml::from_str(DRIFTED).unwrap();
        assert!(partition(&drifted).unwrap().entropy_bits > 0.0);
    }

    /// `.abs() < 1e-12` above passes identically whether `entropy_bits` holds
    /// `0.0` or `-0.0`, so it cannot catch the sign. A committed artifact,
    /// `results/deterministic/anonymity-uniform.json`, shipped with
    /// `"entropy_bits": -0.0` because `to_json` (via `derive(Serialize)`)
    /// serializes the field directly, and the `+ 0.0` guard used to live only
    /// in `render`'s formatting. Check the sign, and check the actual JSON
    /// output specifically, since a fix that only touched `render` would
    /// leave this failing.
    #[test]
    fn entropy_bits_is_not_negative_zero_for_a_uniform_fleet() {
        let uniform: Fleet = toml::from_str(UNIFORM).unwrap();
        let r = partition(&uniform).unwrap();
        assert!(
            r.entropy_bits.is_sign_positive(),
            "entropy_bits is -0.0, which round-trips into JSON as \"-0.0\""
        );
        let v = r.to_json();
        assert_eq!(
            v["entropy_bits"].to_string(),
            "0.0",
            "the committed JSON artifact must not read -0.0: {v}"
        );
    }

    #[test]
    fn hosts_differing_only_in_key_order_land_in_one_partition() {
        // TOML table order must not manufacture a partition. If it did, the
        // tool would report fake fragmentation and the paper's headline
        // number would be an artifact of file formatting.
        let src = r#"
name = "order"
[[host]]
id = "a"
[host.tcb]
alpha = "1"
beta = "2"
[[host]]
id = "b"
[host.tcb]
beta = "2"
alpha = "1"
"#;
        let f: Fleet = toml::from_str(src).unwrap();
        assert_eq!(partition(&f).unwrap().partitions.len(), 1);
    }

    #[test]
    fn tcb_values_are_compared_as_opaque_bytes_without_normalization() {
        // Stated behaviour, pinned: differing case is a differing
        // configuration. If this ever changes it must change deliberately,
        // because merging two populations overstates the anonymity set.
        let src = r#"
name = "case"
[[host]]
id = "a"
[host.tcb]
cpu_svn = "0x0e"
[[host]]
id = "b"
[host.tcb]
cpu_svn = "0x0E"
"#;
        let f: Fleet = toml::from_str(src).unwrap();
        assert_eq!(partition(&f).unwrap().partitions.len(), 2);
    }

    #[test]
    fn every_tcb_attribute_contributes_to_the_partition_identity() {
        // A fingerprint that dropped a field would silently merge two
        // distinguishable populations. Vary one attribute at a time and
        // require each to split the fleet.
        // All SIX attributes the shipped examples use. Omitting one — this
        // list previously stopped at five — leaves the single test standing
        // between the paper and an overstated anonymity set blind to exactly
        // the kind of omission it exists to catch.
        let fields = [
            "tdx_module",
            "cpu_svn",
            "pce_svn",
            "microcode",
            "qe_identity",
            "pcs_chain",
        ];
        for varied in fields {
            let host = |id: &str, value: &str| {
                let mut lines = format!("[[host]]\nid = \"{id}\"\n[host.tcb]\n");
                for f in fields {
                    let v = if f == varied { value } else { "same" };
                    lines.push_str(&format!("{f} = \"{v}\"\n"));
                }
                lines
            };
            let src = format!("name = \"vary\"\n{}{}", host("a", "one"), host("b", "two"));
            let f: Fleet = toml::from_str(&src).unwrap();
            assert_eq!(
                partition(&f).unwrap().partitions.len(),
                2,
                "varying `{varied}` did not split the fleet, so it is missing from the fingerprint"
            );
        }
    }

    #[test]
    fn a_host_missing_an_attribute_others_declare_is_its_own_partition() {
        // Absent is not the same as equal. A host whose quote omits a field
        // is distinguishable from one that reports it.
        let src = r#"
name = "missing"
[[host]]
id = "a"
[host.tcb]
tdx_module = "1.5.05"
pce_svn = "13"
[[host]]
id = "b"
[host.tcb]
tdx_module = "1.5.05"
"#;
        let f: Fleet = toml::from_str(src).unwrap();
        assert_eq!(partition(&f).unwrap().partitions.len(), 2);
    }

    #[test]
    fn an_empty_fleet_is_an_error_not_a_division_by_zero() {
        let f: Fleet = toml::from_str("name = \"empty\"\n").unwrap();
        assert!(partition(&f).is_err());
    }

    #[test]
    fn a_zero_count_host_is_rejected() {
        let src = "name = \"z\"\n[[host]]\nid = \"a\"\ncount = 0\n[host.tcb]\nx = \"1\"\n";
        let f: Fleet = toml::from_str(src).unwrap();
        assert!(partition(&f).is_err());
    }

    #[test]
    fn a_host_with_no_tcb_attributes_is_rejected() {
        // An empty TCB describes nothing and would silently merge every such
        // host into one enormous, wrong anonymity set.
        let src = "name = \"z\"\n[[host]]\nid = \"a\"\n[host.tcb]\n";
        let f: Fleet = toml::from_str(src).unwrap();
        assert!(partition(&f).is_err());
    }

    #[test]
    fn an_unknown_top_level_key_is_rejected_rather_than_ignored() {
        // `[[hosts]]` (plural) is the typo an operator would actually make
        // for the array-of-tables key `[[host]]` — a scalar `hosts = 5`
        // exercises the same `deny_unknown_fields` path but is not the shape
        // this test's name and comment are about.
        let src = "name = \"z\"\n[[hosts]]\nid = \"a\"\n[hosts.tcb]\nx = \"1\"\n";
        assert!(
            toml::from_str::<Fleet>(src).is_err(),
            "`[[hosts]]` is a typo for `[[host]]`"
        );
    }

    #[test]
    fn both_shipped_examples_load_and_partition() {
        for name in ["fleet-uniform", "fleet-drifted"] {
            let p = format!("examples/{name}.toml");
            let f = Fleet::load(std::path::Path::new(&p)).unwrap_or_else(|e| panic!("{p}: {e}"));
            partition(&f).unwrap_or_else(|e| panic!("{p}: {e}"));
        }
    }

    /// `median_set` is otherwise never pinned by any test in this file or in
    /// `tests/acceptance.rs`: every other test checks `min_set`, `max_set`,
    /// `singletons`, `effective_set` and `entropy_bits`, but nothing checks
    /// that the middle of the sorted partition sizes is reported correctly.
    /// `median_set: 0` (or any other single-line substitution) would leave
    /// every other test in this suite green.
    #[test]
    fn median_set_is_the_middle_of_the_sorted_partition_sizes() {
        // DRIFTED's partitions sort to sizes [8, 3, 1] largest-first, i.e.
        // [1, 3, 8] ascending; the middle element is 3.
        let f: Fleet = toml::from_str(DRIFTED).unwrap();
        assert_eq!(partition(&f).unwrap().median_set, 3);
    }

    /// Correct today (`by_fp.into_values()` yields ascending fingerprint
    /// order and `sort_by_key` is stable) but unpinned: nothing asserts it,
    /// and Task 12 commits byte-stable `results/` artifacts that CI diffs, so
    /// a future switch to `sort_unstable_by_key` would silently reorder equal
    /// partitions with this whole suite green.
    #[test]
    fn equal_size_partitions_keep_deterministic_fingerprint_order() {
        let src = r#"
name = "tie"
[[host]]
id = "a"
count = 5
[host.tcb]
x = "1"
[[host]]
id = "b"
count = 5
[host.tcb]
x = "2"
"#;
        let f: Fleet = toml::from_str(src).unwrap();
        let r = partition(&f).unwrap();
        assert_eq!(
            r.partitions[0].tcb.get("x").unwrap(),
            "1",
            "ties break by ascending fingerprint order"
        );
        assert_eq!(r.partitions[1].tcb.get("x").unwrap(), "2");
    }

    /// The doc comment on `fingerprint` claims the length-prefixing prevents
    /// a value containing the `|` separator from colliding with a fleet that
    /// split the same bytes across two keys. Nothing else in this file
    /// exercises that claim: removing the length prefixes (falling back to a
    /// naive `"{k}={v}"` join) is a small, plausible-looking change that
    /// would leave every other test in this suite green, because none of
    /// their TCB values contain `|` or `=`.
    #[test]
    fn length_prefixing_stops_a_value_containing_the_separator_from_colliding() {
        let src = r#"
name = "collision"
[[host]]
id = "one-field"
[host.tcb]
a = "x|b=y"
[[host]]
id = "two-fields"
[host.tcb]
a = "x"
b = "y"
"#;
        let f: Fleet = toml::from_str(src).unwrap();
        assert_eq!(
            partition(&f).unwrap().partitions.len(),
            2,
            "a `|`-bearing value must not collide with a genuinely different TCB map"
        );
    }

    /// The report-content analogue of `render_prints_every_evidence_field_
    /// from_the_report` in `pool.rs`: every real invocation of `partition`
    /// on the shipped examples has `fleet_size` equal to the sum of the
    /// printed partition sizes, `min_set`/`max_set` matching the smallest and
    /// largest printed row, and so on, so a run through real data cannot
    /// catch `render` swapping `min_set` and `max_set`, mislabeling a column,
    /// or silently dropping a field. Build a report by hand, with every
    /// numeric field a distinct value no other field or literal could
    /// satisfy, and check every line `render` derives from it — the same
    /// check every review of this project has asked for.
    #[test]
    fn render_prints_every_field_from_the_report_not_a_neighbour_or_a_literal() {
        let mut tcb_a = BTreeMap::new();
        tcb_a.insert("alpha".to_string(), "1".to_string());
        tcb_a.insert("beta".to_string(), "2".to_string());
        let mut tcb_b = BTreeMap::new();
        tcb_b.insert("alpha".to_string(), "9".to_string());

        let report = AnonymityReport {
            fleet: "acme-audit".to_string(),
            // Deliberately not equal to the sum of the partition sizes below
            // (90 + 7 = 97), so a regression that reconstructs fleet size
            // from the partitions instead of printing the field prints a
            // different, catchable number.
            fleet_size: 555,
            partitions: vec![
                Partition {
                    tcb: tcb_a,
                    host_groups: vec!["g-one".to_string(), "g-one-b".to_string()],
                    size: 90,
                },
                Partition {
                    tcb: tcb_b,
                    host_groups: vec!["g-two".to_string()],
                    size: 7,
                },
            ],
            min_set: 7,
            median_set: 42,
            max_set: 90,
            singletons: 3,
            effective_set: 12.34,
            entropy_bits: 0.567,
            distinguishing_attributes: vec!["alpha".to_string(), "beta".to_string()],
        };
        let out = report.render();

        assert!(out.contains("fleet `acme-audit`"), "{out}");
        assert!(out.contains("fleet size            555"), "{out}");
        assert!(out.contains("distinct TCB configs  2"), "{out}");
        assert!(out.contains("smallest set          7"), "{out}");
        assert!(out.contains("median set            42"), "{out}");
        assert!(out.contains("largest set           90"), "{out}");
        assert!(out.contains("singletons            3"), "{out}");
        assert!(out.contains("effective set size    12.34"), "{out}");
        assert!(out.contains("entropy               0.567 bits"), "{out}");

        assert!(
            out.contains(&format!(
                "{:<8} {:<10} {}",
                90, "g-one,g-one-b", "alpha=1 beta=2"
            )),
            "the larger partition's own row must carry its own size, groups and TCB: {out}"
        );
        assert!(
            out.contains(&format!("{:<8} {:<10} {}", 7, "g-two", "alpha=9")),
            "the smaller partition's own row must carry its own size, groups and TCB: {out}"
        );

        assert!(
            out.contains("The attributes that vary across this fleet: alpha, beta."),
            "{out}"
        );
        assert!(
            out.contains("3 host(s) are alone on their TCB configuration"),
            "render must print the actual `singletons` field, not a hardcoded count: {out}"
        );
    }
}
