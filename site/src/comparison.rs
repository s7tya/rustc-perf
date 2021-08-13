//! Functionality for comparing
//! This is mainly used to build the triage report and the perf
//! comparison endpoints

use crate::api;
use crate::db::{ArtifactId, Benchmark, Profile, Scenario};
use crate::github;
use crate::load::SiteCtxt;
use crate::selector::{self, Tag};

use collector::Bound;
use log::debug;
use serde::Serialize;

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::hash::Hash;
use std::sync::Arc;

type BoxedError = Box<dyn Error + Send + Sync>;

pub async fn handle_triage(
    body: api::triage::Request,
    ctxt: &SiteCtxt,
) -> Result<api::triage::Response, BoxedError> {
    let start = body.start;
    let end = body.end;
    let master_commits = collector::master_commits().await?;

    let start_artifact = ctxt
        .artifact_id_for_bound(start.clone(), true)
        .ok_or(format!("could not find start commit for bound {:?}", start))?;
    let mut next = next_commit(&start_artifact, &master_commits)
        .map(|c| Bound::Commit(c.sha.clone()))
        .unwrap(); // TODO: handle no next commit

    let mut report = HashMap::new();
    let mut before = start.clone();

    let mut num_comparisons = 0;
    loop {
        let comparison = match compare_given_commits(
            before,
            next.clone(),
            "instructions:u".to_owned(),
            ctxt,
            &master_commits,
        )
        .await?
        {
            Some(c) => c,
            None => {
                log::info!(
                    "No data found for end bound {:?}. Ending comparison...",
                    next
                );
                break;
            }
        };
        num_comparisons += 1;
        log::info!(
            "Comparing {} to {}",
            comparison.b.artifact,
            comparison.a.artifact
        );

        // handle results of comparison
        populate_report(&comparison, &mut report).await;

        // Check that there is a next commit and that the
        // after commit is not equal to `end`
        match comparison.next(&master_commits).map(Bound::Commit) {
            Some(n) if Some(&next) != end.as_ref() => {
                before = next;
                next = n;
            }
            _ => break,
        }
    }
    let end = end.unwrap_or(next);

    let report = generate_report(&start, &end, report, num_comparisons).await;
    Ok(api::triage::Response(report))
}

pub async fn handle_compare(
    body: api::comparison::Request,
    ctxt: &SiteCtxt,
) -> Result<api::comparison::Response, BoxedError> {
    let master_commits = collector::master_commits().await?;
    let end = body.end;
    let comparison =
        compare_given_commits(body.start, end.clone(), body.stat, ctxt, &master_commits)
            .await?
            .ok_or_else(|| format!("could not find end commit for bound {:?}", end))?;

    let conn = ctxt.conn().await;
    let prev = comparison.prev(&master_commits);
    let next = comparison.next(&master_commits);
    let is_contiguous = comparison.is_contiguous(&*conn, &master_commits).await;
    let comparisons = comparison
        .statistics
        .into_iter()
        .map(|comparison| api::comparison::Comparison {
            benchmark: comparison.benchmark.to_string(),
            profile: comparison.profile.to_string(),
            scenario: comparison.scenario.to_string(),
            is_dodgy: comparison.is_dodgy(),
            is_significant: comparison.is_significant(),
            historical_statistics: comparison.variance.map(|v| v.data),
            statistics: comparison.results,
        })
        .collect();

    Ok(api::comparison::Response {
        prev,
        a: comparison.a.into(),
        b: comparison.b.into(),
        comparisons,
        next,
        is_contiguous,
    })
}

async fn populate_report(
    comparison: &Comparison,
    report: &mut HashMap<Option<Direction>, Vec<String>>,
) {
    if let Some(summary) = ComparisonSummary::summarize_comparison(comparison) {
        let confidence = summary.confidence();
        if confidence.is_atleast_probably_relevant() {
            if let Some(direction) = summary.direction() {
                let entry = report
                    .entry(confidence.is_definitely_relevant().then(|| direction))
                    .or_default();

                entry.push(summary.write(comparison).await)
            }
        }
    }
}

pub struct ComparisonSummary {
    /// Significant comparisons ordered by magnitude
    comparisons: Vec<TestResultComparison>,
}

impl ComparisonSummary {
    pub fn summarize_comparison(comparison: &Comparison) -> Option<ComparisonSummary> {
        let mut comparisons = comparison
            .get_individual_comparisons()
            .filter(|c| c.is_significant())
            .cloned()
            .collect::<Vec<_>>();
        // Skip empty commits, sometimes happens if there's a compiler bug or so.
        if comparisons.len() == 0 {
            return None;
        }

        let cmp = |b1: &TestResultComparison, b2: &TestResultComparison| {
            b2.relative_change()
                .abs()
                .partial_cmp(&b1.relative_change().abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        };
        comparisons.sort_by(cmp);

        Some(ComparisonSummary { comparisons })
    }

    /// The direction of the changes
    pub fn direction(&self) -> Option<Direction> {
        if self.comparisons.len() == 0 {
            return None;
        }

        let (regressions, improvements): (Vec<&TestResultComparison>, _) =
            self.comparisons.iter().partition(|c| c.is_regression());

        if regressions.len() == 0 {
            return Some(Direction::Improvement);
        }

        if improvements.len() == 0 {
            return Some(Direction::Regression);
        }

        let total_num = self.comparisons.len();
        let regressions_ratio = regressions.len() as f64 / total_num as f64;

        let has_medium_and_above_regressions = regressions
            .iter()
            .any(|c| c.magnitude().is_medium_or_above());
        let has_medium_and_above_improvements = improvements
            .iter()
            .any(|c| c.magnitude().is_medium_or_above());
        match (
            has_medium_and_above_improvements,
            has_medium_and_above_regressions,
        ) {
            (true, true) => return Some(Direction::Mixed),
            (true, false) => {
                if regressions_ratio >= 0.15 {
                    Some(Direction::Mixed)
                } else {
                    Some(Direction::Improvement)
                }
            }
            (false, true) => {
                if regressions_ratio < 0.85 {
                    Some(Direction::Mixed)
                } else {
                    Some(Direction::Regression)
                }
            }
            (false, false) => {
                if regressions_ratio >= 0.1 && regressions_ratio <= 0.9 {
                    Some(Direction::Mixed)
                } else if regressions_ratio <= 0.1 {
                    Some(Direction::Improvement)
                } else {
                    Some(Direction::Regression)
                }
            }
        }
    }

    pub fn relevant_changes<'a>(&'a self) -> [Option<&TestResultComparison>; 2] {
        match self.direction() {
            Some(Direction::Improvement) => [self.largest_improvement(), None],
            Some(Direction::Regression) => [self.largest_regression(), None],
            Some(Direction::Mixed) => [self.largest_improvement(), self.largest_regression()],
            None => [None, None],
        }
    }

    pub fn largest_improvement(&self) -> Option<&TestResultComparison> {
        self.comparisons
            .iter()
            .filter(|s| !s.is_regression())
            .next()
    }

    pub fn largest_regression(&self) -> Option<&TestResultComparison> {
        self.comparisons.iter().filter(|s| s.is_regression()).next()
    }

    pub fn confidence(&self) -> ComparisonConfidence {
        let mut num_small_changes = 0;
        let mut num_medium_changes = 0;
        let mut num_large_changes = 0;
        let mut num_very_large_changes = 0;
        for c in self.comparisons.iter() {
            match c.magnitude() {
                Magnitude::Small => num_small_changes += 1,
                Magnitude::Medium => num_medium_changes += 1,
                Magnitude::Large => num_large_changes += 1,
                Magnitude::VeryLarge => num_very_large_changes += 1,
            }
        }

        match (
            num_medium_changes,
            num_large_changes,
            num_very_large_changes,
        ) {
            (_, _, vl) if vl > 0 => ComparisonConfidence::DefinitelyRelevant,
            (m, l, _) if m + (l * 2) > 4 => ComparisonConfidence::DefinitelyRelevant,
            (m, l, _) if m > 0 || l > 0 => ComparisonConfidence::ProbablyRelevant,
            _ => {
                if num_small_changes > 8 {
                    ComparisonConfidence::ProbablyRelevant
                } else {
                    ComparisonConfidence::MaybeRelevant
                }
            }
        }
    }

    async fn write(&self, comparison: &Comparison) -> String {
        use std::fmt::Write;

        let mut result = if let Some(pr) = comparison.b.pr {
            let title = github::pr_title(pr).await;
            format!(
                "{} [#{}](https://github.com/rust-lang/rust/issues/{})\n",
                title, pr, pr
            )
        } else {
            String::from("<Unknown Change>\n")
        };
        let start = &comparison.a.artifact;
        let end = &comparison.b.artifact;
        let link = &compare_link(start, end);

        for change in self.relevant_changes().iter().filter_map(|s| *s) {
            write!(result, "- ").unwrap();
            change.summary_line(&mut result, Some(link))
        }
        result
    }
}

/// The amount of confidence we have that a comparison actually represents a real
/// change in the performance characteristics.
#[derive(Clone, Copy, Debug)]
pub enum ComparisonConfidence {
    MaybeRelevant,
    ProbablyRelevant,
    DefinitelyRelevant,
}

impl ComparisonConfidence {
    pub fn is_definitely_relevant(self) -> bool {
        matches!(self, Self::DefinitelyRelevant)
    }

    pub fn is_atleast_probably_relevant(self) -> bool {
        matches!(self, Self::DefinitelyRelevant | Self::ProbablyRelevant)
    }
}

/// Compare two bounds on a given stat
///
/// Returns Ok(None) when no data for the end bound is present
pub async fn compare(
    start: Bound,
    end: Bound,
    stat: String,
    ctxt: &SiteCtxt,
) -> Result<Option<Comparison>, BoxedError> {
    let master_commits = collector::master_commits().await?;
    compare_given_commits(start, end, stat, ctxt, &master_commits).await
}

/// Compare two bounds on a given stat
async fn compare_given_commits(
    start: Bound,
    end: Bound,
    stat: String,
    ctxt: &SiteCtxt,
    master_commits: &[collector::MasterCommit],
) -> Result<Option<Comparison>, BoxedError> {
    let a = ctxt
        .artifact_id_for_bound(start.clone(), true)
        .ok_or(format!("could not find start commit for bound {:?}", start))?;
    let b = match ctxt.artifact_id_for_bound(end.clone(), false) {
        Some(b) => b,
        None => return Ok(None),
    };
    let aids = Arc::new(vec![a.clone(), b.clone()]);

    // get all crates, cache, and profile combinations for the given stat
    let query = selector::Query::new()
        .set::<String>(Tag::Benchmark, selector::Selector::All)
        .set::<String>(Tag::Scenario, selector::Selector::All)
        .set::<String>(Tag::Profile, selector::Selector::All)
        .set(Tag::Metric, selector::Selector::One(stat.clone()));

    // `responses` contains series iterators. The first element in the iterator is the data
    // for `a` and the second is the data for `b`
    let mut responses = ctxt.statistic_series(query.clone(), aids).await?;

    let conn = ctxt.conn().await;
    let statistics_for_a = statistics_from_series(&mut responses);
    let statistics_for_b = statistics_from_series(&mut responses);

    let variances = BenchmarkVariances::calculate(ctxt, a.clone(), master_commits, stat).await?;
    let statistics = statistics_for_a
        .into_iter()
        .filter_map(|(test_case, a)| {
            statistics_for_b
                .get(&test_case)
                .map(|&b| TestResultComparison {
                    benchmark: test_case.0,
                    profile: test_case.1,
                    scenario: test_case.2,
                    variance: variances
                        .as_ref()
                        .and_then(|v| v.data.get(&test_case).cloned()),
                    results: (a, b),
                })
        })
        .collect();
    Ok(Some(Comparison {
        a: ArtifactDescription::for_artifact(&*conn, a.clone(), master_commits).await,
        b: ArtifactDescription::for_artifact(&*conn, b.clone(), master_commits).await,
        statistics,
    }))
}

fn previous_commits(
    mut from: ArtifactId,
    n: usize,
    master_commits: &[collector::MasterCommit],
) -> Vec<ArtifactId> {
    let mut prevs = Vec::with_capacity(n);
    while prevs.len() < n {
        match prev_commit(&from, master_commits) {
            Some(c) => {
                let new = ArtifactId::Commit(database::Commit {
                    sha: c.sha.clone(),
                    date: database::Date(c.time),
                });
                from = new.clone();
                prevs.push(new);
            }
            None => break,
        }
    }
    prevs
}

/// Detailed description of a specific artifact
#[derive(Debug, Clone)]
pub struct ArtifactDescription {
    /// The artifact in question
    pub artifact: ArtifactId,
    /// The pr of the artifact if known
    pub pr: Option<u32>,
    /// Bootstrap data in the form "$crate" -> nanoseconds
    pub bootstrap: HashMap<String, u64>,
}

type StatisticsMap = HashMap<TestCase, f64>;
type TestCase = (Benchmark, Profile, Scenario);

impl ArtifactDescription {
    /// For the given `ArtifactId`, consume the first datapoint in each of the given `SeriesResponse`
    ///
    /// It is assumed that the provided `ArtifactId` matches the artifact id of the next data
    /// point for all of `SeriesResponse<T>`. If this is not true, this function will panic.
    async fn for_artifact(
        conn: &dyn database::Connection,
        artifact: ArtifactId,
        master_commits: &[collector::MasterCommit],
    ) -> Self {
        let bootstrap = conn
            .get_bootstrap_by_crate(&[conn.artifact_id(&artifact).await])
            .await;
        let bootstrap = bootstrap
            .into_iter()
            .filter_map(|(k, mut v)| {
                v.pop()
                    .unwrap_or_default()
                    // FIXME: if we're hovering right at the 1 second mark,
                    // this might mean we end up with a Some for one commit and
                    // a None for the other commit. Ultimately it doesn't matter
                    // that much -- we'll mostly just ignore such results.
                    // Anything less than a second in wall-time measurements is
                    // always going to be pretty high variance just from process
                    // startup overheads and such, though, so we definitely
                    // don't want to compare those values.
                    .filter(|v| v.as_secs() >= 1)
                    .map(|v| (k, v.as_nanos() as u64))
            })
            .collect::<HashMap<_, _>>();

        let pr = if let ArtifactId::Commit(c) = &artifact {
            if let Some(m) = master_commits.iter().find(|m| m.sha == c.sha) {
                m.pr
            } else {
                conn.pr_of(&c.sha).await
            }
        } else {
            None
        };

        Self {
            pr,
            artifact,
            bootstrap,
        }
    }
}

fn statistics_from_series<T>(series: &mut [selector::SeriesResponse<T>]) -> StatisticsMap
where
    T: Iterator<Item = (ArtifactId, Option<f64>)>,
{
    let mut stats: StatisticsMap = HashMap::new();
    for response in series {
        let (_, point) = response.series.next().expect("must have element");

        let value = if let Some(v) = point {
            v
        } else {
            continue;
        };
        let benchmark = *response.path.get::<Benchmark>().unwrap();
        let profile = *response.path.get::<Profile>().unwrap();
        let scenario = *response.path.get::<Scenario>().unwrap();
        stats.insert((benchmark, profile, scenario), value);
    }
    stats
}

impl From<ArtifactDescription> for api::comparison::ArtifactDescription {
    fn from(data: ArtifactDescription) -> Self {
        api::comparison::ArtifactDescription {
            commit: match data.artifact.clone() {
                ArtifactId::Commit(c) => c.sha,
                ArtifactId::Tag(t) => t,
            },
            date: if let ArtifactId::Commit(c) = &data.artifact {
                Some(c.date)
            } else {
                None
            },
            pr: data.pr,
            bootstrap: data.bootstrap,
        }
    }
}

// A comparison of two artifacts
pub struct Comparison {
    pub a: ArtifactDescription,
    pub b: ArtifactDescription,
    /// Statistics based on test case
    pub statistics: HashSet<TestResultComparison>,
}

impl Comparison {
    /// Gets the previous commit before `a`
    pub fn prev(&self, master_commits: &[collector::MasterCommit]) -> Option<String> {
        prev_commit(&self.a.artifact, master_commits).map(|c| c.sha.clone())
    }

    /// Determines if `a` and `b` are contiguous
    pub async fn is_contiguous(
        &self,
        conn: &dyn database::Connection,
        master_commits: &[collector::MasterCommit],
    ) -> bool {
        match (&self.a.artifact, &self.b.artifact) {
            (ArtifactId::Commit(a), ArtifactId::Commit(b)) => {
                if let Some(b) = master_commits.iter().find(|c| c.sha == b.sha) {
                    b.parent_sha == a.sha
                } else {
                    conn.parent_of(&b.sha).await.map_or(false, |p| p == a.sha)
                }
            }
            _ => false,
        }
    }

    /// Gets the sha of the next commit after `b`
    pub fn next(&self, master_commits: &[collector::MasterCommit]) -> Option<String> {
        next_commit(&self.b.artifact, master_commits).map(|c| c.sha.clone())
    }

    fn get_individual_comparisons(&self) -> impl Iterator<Item = &TestResultComparison> {
        self.statistics.iter().filter(|b| b.profile != Profile::Doc)
    }
}

/// A description of the amount of variance a certain benchmark is historically
/// experiencing at a given point in time.
pub struct BenchmarkVariances {
    /// Variance data on a per test case basis
    pub data: HashMap<(Benchmark, Profile, Scenario), BenchmarkVariance>,
}

impl BenchmarkVariances {
    const NUM_PREVIOUS_COMMITS: usize = 100;
    const MIN_PREVIOUS_COMMITS: usize = 50;

    async fn calculate(
        ctxt: &SiteCtxt,
        from: ArtifactId,
        master_commits: &[collector::MasterCommit],
        stat: String,
    ) -> Result<Option<Self>, BoxedError> {
        // get all crates, cache, and profile combinations for the given stat
        let query = selector::Query::new()
            .set::<String>(Tag::Benchmark, selector::Selector::All)
            .set::<String>(Tag::Scenario, selector::Selector::All)
            .set::<String>(Tag::Profile, selector::Selector::All)
            .set(Tag::Metric, selector::Selector::One(stat));

        let previous_commits = Arc::new(previous_commits(
            from,
            Self::NUM_PREVIOUS_COMMITS,
            master_commits,
        ));
        let mut previous_commit_series = ctxt
            .statistic_series(query, previous_commits.clone())
            .await?;

        let mut variance_data: HashMap<(Benchmark, Profile, Scenario), BenchmarkVariance> =
            HashMap::new();
        for _ in previous_commits.iter() {
            for (test_case, stat) in statistics_from_series(&mut previous_commit_series) {
                variance_data.entry(test_case).or_default().push(stat);
            }
        }
        if variance_data.len() < Self::MIN_PREVIOUS_COMMITS {
            return Ok(None);
        }

        for ((bench, _, _), results) in variance_data.iter_mut() {
            debug!("Calculating variance for: {}", bench);
            results.calculate_description();
        }
        Ok(Some(Self {
            data: variance_data,
        }))
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct BenchmarkVariance {
    data: Vec<f64>,
    description: BenchmarkVarianceDescription,
}

impl BenchmarkVariance {
    /// The ratio of change that we consider significant.
    const SIGNFICANT_DELTA_THRESHOLD: f64 = 0.01;
    /// The percentage of significant changes that we consider too high
    const SIGNFICANT_CHANGE_THRESHOLD: f64 = 5.0;
    /// The ratio of change that constitutes noisy data
    const NOISE_THRESHOLD: f64 = 0.001;

    fn push(&mut self, value: f64) {
        self.data.push(value);
    }

    fn mean(&self) -> f64 {
        self.data.iter().sum::<f64>() / self.data.len() as f64
    }

    fn calculate_description(&mut self) {
        self.description = BenchmarkVarianceDescription::Normal;

        let results_mean = self.mean();
        let mut deltas = self
            .data
            .windows(2)
            .map(|window| (window[0] - window[1]).abs())
            .collect::<Vec<_>>();
        deltas.sort_by(|d1, d2| d1.partial_cmp(d2).unwrap_or(std::cmp::Ordering::Equal));
        let non_significant = deltas
            .iter()
            .zip(self.data.iter())
            .take_while(|(&d, &r)| d / r < Self::SIGNFICANT_DELTA_THRESHOLD)
            .collect::<Vec<_>>();

        let percent_significant_changes =
            ((deltas.len() - non_significant.len()) as f64 / deltas.len() as f64) * 100.0;
        debug!(
            "Percent significant changes: {:.1}%",
            percent_significant_changes
        );

        if percent_significant_changes > Self::SIGNFICANT_CHANGE_THRESHOLD {
            self.description = BenchmarkVarianceDescription::HighlyVariable;
            return;
        }

        let delta_mean =
            non_significant.iter().map(|(&d, _)| d).sum::<f64>() / (non_significant.len() as f64);
        let ratio_change = delta_mean / results_mean;
        debug!("Ratio change: {:.3}", ratio_change);
        if ratio_change > Self::NOISE_THRESHOLD {
            self.description = BenchmarkVarianceDescription::Noisy;
        }
    }

    /// Whether we can trust this benchmark or not
    fn is_dodgy(&self) -> bool {
        matches!(
            self.description,
            BenchmarkVarianceDescription::Noisy | BenchmarkVarianceDescription::HighlyVariable
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "type", content = "percent")]
pub enum BenchmarkVarianceDescription {
    Normal,
    /// A highly variable benchmark that produces many significant changes.
    /// This might indicate a benchmark which is very sensitive to compiler changes.
    HighlyVariable,
    /// A noisy benchmark which is likely to see changes in performance simply between
    /// compiler runs.
    Noisy,
}

impl Default for BenchmarkVarianceDescription {
    fn default() -> Self {
        Self::Normal
    }
}

/// Gets the previous commit
pub fn prev_commit<'a>(
    artifact: &ArtifactId,
    master_commits: &'a [collector::MasterCommit],
) -> Option<&'a collector::MasterCommit> {
    match &artifact {
        ArtifactId::Commit(a) => {
            let current = master_commits.iter().find(|c| c.sha == a.sha)?;
            master_commits.iter().find(|c| c.sha == current.parent_sha)
        }
        ArtifactId::Tag(_) => None,
    }
}

/// Gets the next commit
pub fn next_commit<'a>(
    artifact: &ArtifactId,
    master_commits: &'a [collector::MasterCommit],
) -> Option<&'a collector::MasterCommit> {
    match artifact {
        ArtifactId::Commit(b) => master_commits.iter().find(|c| c.parent_sha == b.sha),
        ArtifactId::Tag(_) => None,
    }
}

// A single comparison between two test results
#[derive(Debug, Clone)]
pub struct TestResultComparison {
    benchmark: Benchmark,
    profile: Profile,
    scenario: Scenario,
    variance: Option<BenchmarkVariance>,
    results: (f64, f64),
}

impl TestResultComparison {
    /// The amount of relative change considered significant when
    /// the test case is not dodgy
    const SIGNIFICANT_RELATIVE_CHANGE_THRESHOLD: f64 = 0.002;

    /// The amount of relative change considered significant when
    /// the test case is dodgy
    const SIGNIFICANT_RELATIVE_CHANGE_THRESHOLD_DODGY: f64 = 0.008;

    fn is_regression(&self) -> bool {
        let (a, b) = self.results;
        b > a
    }

    fn is_significant(&self) -> bool {
        self.relative_change().abs() > self.signifcance_threshold()
    }

    fn signifcance_threshold(&self) -> f64 {
        if self.is_dodgy() {
            Self::SIGNIFICANT_RELATIVE_CHANGE_THRESHOLD_DODGY
        } else {
            Self::SIGNIFICANT_RELATIVE_CHANGE_THRESHOLD
        }
    }

    fn magnitude(&self) -> Magnitude {
        let mag = self.relative_change().abs();
        let threshold = self.signifcance_threshold();
        if mag < threshold * 3.0 {
            Magnitude::Small
        } else if mag < threshold * 10.0 {
            Magnitude::Medium
        } else if mag < threshold * 25.0 {
            Magnitude::Large
        } else {
            Magnitude::VeryLarge
        }
    }

    fn is_dodgy(&self) -> bool {
        self.variance
            .as_ref()
            .map(|v| v.is_dodgy())
            .unwrap_or(false)
    }

    fn relative_change(&self) -> f64 {
        let (a, b) = self.results;
        (b - a) / a
    }

    fn direction(&self) -> Direction {
        if self.relative_change() > 0.0 {
            Direction::Regression
        } else {
            Direction::Improvement
        }
    }

    pub fn summary_line(&self, summary: &mut String, link: Option<&str>) {
        use std::fmt::Write;
        let magnitude = self.magnitude();

        let percent = self.relative_change() * 100.0;
        write!(
            summary,
            "{} {} in {}",
            magnitude,
            self.direction(),
            match link {
                Some(l) => format!("[instruction counts]({})", l),
                None => "instruction counts".into(),
            }
        )
        .unwrap();
        writeln!(
            summary,
            " (up to {:.1}% on `{}` builds of `{}`)",
            percent, self.scenario, self.benchmark
        )
        .unwrap();
    }
}

impl std::cmp::PartialEq for TestResultComparison {
    fn eq(&self, other: &Self) -> bool {
        self.benchmark == other.benchmark
            && self.profile == other.profile
            && self.scenario == other.scenario
    }
}

impl std::cmp::Eq for TestResultComparison {}

impl std::hash::Hash for TestResultComparison {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.benchmark.hash(state);
        self.profile.hash(state);
        self.scenario.hash(state);
    }
}

// The direction of a performance change
#[derive(PartialEq, Eq, Hash, Debug)]
pub enum Direction {
    Improvement,
    Regression,
    Mixed,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            Direction::Improvement => "improvement",
            Direction::Regression => "regression",
            Direction::Mixed => "mixed",
        };
        write!(f, "{}", description)
    }
}

/// The relative size of a performance change
#[derive(Debug)]
enum Magnitude {
    Small,
    Medium,
    Large,
    VeryLarge,
}

impl Magnitude {
    fn is_medium_or_above(&self) -> bool {
        !matches!(self, Self::Small)
    }
}

impl std::fmt::Display for Magnitude {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            Self::Small => "Small",
            Self::Medium => "Moderate",
            Self::Large => "Large",
            Self::VeryLarge => "Very large",
        };
        f.write_str(s)
    }
}

async fn generate_report(
    start: &Bound,
    end: &Bound,
    mut report: HashMap<Option<Direction>, Vec<String>>,
    num_comparisons: usize,
) -> String {
    fn fmt_bound(bound: &Bound) -> String {
        match bound {
            Bound::Commit(s) => s.to_owned(),
            Bound::Date(s) => s.format("%Y-%m-%d").to_string(),
            _ => "???".to_owned(),
        }
    }
    let start = fmt_bound(start);
    let end = fmt_bound(end);
    let regressions = report
        .remove(&Some(Direction::Regression))
        .unwrap_or_default();
    let improvements = report
        .remove(&Some(Direction::Improvement))
        .unwrap_or_default();
    let mixed = report.remove(&Some(Direction::Mixed)).unwrap_or_default();
    let unlabeled = report.remove(&None).unwrap_or_default();
    let untriaged = match github::untriaged_perf_regressions().await {
        Ok(u) => u
            .iter()
            .map(|github::PullRequest { title, number }| {
                format!(
                    "- [#{} {}](https://github.com/rust-lang/rust/pull/{})",
                    number, title, number
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Err(e) => format!(
            "An **error** occurred when finding the untriaged PRs: {}",
            e
        ),
    };
    format!(
        r#####"# {date} Triage Log

TODO: Summary

Triage done by **@???**.
Revision range: [{first_commit}..{last_commit}](https://perf.rust-lang.org/?start={first_commit}&end={last_commit}&absolute=false&stat=instructions%3Au)
{num_comparisons} comparisons made in total
{num_def_relevant} definitely relevant comparisons and {num_prob_relevant} probably relevant comparisons

{num_regressions} Regressions, {num_improvements} Improvements, {num_mixed} Mixed; ??? of them in rollups

#### Regressions

{regressions}

#### Improvements

{improvements}

#### Mixed

{mixed}

#### Probably changed

The following is a list of comparisons which *probably* represent real performance changes,
but we're not 100% sure. Please move things from this category into the categories
above for changes you think *are* definitely relevant and file an issue for each so that
we can consider how to change our heuristics.

{unlabeled}

#### Untriaged Pull Requests

{untriaged}

#### Nags requiring follow up

TODO: Nags

"#####,
        date = chrono::Utc::today().format("%Y-%m-%d"),
        first_commit = start,
        last_commit = end,
        num_comparisons = num_comparisons,
        num_def_relevant = regressions.len() + improvements.len() + mixed.len(),
        num_prob_relevant = unlabeled.len(),
        num_regressions = regressions.len(),
        num_improvements = improvements.len(),
        num_mixed = mixed.len(),
        regressions = regressions.join("\n\n"),
        improvements = improvements.join("\n\n"),
        mixed = mixed.join("\n\n"),
        unlabeled = unlabeled.join("\n\n"),
        untriaged = untriaged
    )
}

fn compare_link(start: &ArtifactId, end: &ArtifactId) -> String {
    let start = match &start {
        ArtifactId::Tag(a) => a,
        ArtifactId::Commit(c) => &c.sha,
    };
    let end = match &end {
        ArtifactId::Tag(a) => a,
        ArtifactId::Commit(c) => &c.sha,
    };
    format!(
        "https://perf.rust-lang.org/compare.html?start={}&end={}&stat=instructions:u",
        start, end
    )
}