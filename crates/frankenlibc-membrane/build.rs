use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const FRAGMENTATION_TASK_PATH: &str = "artifacts/sos/fragmentation_certificate.task";
const THREAD_SAFETY_TASK_PATH: &str = "artifacts/sos/thread_safety_certificate.task";
const SIZE_CLASS_TASK_PATH: &str = "artifacts/sos/size_class_certificate.task";
const GENERATED_FRAGMENTATION_RS_PATH: &str = "sos_fragmentation_generated.rs";
const GENERATED_THREAD_SAFETY_RS_PATH: &str = "sos_thread_safety_generated.rs";
const GENERATED_SIZE_CLASS_RS_PATH: &str = "sos_size_class_generated.rs";
const SOUNDNESS_REPORT_FILE_NAME: &str = "sos_soundness_verification.json";
const MEMORY_MODEL_AUDIT_FILE_NAME: &str = "memory_model_audit.json";
const CHOLESKY_TOLERANCE: f64 = 1e-9;
const MIN_BARRIER_MAP_SITES: usize = 20;
const OPERATION_LOOKBACK_LINES: usize = 6;

#[derive(Debug, Clone)]
pub struct SosTask {
    pub dimension: usize,
    pub monomial_degree: u32,
    pub barrier_budget_milli: i64,
    pub gram_matrix: Vec<Vec<i64>>,
    /// Independently specified barrier polynomial. Quadratic coefficients use
    /// the same score units as Q; the runtime applies its common fixed-point
    /// divisor to either representation. Never derive this witness from Q.
    pub barrier_polynomial: QuadraticPolynomial,
}

#[derive(Debug, Clone, Copy)]
struct PsdVerification {
    min_pivot: f64,
    max_abs_reconstruction_error: f64,
    frobenius_residual: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuadraticPolynomial {
    pub constant: i128,
    /// Canonical quadratic coefficients for monomials `z_i * z_j` with `i <= j`.
    pub coefficients: Vec<Vec<i128>>,
}

#[derive(Debug, Clone)]
struct SoundnessReportEntry {
    certificate_id: String,
    task_relative_path: String,
    task_source_sha256_hex: String,
    proof_hash_hex: String,
    cholesky_success: bool,
    polynomial_identity_verified: bool,
    min_pivot: f64,
    max_abs_reconstruction_error: f64,
    frobenius_residual: f64,
}

#[derive(Debug, Clone, Copy)]
struct MemoryModelSource {
    relative_path: &'static str,
    domain: &'static str,
    expected_sites: usize,
    stop_at_cfg_test: bool,
    /// If true, skip gracefully when the source file is missing (for cross-crate sources).
    optional: bool,
}

#[derive(Debug, Clone)]
struct MemoryModelSourceSummary {
    relative_path: &'static str,
    domain: &'static str,
    expected_sites: usize,
    observed_sites: usize,
    source_sha256_hex: String,
}

#[derive(Debug, Clone)]
struct MemoryModelAuditSite {
    domain: &'static str,
    relative_path: &'static str,
    line: usize,
    operation: &'static str,
    ordering: String,
    barrier_requirement: &'static str,
    x86_64_tso: &'static str,
    aarch64: &'static str,
    herd7_result: &'static str,
}

fn main() {
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR must be available for build script"),
    );
    let out_dir =
        PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be available for build script"));

    let report_entries = vec![
        generate_certificate_artifact(
            &manifest_dir,
            &out_dir,
            FRAGMENTATION_TASK_PATH,
            GENERATED_FRAGMENTATION_RS_PATH,
            "FRAGMENTATION",
        ),
        generate_certificate_artifact(
            &manifest_dir,
            &out_dir,
            THREAD_SAFETY_TASK_PATH,
            GENERATED_THREAD_SAFETY_RS_PATH,
            "THREAD_SAFETY",
        ),
        generate_certificate_artifact(
            &manifest_dir,
            &out_dir,
            SIZE_CLASS_TASK_PATH,
            GENERATED_SIZE_CLASS_RS_PATH,
            "SIZE_CLASS",
        ),
    ];

    write_soundness_report(&out_dir, &report_entries)
        .expect("failed to write SOS soundness verification report");
    write_memory_model_audit(&manifest_dir, &out_dir)
        .expect("failed to write memory-model barrier-map audit");
}

fn generate_certificate_artifact(
    manifest_dir: &Path,
    out_dir: &Path,
    task_relative_path: &str,
    generated_file_name: &str,
    const_prefix: &str,
) -> SoundnessReportEntry {
    let task_path = manifest_dir.join(task_relative_path);
    println!("cargo:rerun-if-changed={}", task_path.display());

    let task = parse_sos_task(&task_path).unwrap_or_else(|err| {
        panic!(
            "failed to parse SOS task artifact {}: {err}",
            task_path.display()
        )
    });
    validate_task(&task)
        .unwrap_or_else(|err| panic!("invalid SOS task artifact {}: {err}", task_path.display()));
    let psd = verify_psd_cholesky(&task.gram_matrix).unwrap_or_else(|err| {
        panic!(
            "SOS task artifact {} failed PSD/Cholesky verification: {err}",
            task_path.display()
        )
    });
    let barrier = build_barrier_polynomial(&task.gram_matrix, task.barrier_budget_milli);
    verify_barrier_against_sos_witness(&barrier, task.monomial_degree, &task.gram_matrix)
        .unwrap_or_else(|err| {
            panic!(
                "SOS task artifact {} failed exact rational SOS witness verification: {err}",
                task_path.display()
            )
        });
    assert_sos_verifier_negative_controls();
    verify_polynomial_identity(&task).unwrap_or_else(|err| {
        panic!(
            "SOS task artifact {} failed symbolic identity verification: {err}",
            task_path.display()
        )
    });

    let proof_hash = compute_proof_hash(
        task.dimension,
        task.monomial_degree,
        task.barrier_budget_milli,
        &task.gram_matrix,
    );
    let task_sha256_hex =
        compute_file_sha256_hex(&task_path).expect("failed to hash task artifact bytes");

    let generated_path = out_dir.join(generated_file_name);
    let generated = render_generated_rs(
        &task,
        proof_hash,
        psd,
        &task_sha256_hex,
        task_relative_path,
        const_prefix,
    );
    fs::write(&generated_path, generated).unwrap_or_else(|err| {
        panic!(
            "failed to write generated artifact {}: {err}",
            generated_path.display()
        )
    });

    SoundnessReportEntry {
        certificate_id: const_prefix.to_ascii_lowercase(),
        task_relative_path: task_relative_path.to_string(),
        task_source_sha256_hex: task_sha256_hex,
        proof_hash_hex: bytes_to_hex(&proof_hash),
        cholesky_success: true,
        polynomial_identity_verified: true,
        min_pivot: psd.min_pivot,
        max_abs_reconstruction_error: psd.max_abs_reconstruction_error,
        frobenius_residual: psd.frobenius_residual,
    }
}

pub fn parse_sos_task(path: &Path) -> Result<SosTask, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("unable to read {}: {err}", path.display()))?;
    parse_sos_task_text(&text)
}

fn parse_sos_task_text(text: &str) -> Result<SosTask, String> {
    let mut schema_version: Option<u32> = None;
    let mut dimension: Option<usize> = None;
    let mut monomial_degree: Option<u32> = None;
    let mut barrier_budget_milli: Option<i64> = None;
    let mut barrier_constant_milli: Option<i64> = None;
    let mut barrier_coefficients: Vec<Vec<i128>> = Vec::new();
    let mut gram_matrix: Vec<Vec<i64>> = Vec::new();
    let mut matrix_section = None;
    let mut seen_keys = std::collections::BTreeSet::new();

    for (line_no, raw_line) in text.lines().enumerate() {
        let line_no = line_no + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            match matrix_section {
                Some("gram_matrix") => gram_matrix.push(parse_matrix_row(line, line_no)?),
                Some("barrier_coefficients") => {
                    barrier_coefficients.push(parse_matrix_row(line, line_no)?);
                }
                _ => {
                    return Err(format!(
                        "line {line_no}: expected `key: value` or a declared matrix row"
                    ));
                }
            }
            continue;
        };

        let key = key.trim();
        let value = value.trim();
        if !seen_keys.insert(key) {
            return Err(format!("line {line_no}: duplicate `{key}` field"));
        }
        matrix_section = None;
        match key {
            "schema_version" => {
                schema_version = Some(parse_u64_like_u32(value, line_no, key)?);
            }
            "solver_family" | "certificate" => {
                if value.is_empty() {
                    return Err(format!("line {line_no}: `{key}` must not be empty"));
                }
            }
            "dimension" => {
                dimension = Some(parse_u64_like_usize(value, line_no, key)?);
            }
            "monomial_degree" => {
                monomial_degree = Some(parse_u64_like_u32(value, line_no, key)?);
            }
            "barrier_budget_milli" => {
                barrier_budget_milli = Some(parse_i64_like(value, line_no, key)?);
            }
            "barrier_constant_milli" => {
                barrier_constant_milli = Some(parse_i64_like(value, line_no, key)?);
            }
            "gram_matrix" | "barrier_coefficients" => {
                if !value.is_empty() {
                    return Err(format!(
                        "line {line_no}: `{key}` key must not include inline values"
                    ));
                }
                matrix_section = Some(key);
            }
            _ => {
                return Err(format!("line {line_no}: unknown `{key}` field"));
            }
        }
    }

    if schema_version != Some(2) {
        return Err(
            "schema_version must be 2 (independent barrier polynomial required)".to_string(),
        );
    }
    if !seen_keys.contains("barrier_coefficients") {
        return Err("missing `barrier_coefficients`".to_string());
    }
    Ok(SosTask {
        dimension: dimension.ok_or_else(|| "missing `dimension`".to_string())?,
        monomial_degree: monomial_degree.ok_or_else(|| "missing `monomial_degree`".to_string())?,
        barrier_budget_milli: barrier_budget_milli
            .ok_or_else(|| "missing `barrier_budget_milli`".to_string())?,
        gram_matrix,
        barrier_polynomial: QuadraticPolynomial {
            constant: i128::from(
                barrier_constant_milli
                    .ok_or_else(|| "missing `barrier_constant_milli`".to_string())?,
            ),
            coefficients: barrier_coefficients,
        },
    })
}

fn parse_matrix_row<T>(line: &str, line_no: usize) -> Result<Vec<T>, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let mut row = Vec::new();
    for (idx, part) in line.split(',').enumerate() {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            return Err(format!(
                "line {line_no}: empty matrix cell at column {}",
                idx + 1
            ));
        }
        let value = trimmed.parse::<T>().map_err(|err| {
            format!("line {line_no}: invalid integer matrix cell `{trimmed}`: {err}")
        })?;
        row.push(value);
    }
    Ok(row)
}

fn parse_u64_like_usize(value: &str, line_no: usize, key: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|err| format!("line {line_no}: invalid `{key}` value `{value}`: {err}"))
}

fn parse_u64_like_u32(value: &str, line_no: usize, key: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|err| format!("line {line_no}: invalid `{key}` value `{value}`: {err}"))
}

fn parse_i64_like(value: &str, line_no: usize, key: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .map_err(|err| format!("line {line_no}: invalid `{key}` value `{value}`: {err}"))
}

fn validate_task(task: &SosTask) -> Result<(), String> {
    if task.dimension == 0 {
        return Err("dimension must be > 0".to_string());
    }
    if task.dimension > 16 {
        return Err("dimension must be <= 16".to_string());
    }
    if task.monomial_degree != 2 {
        return Err("only degree-2 barrier polynomials are supported".to_string());
    }
    if task.barrier_budget_milli <= 0 {
        return Err("barrier_budget_milli must be positive".to_string());
    }
    if task.gram_matrix.len() != task.dimension {
        return Err(format!(
            "gram_matrix row count {} does not match dimension {}",
            task.gram_matrix.len(),
            task.dimension
        ));
    }
    for (row_idx, row) in task.gram_matrix.iter().enumerate() {
        if row.len() != task.dimension {
            return Err(format!(
                "gram_matrix row {} has {} entries; expected {}",
                row_idx,
                row.len(),
                task.dimension
            ));
        }
    }
    for i in 0..task.dimension {
        for j in 0..task.dimension {
            if task.gram_matrix[i][j] != task.gram_matrix[j][i] {
                return Err(format!(
                    "gram_matrix is not symmetric at ({i}, {j}) => {} != {}",
                    task.gram_matrix[i][j], task.gram_matrix[j][i]
                ));
            }
        }
    }
    if task.barrier_polynomial.coefficients.len() != task.dimension {
        return Err(format!(
            "barrier_coefficients row count {} does not match dimension {}",
            task.barrier_polynomial.coefficients.len(),
            task.dimension
        ));
    }
    for (i, row) in task.barrier_polynomial.coefficients.iter().enumerate() {
        if row.len() != task.dimension {
            return Err(format!(
                "barrier_coefficients row {i} has {} entries; expected {}",
                row.len(),
                task.dimension
            ));
        }
        if row[..i].iter().any(|&coefficient| coefficient != 0) {
            return Err(format!(
                "barrier_coefficients row {i} must be canonical upper-triangular"
            ));
        }
    }
    Ok(())
}

fn verify_psd_cholesky(gram_matrix: &[Vec<i64>]) -> Result<PsdVerification, String> {
    let n = gram_matrix.len();
    if n == 0 {
        return Err("empty Gram matrix".to_string());
    }

    let mut l = vec![vec![0.0_f64; n]; n];
    let mut min_pivot = f64::INFINITY;

    for i in 0..n {
        for j in 0..=i {
            let mut sum = gram_matrix[i][j] as f64;
            for (l_i_k, l_j_k) in l[i].iter().zip(l[j].iter()).take(j) {
                sum -= l_i_k * l_j_k;
            }

            if i == j {
                if sum < -CHOLESKY_TOLERANCE {
                    return Err(format!(
                        "negative pivot at row {i}: {sum:.12} (tol={CHOLESKY_TOLERANCE})"
                    ));
                }
                let pivot = if sum <= CHOLESKY_TOLERANCE {
                    0.0
                } else {
                    sum.sqrt()
                };
                l[i][j] = pivot;
                min_pivot = min_pivot.min(sum.max(0.0));
            } else {
                let denom = l[j][j];
                if denom > CHOLESKY_TOLERANCE {
                    l[i][j] = sum / denom;
                } else if sum.abs() <= CHOLESKY_TOLERANCE {
                    l[i][j] = 0.0;
                } else {
                    return Err(format!(
                        "indefinite matrix at ({i}, {j}): sum={sum:.12}, denom={denom:.12}"
                    ));
                }
            }
        }
    }

    let mut max_abs_reconstruction_error = 0.0_f64;
    let mut frobenius_sq = 0.0_f64;
    for i in 0..n {
        for j in 0..n {
            let mut reconstructed = 0.0_f64;
            let k_max = i.min(j);
            for (l_i_k, l_j_k) in l[i].iter().zip(l[j].iter()).take(k_max + 1) {
                reconstructed += l_i_k * l_j_k;
            }
            let diff = (gram_matrix[i][j] as f64) - reconstructed;
            let abs = diff.abs();
            max_abs_reconstruction_error = max_abs_reconstruction_error.max(abs);
            frobenius_sq += diff * diff;
        }
    }

    Ok(PsdVerification {
        min_pivot,
        max_abs_reconstruction_error,
        frobenius_residual: frobenius_sq.sqrt(),
    })
}

/// Check an independently supplied polynomial against the Gram witness.
///
/// The task specifies B(z) separately from Q. We check every coefficient of
/// B(z) + z^T Q z - budget, including the constant, using exact integer
/// arithmetic. The quadratic numerators share the runtime fixed-point scale,
/// so their cancellation is exact before or after that common scaling.
///
/// Together with PSD checking this establishes a quadratic decomposition. It
/// does NOT establish initial/unsafe-set separation or invariance under system
/// dynamics: those would require independently specified sets and dynamics.
fn verify_polynomial_identity(task: &SosTask) -> Result<(), String> {
    validate_task(task)?;
    let constant_residual = task
        .barrier_polynomial
        .constant
        .checked_sub(i128::from(task.barrier_budget_milli))
        .ok_or_else(|| "constant residual overflow".to_string())?;
    if constant_residual != 0 {
        return Err(format!(
            "constant residual must be zero, got {constant_residual}"
        ));
    }
    for i in 0..task.dimension {
        for j in i..task.dimension {
            // Off-diagonal entries contribute twice in the full matrix
            // evaluation. Convert before addition so even i64 extremes are
            // handled exactly rather than wrapping or saturating.
            let mut gram_coefficient = i128::from(task.gram_matrix[i][j]);
            if i != j {
                gram_coefficient += i128::from(task.gram_matrix[j][i]);
            }
            let residual = task.barrier_polynomial.coefficients[i][j]
                .checked_add(gram_coefficient)
                .ok_or_else(|| format!("quadratic residual overflow at ({i}, {j})"))?;
            if residual != 0 {
                return Err(format!(
                    "quadratic residual at ({i}, {j}) must be zero, got {residual}"
                ));
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rational128 {
    num: i128,
    den: i128,
}

impl Rational128 {
    const ZERO: Self = Self { num: 0, den: 1 };
    const ONE: Self = Self { num: 1, den: 1 };

    fn from_i128(value: i128) -> Self {
        Self { num: value, den: 1 }
    }

    fn new(num: i128, den: i128) -> Result<Self, String> {
        if den == 0 {
            return Err("zero denominator in rational SOS witness".to_string());
        }
        if num == 0 {
            return Ok(Self::ZERO);
        }
        let (signed_num, pos_den) = if den < 0 {
            (
                num.checked_neg()
                    .ok_or_else(|| "i128 numerator negation overflow".to_string())?,
                den.checked_neg()
                    .ok_or_else(|| "i128 denominator negation overflow".to_string())?,
            )
        } else {
            (num, den)
        };
        let g = gcd_u128(signed_num.unsigned_abs(), pos_den.unsigned_abs()) as i128;
        Ok(Self {
            num: signed_num / g,
            den: pos_den / g,
        })
    }

    fn checked_add(self, rhs: Self) -> Result<Self, String> {
        let g = gcd_u128(self.den.unsigned_abs(), rhs.den.unsigned_abs()) as i128;
        let lhs_scaled = self
            .num
            .checked_mul(rhs.den / g)
            .ok_or_else(|| "rational add lhs overflow".to_string())?;
        let rhs_scaled = rhs
            .num
            .checked_mul(self.den / g)
            .ok_or_else(|| "rational add rhs overflow".to_string())?;
        let num = lhs_scaled
            .checked_add(rhs_scaled)
            .ok_or_else(|| "rational add sum overflow".to_string())?;
        let den = (self.den / g)
            .checked_mul(rhs.den)
            .ok_or_else(|| "rational add denominator overflow".to_string())?;
        Self::new(num, den)
    }

    fn checked_sub(self, rhs: Self) -> Result<Self, String> {
        let neg_rhs = Self {
            num: rhs
                .num
                .checked_neg()
                .ok_or_else(|| "rational sub negation overflow".to_string())?,
            den: rhs.den,
        };
        self.checked_add(neg_rhs)
    }

    fn checked_mul(self, rhs: Self) -> Result<Self, String> {
        if self.num == 0 || rhs.num == 0 {
            return Ok(Self::ZERO);
        }
        let g1 = gcd_u128(self.num.unsigned_abs(), rhs.den.unsigned_abs()) as i128;
        let g2 = gcd_u128(rhs.num.unsigned_abs(), self.den.unsigned_abs()) as i128;
        let num = (self.num / g1)
            .checked_mul(rhs.num / g2)
            .ok_or_else(|| "rational mul numerator overflow".to_string())?;
        let den = (self.den / g2)
            .checked_mul(rhs.den / g1)
            .ok_or_else(|| "rational mul denominator overflow".to_string())?;
        Self::new(num, den)
    }

    fn checked_div(self, rhs: Self) -> Result<Self, String> {
        if rhs.num == 0 {
            return Err("division by zero pivot in rational LDL^T".to_string());
        }
        let recip = Self::new(rhs.den, rhs.num)?;
        self.checked_mul(recip)
    }
}

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a.max(1)
}

pub fn build_barrier_polynomial(
    gram_matrix: &[Vec<i64>],
    barrier_budget_milli: i64,
) -> QuadraticPolynomial {
    let degree_two = canonical_degree_two_coefficients(gram_matrix);
    let dim = degree_two.len();
    let mut barrier = QuadraticPolynomial {
        constant: i128::from(barrier_budget_milli),
        coefficients: vec![vec![0_i128; dim]; dim],
    };
    for (i, row) in degree_two.iter().enumerate().take(dim) {
        for (j, coeff) in row.iter().enumerate().skip(i) {
            barrier.coefficients[i][j] = -*coeff;
        }
    }
    barrier
}

/// Non-tautological exact rational SOS witness verification:
/// 1. Validates degree == 2, interior safety budget `B(0) > 0`, and symmetric `n x n` Gram shape.
/// 2. Computes exact reduced rational `Q = L D L^T` over `Q`, rejecting negative pivots or
///    rank-deficient zero pivots with non-zero off-diagonal coupling.
/// 3. Expands the explicit sum-of-squares polynomial
///    `sigma_SOS(z) = sum_{k=0}^{n-1} d_k * (sum_{i=k}^{n-1} L_{i,k} z_i)^2`
///    and verifies coefficient-by-coefficient that `B(z) + sigma_SOS(z) == B(0)` over `Q`.
pub fn verify_barrier_against_sos_witness(
    barrier: &QuadraticPolynomial,
    monomial_degree: u32,
    gram_matrix: &[Vec<i64>],
) -> Result<(), String> {
    if monomial_degree != 2 {
        return Err(format!(
            "unsupported SOS monomial_degree {monomial_degree}; expected 2"
        ));
    }
    if barrier.constant <= 0 {
        return Err(format!(
            "barrier constant B(0) must be strictly positive, got {}",
            barrier.constant
        ));
    }
    let n = gram_matrix.len();
    if n == 0 {
        return Err("empty Gram matrix".to_string());
    }
    if barrier.coefficients.len() != n {
        return Err(format!(
            "barrier polynomial dimension {} does not match Gram dimension {n}",
            barrier.coefficients.len()
        ));
    }
    for (row_idx, row) in gram_matrix.iter().enumerate() {
        if row.len() != n {
            return Err(format!(
                "Gram row {row_idx} has length {}, expected {n}",
                row.len()
            ));
        }
        if barrier.coefficients[row_idx].len() != n {
            return Err(format!(
                "barrier row {row_idx} has length {}, expected {n}",
                barrier.coefficients[row_idx].len()
            ));
        }
        for (col_idx, &entry) in row.iter().enumerate() {
            if entry != gram_matrix[col_idx][row_idx] {
                return Err(format!(
                    "Gram matrix is not symmetric at ({row_idx}, {col_idx}): {entry} != {}",
                    gram_matrix[col_idx][row_idx]
                ));
            }
        }
    }

    let mut l = vec![vec![Rational128::ZERO; n]; n];
    let mut d = vec![Rational128::ZERO; n];
    for (idx, row) in l.iter_mut().enumerate() {
        row[idx] = Rational128::ONE;
    }

    for j in 0..n {
        let mut pivot = Rational128::from_i128(i128::from(gram_matrix[j][j]));
        for (k, &d_k) in d.iter().enumerate().take(j) {
            let l_sq = l[j][k].checked_mul(l[j][k])?;
            let term = l_sq.checked_mul(d_k)?;
            pivot = pivot.checked_sub(term)?;
        }
        if pivot.num < 0 {
            return Err(format!(
                "indefinite Gram matrix: negative rational LDL^T pivot at row {j}: {}/{}",
                pivot.num, pivot.den
            ));
        }
        d[j] = pivot;

        for i in (j + 1)..n {
            let mut sum = Rational128::from_i128(i128::from(gram_matrix[i][j]));
            for (k, &d_k) in d.iter().enumerate().take(j) {
                let prod = l[i][k].checked_mul(l[j][k])?.checked_mul(d_k)?;
                sum = sum.checked_sub(prod)?;
            }
            if pivot.num == 0 {
                if sum.num != 0 {
                    return Err(format!(
                        "indefinite Gram matrix: zero pivot at row {j} with non-zero coupling at ({i}, {j}): {}/{}",
                        sum.num, sum.den
                    ));
                }
                l[i][j] = Rational128::ZERO;
            } else {
                l[i][j] = sum.checked_div(pivot)?;
            }
        }
    }

    let mut sigma_coeffs = vec![vec![Rational128::ZERO; n]; n];
    let two = Rational128::from_i128(2);
    for (k, &d_k) in d.iter().enumerate() {
        if d_k.num == 0 {
            continue;
        }
        for i in k..n {
            let diag_sq = l[i][k].checked_mul(l[i][k])?;
            let diag_term = d_k.checked_mul(diag_sq)?;
            sigma_coeffs[i][i] = sigma_coeffs[i][i].checked_add(diag_term)?;
            for j in (i + 1)..n {
                let cross = two
                    .checked_mul(d_k)?
                    .checked_mul(l[i][k])?
                    .checked_mul(l[j][k])?;
                sigma_coeffs[i][j] = sigma_coeffs[i][j].checked_add(cross)?;
            }
        }
    }

    for (i, (barrier_row, sigma_row)) in barrier
        .coefficients
        .iter()
        .zip(sigma_coeffs.iter())
        .enumerate()
    {
        for (j, &coeff) in barrier_row.iter().enumerate().take(i) {
            if coeff != 0 {
                return Err(format!(
                    "non-canonical lower-triangular barrier coefficient at ({i}, {j}): {coeff}"
                ));
            }
        }
        for j in i..n {
            let sos_coeff = sigma_row[j];
            if sos_coeff.den != 1 {
                return Err(format!(
                    "non-integral reconstructed SOS coefficient at ({i}, {j}): {}/{}",
                    sos_coeff.num, sos_coeff.den
                ));
            }
            let residual = barrier_row[j]
                .checked_add(sos_coeff.num)
                .ok_or_else(|| format!("barrier + SOS coefficient overflow at ({i}, {j})"))?;
            if residual != 0 {
                return Err(format!(
                    "SOS identity B(z) + sigma(z) == B(0) violated at ({i}, {j}): barrier_coeff={}, sos_coeff={}",
                    barrier_row[j], sos_coeff.num
                ));
            }
        }
    }

    Ok(())
}

fn assert_sos_verifier_negative_controls() {
    let valid_gram = vec![vec![4_i64, 2], vec![2, 3]];
    let mut perturbed = build_barrier_polynomial(&valid_gram, 1_000);
    perturbed.coefficients[0][1] += 1;
    assert!(
        verify_barrier_against_sos_witness(&perturbed, 2, &valid_gram).is_err(),
        "SOS verifier must reject perturbed barrier polynomial"
    );

    let indefinite_gram = vec![vec![0_i64, 1], vec![1, 0]];
    let indefinite_barrier = build_barrier_polynomial(&indefinite_gram, 1_000);
    assert!(
        verify_barrier_against_sos_witness(&indefinite_barrier, 2, &indefinite_gram).is_err(),
        "SOS verifier must reject rank-deficient indefinite Gram matrix"
    );
}

fn canonical_degree_two_coefficients(gram_matrix: &[Vec<i64>]) -> Vec<Vec<i128>> {
    let dim = gram_matrix.len();
    let mut coeffs = vec![vec![0_i128; dim]; dim];
    for (i, row) in gram_matrix.iter().enumerate() {
        for (j, &entry) in row.iter().enumerate() {
            let a = i.min(j);
            let b = i.max(j);
            coeffs[a][b] = coeffs[a][b].saturating_add(i128::from(entry));
        }
    }
    coeffs
}

#[cfg(test)]
mod polynomial_witness_tests {
    use super::*;

    const ARTIFACTS: [&str; 3] = [
        include_str!("artifacts/sos/fragmentation_certificate.task"),
        include_str!("artifacts/sos/thread_safety_certificate.task"),
        include_str!("artifacts/sos/size_class_certificate.task"),
    ];

    const SMALL_TASK: &str = "schema_version: 2\n\
dimension: 2\n\
monomial_degree: 2\n\
barrier_budget_milli: 10\n\
barrier_constant_milli: 10\n\
barrier_coefficients:\n\
-4,-2\n\
0,-3\n\
gram_matrix:\n\
4,1\n\
1,3\n";

    #[test]
    fn shipped_polynomials_match_their_psd_witnesses() {
        for text in ARTIFACTS {
            let task = parse_sos_task_text(text).expect("checked-in task parses");
            validate_task(&task).expect("checked-in task has supported shape");
            verify_psd_cholesky(&task.gram_matrix).expect("checked-in Q is PSD");
            verify_polynomial_identity(&task).expect("independent polynomial matches Q");
        }
    }

    #[test]
    fn changed_psd_gram_witness_cannot_certify_unchanged_polynomial() {
        for text in ARTIFACTS {
            let original = parse_sos_task_text(text).unwrap();
            for i in 0..original.dimension {
                for j in i..original.dimension {
                    let mut changed = original.clone();
                    changed.gram_matrix[i][j] += 1;
                    if i != j {
                        changed.gram_matrix[j][i] += 1;
                    }
                    // Positive definiteness alone is insufficient: all these
                    // witnesses are still PSD but certify a different target.
                    verify_psd_cholesky(&changed.gram_matrix)
                        .expect("small symmetric mutation remains PSD");
                    let error = verify_polynomial_identity(&changed).unwrap_err();
                    assert!(error.contains(&format!("quadratic residual at ({i}, {j})")));
                }
            }
        }
    }

    #[test]
    fn independently_changed_polynomial_and_budget_are_rejected() {
        for text in ARTIFACTS {
            let original = parse_sos_task_text(text).unwrap();
            let mut changed = original.clone();
            changed.barrier_polynomial.constant += 1;
            assert!(
                verify_polynomial_identity(&changed)
                    .unwrap_err()
                    .contains("constant residual")
            );
            let mut changed = original.clone();
            changed.barrier_budget_milli += 1;
            assert!(
                verify_polynomial_identity(&changed)
                    .unwrap_err()
                    .contains("constant residual")
            );
            for i in 0..original.dimension {
                for j in i..original.dimension {
                    let mut changed = original.clone();
                    changed.barrier_polynomial.coefficients[i][j] += 1;
                    assert!(verify_polynomial_identity(&changed).is_err());
                }
            }
        }
    }

    #[test]
    fn malformed_or_missing_independent_witness_fails_closed() {
        let invalid = [
            SMALL_TASK.replace("schema_version: 2", "schema_version: 1"),
            SMALL_TASK.replace("schema_version: 2\n", ""),
            SMALL_TASK.replace("barrier_constant_milli: 10\n", ""),
            SMALL_TASK.replace("barrier_coefficients:\n-4,-2\n0,-3\n", ""),
            SMALL_TASK.replace("dimension: 2", "dimension: 2\ndimension: 2"),
            SMALL_TASK.replace("gram_matrix:", "gram_matrix:\ngram_matrix:"),
            SMALL_TASK.replace("barrier_constant_milli:", "barrier_constant_typo:"),
            SMALL_TASK.replace("-4,-2", "-4,"),
            SMALL_TASK.replace("-4,-2", "-4,NaN"),
        ];
        for text in invalid {
            assert!(
                parse_sos_task_text(&text).is_err(),
                "accepted malformed task: {text}"
            );
        }
    }

    #[test]
    fn unsupported_polynomial_shapes_and_degree_are_rejected() {
        for text in [
            SMALL_TASK.replace("monomial_degree: 2", "monomial_degree: 3"),
            SMALL_TASK.replace("0,-3", "1,-3"),
            SMALL_TASK.replace("0,-3\n", ""),
            SMALL_TASK.replace("-4,-2", "-4,-2,0"),
            SMALL_TASK.replace("barrier_budget_milli: 10", "barrier_budget_milli: 0"),
        ] {
            let task = parse_sos_task_text(&text).expect("syntactically valid task");
            assert!(
                verify_polynomial_identity(&task).is_err(),
                "accepted unsupported task: {text}"
            );
        }
    }

    #[test]
    fn coefficient_residuals_use_exact_checked_arithmetic() {
        let mut task = parse_sos_task_text(SMALL_TASK).unwrap();
        let max = i64::MAX;
        task.gram_matrix = vec![vec![max, max], vec![max, max]];
        task.barrier_polynomial.coefficients = vec![
            vec![-i128::from(max), -2 * i128::from(max)],
            vec![0, -i128::from(max)],
        ];
        verify_polynomial_identity(&task).expect("off-diagonal sum exceeds i64 but fits i128");
        task.barrier_polynomial.coefficients[0][1] += 1;
        assert!(
            verify_polynomial_identity(&task)
                .unwrap_err()
                .ends_with("got 1")
        );
        task.barrier_polynomial.coefficients[0][1] = i128::MAX;
        assert!(
            verify_polynomial_identity(&task)
                .unwrap_err()
                .contains("overflow")
        );
    }
}

fn write_soundness_report(out_dir: &Path, entries: &[SoundnessReportEntry]) -> Result<(), String> {
    let report_path = out_dir.join(SOUNDNESS_REPORT_FILE_NAME);
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"schema_version\": 1,\n");
    out.push_str("  \"verification\": \"sos_soundness\",\n");
    out.push_str("  \"verification_scope\": \"numerical_psd_and_exact_polynomial_identity\",\n");
    out.push_str("  \"dynamical_safety_verified\": false,\n");
    out.push_str("  \"entries\": [\n");
    for (idx, entry) in entries.iter().enumerate() {
        if idx > 0 {
            out.push_str(",\n");
        }
        out.push_str("    {\n");
        out.push_str(&format!(
            "      \"certificate_id\": \"{}\",\n",
            json_escape(&entry.certificate_id)
        ));
        out.push_str(&format!(
            "      \"task_path\": \"{}\",\n",
            json_escape(&entry.task_relative_path)
        ));
        out.push_str(&format!(
            "      \"task_source_sha256_hex\": \"{}\",\n",
            json_escape(&entry.task_source_sha256_hex)
        ));
        out.push_str(&format!(
            "      \"proof_hash_hex\": \"{}\",\n",
            json_escape(&entry.proof_hash_hex)
        ));
        out.push_str(&format!(
            "      \"cholesky_success\": {},\n",
            entry.cholesky_success
        ));
        out.push_str(&format!(
            "      \"polynomial_identity_verified\": {},\n",
            entry.polynomial_identity_verified
        ));
        out.push_str(&format!("      \"min_pivot\": {:.12},\n", entry.min_pivot));
        out.push_str(&format!(
            "      \"max_abs_reconstruction_error\": {:.12},\n",
            entry.max_abs_reconstruction_error
        ));
        out.push_str(&format!(
            "      \"stability_bound_delta\": {:.12}\n",
            entry.frobenius_residual
        ));
        out.push_str("    }");
    }
    out.push_str("\n  ]\n");
    out.push_str("}\n");

    fs::write(&report_path, out)
        .map_err(|err| format!("unable to write {}: {err}", report_path.display()))
}

fn json_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn compute_proof_hash(
    dimension: usize,
    monomial_degree: u32,
    barrier_budget_milli: i64,
    gram_matrix: &[Vec<i64>],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((dimension as u32).to_le_bytes());
    hasher.update(monomial_degree.to_le_bytes());
    hasher.update(barrier_budget_milli.to_le_bytes());
    for row in gram_matrix {
        for cell in row {
            hasher.update(cell.to_le_bytes());
        }
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn compute_file_sha256_hex(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|err| format!("unable to read {}: {err}", path.display()))?;
    let digest = Sha256::digest(&bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut out, "{byte:02x}").expect("writing to String must succeed");
    }
    Ok(out)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("writing to String must succeed");
    }
    out
}

fn render_generated_rs(
    task: &SosTask,
    proof_hash: [u8; 32],
    psd: PsdVerification,
    task_sha256_hex: &str,
    task_relative_path: &str,
    const_prefix: &str,
) -> String {
    let mut gram_matrix_rows = String::new();
    for row in &task.gram_matrix {
        gram_matrix_rows.push_str("    [");
        for (idx, cell) in row.iter().enumerate() {
            if idx > 0 {
                gram_matrix_rows.push_str(", ");
            }
            write!(&mut gram_matrix_rows, "{cell}").expect("writing to String must succeed");
        }
        gram_matrix_rows.push_str("],\n");
    }

    let mut proof_hash_bytes = String::new();
    for (idx, byte) in proof_hash.iter().enumerate() {
        if idx > 0 {
            proof_hash_bytes.push_str(", ");
        }
        write!(&mut proof_hash_bytes, "0x{byte:02x}").expect("writing to String must succeed");
    }

    let cert_dim = format!("{const_prefix}_CERT_DIM");
    let monomial_degree = format!("{const_prefix}_MONOMIAL_DEGREE");
    let barrier_budget = format!("{const_prefix}_BARRIER_BUDGET_MILLI");
    let task_source_hash = format!("{const_prefix}_TASK_SOURCE_SHA256_HEX");
    let gram_matrix = format!("{const_prefix}_GRAM_MATRIX");
    let proof_hash = format!("{const_prefix}_PROOF_HASH");
    let min_pivot = format!("{const_prefix}_CHOLESKY_MIN_PIVOT");
    let max_abs_reconstruction_error =
        format!("{const_prefix}_CHOLESKY_MAX_ABS_RECONSTRUCTION_ERROR");
    let stability_bound_delta = format!("{const_prefix}_STABILITY_BOUND_DELTA");

    format!(
        "// @generated by crates/frankenlibc-membrane/build.rs from {task_relative_path}\n\
pub(crate) const {cert_dim}: usize = {dimension};\n\
pub(crate) const {monomial_degree}: u32 = {task_monomial_degree};\n\
pub(crate) const {barrier_budget}: i64 = {barrier_budget_milli};\n\
pub(crate) const {task_source_hash}: &str = \"{task_sha256_hex}\";\n\
pub(crate) static {gram_matrix}: [[i64; {cert_dim}]; {cert_dim}] = [\n\
{gram_matrix_rows}];\n\
pub(crate) const {proof_hash}: [u8; 32] = [{proof_hash_bytes}];\n\
#[cfg(test)]\n\
pub(crate) const {min_pivot}: f64 = {min_pivot_value:.12};\n\
#[cfg(test)]\n\
pub(crate) const {max_abs_reconstruction_error}: f64 = {max_abs_reconstruction_error_value:.12};\n\
#[cfg(test)]\n\
pub(crate) const {stability_bound_delta}: f64 = {stability_bound_delta_value:.12};\n",
        task_relative_path = task_relative_path,
        cert_dim = cert_dim,
        monomial_degree = monomial_degree,
        barrier_budget = barrier_budget,
        task_source_hash = task_source_hash,
        gram_matrix = gram_matrix,
        proof_hash = proof_hash,
        min_pivot = min_pivot,
        max_abs_reconstruction_error = max_abs_reconstruction_error,
        stability_bound_delta = stability_bound_delta,
        dimension = task.dimension,
        task_monomial_degree = task.monomial_degree,
        barrier_budget_milli = task.barrier_budget_milli,
        task_sha256_hex = task_sha256_hex,
        gram_matrix_rows = gram_matrix_rows,
        proof_hash_bytes = proof_hash_bytes,
        min_pivot_value = psd.min_pivot,
        max_abs_reconstruction_error_value = psd.max_abs_reconstruction_error,
        stability_bound_delta_value = psd.frobenius_residual,
    )
}

const MEMORY_MODEL_SOURCES: &[MemoryModelSource] = &[
    MemoryModelSource {
        relative_path: "src/ptr_validator.rs",
        domain: "tsm",
        // Merged ptr_validator.rs: per-tid native validation table plus the
        // probe-table tests. Ordering:: sites were counted on the resolved
        // file (production ContextTable, test setup, native/fallback entry,
        // and logging). Slot/alias publication uses AcqRel CAS and Acquire
        // readers; activity credits are reserved before publication and
        // released after the slot. Child repair's Relaxed slot load runs
        // only in the sole fork survivor with signals blocked.
        expected_sites: 118,
        stop_at_cfg_test: false,
        optional: false,
    },
    MemoryModelSource {
        relative_path: "src/arena.rs",
        domain: "tsm",
        // 2 generation-counter sites + 7 arena-wide quarantine totals (2 loads
        // in the drain bound, 2 fetch_add on free, 2 fetch_sub on drain, 1 test
        // load). The totals are Relaxed: they only bound how much the shards
        // (each updated under its own lock) hold, and publish no other memory.
        // 3 fragmentation sampling sites: Release marks pending work (including
        // retries), Acquire checks the hint, and AcqRel swap claims it. A later
        // producer's Release remains pending after that claim. This flag only
        // coalesces sampling work; shard locks protect the measured counters.
        expected_sites: 12,
        stop_at_cfg_test: false,
        optional: false,
    },
    MemoryModelSource {
        relative_path: "src/tls_cache.rs",
        domain: "tsm",
        // Atomic-ordering sites in tls_cache.rs after the per-shard
        // invalidation refactor. The previous global-epoch design had 2
        // sites (one load+Acquire, one fetch_add+Release). The new design
        // exposes more sites because the same Acquire/Release pattern is
        // now applied per-shard (current_shard_epoch, snapshot_shard_epochs,
        // bump_shard_epoch, bump_tls_cache_epoch, current_epoch) and the
        // race-safety + cross-shard isolation tests each touch SHARD_EPOCHS
        // directly. Adjust here when the in-file barrier surface changes.
        // 8 -> 13 (bd-reality-202609-lx578q.4): ESCALATED_INTEGRITY_SOURCES
        // adds 1 Relaxed load + 1 fetch_or + 1 fetch_and for race-free multi-source
        // cadence tightening, and PIPELINE_RUNTIME_MATH_DISABLED adds 1 Relaxed load +
        // 1 Relaxed store for FRANKENLIBC_RUNTIME_MATH=off synchronization; neither
        // publishes auxiliary memory, while slot/header/canary reads remain
        // synchronized by SHARD_EPOCHS Acquire/Release + shard lock.
        // 13 -> 15 (bd-rc0923-epic-eeuy4f.24): NATIVE_THREAD_COMPILER_TLS_DISABLED
        // adds 1 Release store (before clone) + 1 Relaxed load so native threads
        // sharing a TCB bypass compiler-TLS validation-cache borrows.
        // The native-thread TLS-sharing flag adds a SeqCst publish
        // before thread admission and an Acquire read before compiler-TLS use.
        // Merged tls_cache.rs Ordering:: sites: 17.
        expected_sites: 17,
        stop_at_cfg_test: false,
        optional: false,
    },
    MemoryModelSource {
        relative_path: "src/config.rs",
        domain: "tsm",
        // 15 -> 17: seed_safety_level_if_unset compare_exchange (Release/Relaxed)
        // allows the ABI layer's allocation-free environ scan to pre-seed
        // CACHED_LEVEL during .init_array startup.
        expected_sites: 17,
        stop_at_cfg_test: false,
        optional: false,
    },
    MemoryModelSource {
        relative_path: "src/metrics.rs",
        domain: "tsm",
        expected_sites: 2,
        stop_at_cfg_test: false,
        optional: false,
    },
    MemoryModelSource {
        relative_path: "../frankenlibc-core/src/pthread/cond.rs",
        domain: "futex",
        // 33 -> 26 (bd-rc0923-epic-eeuy4f.24): condvar_timedwait's copies of the
        // association CAS, seq load, waiter inc/dec, mutex release, association
        // clear and clock load now run in the shared condvar_wait_prepare /
        // condvar_wait_finish / condvar_timed_futex_op, with the same orderings.
        // 26 -> 28 (bd-rc0923-epic-eeuy4f.15): process-shared condvars read the
        // magic word (Acquire, futex_private_flag) and set it (Release,
        // mark_process_shared), pairing with the existing init/adopt protocol.
        expected_sites: 28,
        stop_at_cfg_test: true,
        optional: true, // Cross-crate: skip gracefully for standalone builds
    },
];

fn verify_atomic_site_count(
    source: &MemoryModelSource,
    observed_sites: usize,
) -> Result<(), String> {
    if observed_sites != source.expected_sites {
        return Err(format!(
            "BarrierMap drift in {}: expected {} sites, observed {}. \
Update MEMORY_MODEL_SOURCES after reviewing barrier requirements.",
            source.relative_path, source.expected_sites, observed_sites
        ));
    }
    Ok(())
}

#[cfg(test)]
mod memory_model_inventory_tests {
    use super::*;

    const REVIEWED_SOURCES: [(&str, &str); 3] = [
        ("src/ptr_validator.rs", include_str!("src/ptr_validator.rs")),
        ("src/tls_cache.rs", include_str!("src/tls_cache.rs")),
        ("src/arena.rs", include_str!("src/arena.rs")),
    ];

    fn source_for(path: &str) -> &'static MemoryModelSource {
        MEMORY_MODEL_SOURCES
            .iter()
            .find(|source| source.relative_path == path)
            .expect("reviewed source must remain in the build-time audit")
    }

    #[test]
    fn reviewed_context_and_tls_sources_pass_inventory() {
        for (path, text) in REVIEWED_SOURCES {
            let source = source_for(path);
            let observed = extract_atomic_sites(source, text).len();
            verify_atomic_site_count(source, observed).unwrap_or_else(|error| panic!("{error}"));
        }
    }

    #[test]
    fn added_or_removed_ordering_requires_inventory_review() {
        for (path, text) in REVIEWED_SOURCES {
            let source = source_for(path);
            let added = format!("{text}\nflag.load(Ordering::Acquire);\n");
            let removed = text.replacen("Ordering::Acquire", "ordering", 1);

            for (mutated, delta) in [(&added, 1isize), (&removed, -1isize)] {
                let observed = extract_atomic_sites(source, mutated).len();
                assert_eq!(
                    observed as isize,
                    source.expected_sites as isize + delta,
                    "mutation must change exactly one audited ordering in {path}"
                );
                let error = verify_atomic_site_count(source, observed)
                    .expect_err("unreviewed ordering changes must fail closed");
                assert!(
                    error.starts_with(&format!("BarrierMap drift in {path}:")),
                    "gate must identify the changed source: {error}"
                );
            }
        }
    }
}

fn write_memory_model_audit(manifest_dir: &Path, out_dir: &Path) -> Result<(), String> {
    let mut source_summaries = Vec::new();
    let mut sites = Vec::new();

    for source in MEMORY_MODEL_SOURCES {
        let source_path = manifest_dir.join(source.relative_path);
        println!("cargo:rerun-if-changed={}", source_path.display());
        let source_text = match fs::read_to_string(&source_path) {
            Ok(text) => text,
            Err(err) if source.optional => {
                eprintln!(
                    "cargo:warning=Skipping optional memory-model source {}: {err}",
                    source.relative_path
                );
                continue;
            }
            Err(err) => {
                return Err(format!("unable to read {}: {err}", source_path.display()));
            }
        };
        let source_hash = compute_file_sha256_hex(&source_path)?;
        let source_sites = extract_atomic_sites(source, &source_text);
        let observed_sites = source_sites.len();
        verify_atomic_site_count(source, observed_sites)?;

        source_summaries.push(MemoryModelSourceSummary {
            relative_path: source.relative_path,
            domain: source.domain,
            expected_sites: source.expected_sites,
            observed_sites,
            source_sha256_hex: source_hash,
        });
        sites.extend(source_sites);
    }

    if sites.len() < MIN_BARRIER_MAP_SITES {
        return Err(format!(
            "insufficient atomic sites for BarrierMap: found {}, need at least {}",
            sites.len(),
            MIN_BARRIER_MAP_SITES
        ));
    }

    let report_path = out_dir.join(MEMORY_MODEL_AUDIT_FILE_NAME);
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"schema_version\": 1,\n");
    out.push_str("  \"verification\": \"memory_model_barrier_map\",\n");
    out.push_str(&format!(
        "  \"minimum_required_sites\": {},\n",
        MIN_BARRIER_MAP_SITES
    ));
    out.push_str("  \"summary\": {\n");
    out.push_str(&format!("    \"total_atomic_sites\": {},\n", sites.len()));
    out.push_str(&format!("    \"verified_count\": {},\n", sites.len()));
    out.push_str("    \"sources\": [\n");
    for (idx, source) in source_summaries.iter().enumerate() {
        if idx > 0 {
            out.push_str(",\n");
        }
        out.push_str("      {\n");
        out.push_str(&format!(
            "        \"path\": \"{}\",\n",
            json_escape(source.relative_path)
        ));
        out.push_str(&format!(
            "        \"domain\": \"{}\",\n",
            json_escape(source.domain)
        ));
        out.push_str(&format!(
            "        \"expected_sites\": {},\n",
            source.expected_sites
        ));
        out.push_str(&format!(
            "        \"observed_sites\": {},\n",
            source.observed_sites
        ));
        out.push_str(&format!(
            "        \"source_sha256_hex\": \"{}\"\n",
            json_escape(&source.source_sha256_hex)
        ));
        out.push_str("      }");
    }
    out.push_str("\n    ]\n");
    out.push_str("  },\n");
    out.push_str("  \"sites\": [\n");
    for (idx, site) in sites.iter().enumerate() {
        if idx > 0 {
            out.push_str(",\n");
        }
        out.push_str("    {\n");
        out.push_str(&format!("      \"site_id\": \"S{:04}\",\n", idx + 1));
        out.push_str(&format!(
            "      \"domain\": \"{}\",\n",
            json_escape(site.domain)
        ));
        out.push_str(&format!(
            "      \"path\": \"{}\",\n",
            json_escape(site.relative_path)
        ));
        out.push_str(&format!("      \"line\": {},\n", site.line));
        out.push_str(&format!(
            "      \"operation\": \"{}\",\n",
            json_escape(site.operation)
        ));
        out.push_str(&format!(
            "      \"ordering\": \"{}\",\n",
            json_escape(&site.ordering)
        ));
        out.push_str(&format!(
            "      \"barrier_requirement\": \"{}\",\n",
            json_escape(site.barrier_requirement)
        ));
        out.push_str(&format!(
            "      \"x86_64_tso\": \"{}\",\n",
            json_escape(site.x86_64_tso)
        ));
        out.push_str(&format!(
            "      \"aarch64\": \"{}\",\n",
            json_escape(site.aarch64)
        ));
        out.push_str(&format!(
            "      \"herd7_result\": \"{}\"\n",
            json_escape(site.herd7_result)
        ));
        out.push_str("    }");
    }
    out.push_str("\n  ]\n");
    out.push_str("}\n");

    fs::write(&report_path, out)
        .map_err(|err| format!("unable to write {}: {err}", report_path.display()))
}

fn extract_atomic_sites(
    source: &MemoryModelSource,
    source_text: &str,
) -> Vec<MemoryModelAuditSite> {
    let lines: Vec<&str> = source_text.lines().collect();
    let mut max_line = lines.len();
    if source.stop_at_cfg_test {
        for (idx, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("#[cfg(test)]") {
                max_line = idx;
                break;
            }
        }
    }

    let mut sites = Vec::new();
    for line_idx in 0..max_line {
        let line = lines[line_idx];
        let orderings = extract_ordering_variants(line);
        if orderings.is_empty() {
            continue;
        }
        let operation = infer_atomic_operation(&lines, line_idx);
        for ordering in orderings {
            let (barrier_requirement, x86_64_tso, aarch64, herd7_result) =
                ordering_memory_model_profile(&ordering);
            sites.push(MemoryModelAuditSite {
                domain: source.domain,
                relative_path: source.relative_path,
                line: line_idx + 1,
                operation,
                ordering,
                barrier_requirement,
                x86_64_tso,
                aarch64,
                herd7_result,
            });
        }
    }

    sites
}

fn extract_ordering_variants(line: &str) -> Vec<String> {
    let mut orderings = Vec::new();
    let mut cursor = 0usize;
    while let Some(pos) = line[cursor..].find("Ordering::") {
        let start = cursor + pos + "Ordering::".len();
        let suffix = &line[start..];
        let variant: String = suffix
            .chars()
            .take_while(|c| c.is_ascii_alphabetic())
            .collect();
        if !variant.is_empty() {
            orderings.push(variant);
            cursor = start + 1;
        } else {
            cursor = start;
        }
    }
    orderings
}

fn infer_atomic_operation(lines: &[&str], line_idx: usize) -> &'static str {
    const OPERATION_PATTERNS: &[(&str, &str)] = &[
        ("compare_exchange_weak(", "compare_exchange_weak"),
        ("compare_exchange(", "compare_exchange"),
        ("fetch_add(", "fetch_add"),
        ("fetch_sub(", "fetch_sub"),
        ("fetch_or(", "fetch_or"),
        ("fetch_and(", "fetch_and"),
        ("fetch_xor(", "fetch_xor"),
        ("fetch_max(", "fetch_max"),
        ("fetch_min(", "fetch_min"),
        ("swap(", "swap"),
        ("store(", "store"),
        ("load(", "load"),
    ];

    let start = line_idx.saturating_sub(OPERATION_LOOKBACK_LINES);
    let mut window = String::new();
    for line in lines.iter().take(line_idx + 1).skip(start) {
        window.push_str(line);
        window.push('\n');
    }
    for (needle, operation) in OPERATION_PATTERNS {
        if window.contains(needle) {
            return operation;
        }
    }
    "unknown"
}

fn ordering_memory_model_profile(
    ordering: &str,
) -> (&'static str, &'static str, &'static str, &'static str) {
    match ordering {
        "Relaxed" => (
            "none",
            "TSO keeps program-order store/load constraints for this atomic access",
            "No fence; relaxed atomics rely on architecture-level atomicity only",
            "pending_external_herd7",
        ),
        "Acquire" => (
            "acquire",
            "Load-acquire ordering is satisfied without explicit mfence",
            "Requires load-acquire semantics (ldar or equivalent)",
            "pending_external_herd7",
        ),
        "Release" => (
            "release",
            "Store-release ordering is satisfied without explicit mfence",
            "Requires store-release semantics (stlr or equivalent)",
            "pending_external_herd7",
        ),
        "AcqRel" => (
            "acq_rel",
            "RMW operations preserve acquire+release ordering on TSO",
            "Requires acquire+release RMW semantics (ldaxr/stlxr or equivalent)",
            "pending_external_herd7",
        ),
        "SeqCst" => (
            "seq_cst",
            "Sequential consistency is mapped to globally ordered atomic operations",
            "Requires globally ordered seq-cst semantics (dmb ish around operations)",
            "pending_external_herd7",
        ),
        _ => (
            "unknown",
            "Unknown ordering; requires manual model review",
            "Unknown ordering; requires manual model review",
            "not_applicable",
        ),
    }
}
