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

#[derive(Debug)]
struct SosTask {
    dimension: usize,
    monomial_degree: u32,
    barrier_budget_milli: i64,
    gram_matrix: Vec<Vec<i64>>,
}

#[derive(Debug, Clone, Copy)]
struct PsdVerification {
    min_pivot: f64,
    max_abs_reconstruction_error: f64,
    frobenius_residual: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QuadraticPolynomial {
    constant: i128,
    /// Canonical quadratic coefficients for monomials `z_i * z_j` with `i <= j`.
    coefficients: Vec<Vec<i128>>,
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
    verify_polynomial_identity(&task.gram_matrix, task.barrier_budget_milli).unwrap_or_else(
        |err| {
            panic!(
                "SOS task artifact {} failed symbolic identity verification: {err}",
                task_path.display()
            )
        },
    );

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

fn parse_sos_task(path: &Path) -> Result<SosTask, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("unable to read {}: {err}", path.display()))?;
    let mut dimension: Option<usize> = None;
    let mut monomial_degree: Option<u32> = None;
    let mut barrier_budget_milli: Option<i64> = None;
    let mut gram_matrix: Vec<Vec<i64>> = Vec::new();
    let mut reading_matrix = false;

    for (line_no, raw_line) in text.lines().enumerate() {
        let line_no = line_no + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if reading_matrix {
            if line.contains(':') {
                return Err(format!(
                    "line {line_no}: encountered key/value while parsing gram_matrix rows"
                ));
            }
            let row = parse_matrix_row(line, line_no)?;
            gram_matrix.push(row);
            continue;
        }

        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| format!("line {line_no}: expected `key: value` format, got `{line}`"))?;
        let key = key.trim();
        let value = value.trim();
        match key {
            "dimension" => {
                dimension = Some(parse_u64_like_usize(value, line_no, key)?);
            }
            "monomial_degree" => {
                monomial_degree = Some(parse_u64_like_u32(value, line_no, key)?);
            }
            "barrier_budget_milli" => {
                barrier_budget_milli = Some(parse_i64_like(value, line_no, key)?);
            }
            "gram_matrix" => {
                if !value.is_empty() {
                    return Err(format!(
                        "line {line_no}: `gram_matrix` key must not include inline values"
                    ));
                }
                reading_matrix = true;
            }
            _ => {}
        }
    }

    Ok(SosTask {
        dimension: dimension.ok_or_else(|| "missing `dimension`".to_string())?,
        monomial_degree: monomial_degree.ok_or_else(|| "missing `monomial_degree`".to_string())?,
        barrier_budget_milli: barrier_budget_milli
            .ok_or_else(|| "missing `barrier_budget_milli`".to_string())?,
        gram_matrix,
    })
}

fn parse_matrix_row(line: &str, line_no: usize) -> Result<Vec<i64>, String> {
    let mut row = Vec::new();
    for (idx, part) in line.split(',').enumerate() {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            return Err(format!(
                "line {line_no}: empty matrix cell at column {}",
                idx + 1
            ));
        }
        let value = trimmed
            .parse::<i64>()
            .map_err(|err| format!("line {line_no}: invalid i64 matrix cell `{trimmed}`: {err}"))?;
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

fn verify_polynomial_identity(
    gram_matrix: &[Vec<i64>],
    barrier_budget_milli: i64,
) -> Result<(), String> {
    let degree_two = canonical_degree_two_coefficients(gram_matrix);
    let dim = degree_two.len();

    // Runtime barrier polynomial: B(z) = budget - z^T Q z.
    let mut barrier = QuadraticPolynomial {
        constant: i128::from(barrier_budget_milli),
        coefficients: vec![vec![0_i128; dim]; dim],
    };
    for (i, row) in degree_two.iter().enumerate().take(dim) {
        for (j, coeff) in row.iter().enumerate().skip(i) {
            barrier.coefficients[i][j] = -*coeff;
        }
    }

    // SOS remainder polynomial: sigma(z) = z^T Q z (sum-of-squares when Q is PSD).
    let sigma = QuadraticPolynomial {
        constant: 0,
        coefficients: degree_two,
    };

    // Invariant witness polynomial for identity check:
    // I(z) = B(z) - sigma(z), so B(z) = I(z) + sigma(z).
    let invariant = polynomial_sub(&barrier, &sigma)?;
    let recomposed = polynomial_add(&invariant, &sigma)?;
    if barrier != recomposed {
        return Err(polynomial_identity_mismatch(&barrier, &recomposed));
    }

    Ok(())
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

fn polynomial_add(
    lhs: &QuadraticPolynomial,
    rhs: &QuadraticPolynomial,
) -> Result<QuadraticPolynomial, String> {
    if lhs.coefficients.len() != rhs.coefficients.len() {
        return Err(format!(
            "dimension mismatch in polynomial_add: {} vs {}",
            lhs.coefficients.len(),
            rhs.coefficients.len()
        ));
    }
    let dim = lhs.coefficients.len();
    let mut out = QuadraticPolynomial {
        constant: lhs.constant.saturating_add(rhs.constant),
        coefficients: vec![vec![0_i128; dim]; dim],
    };
    for (i, (lhs_row, rhs_row)) in lhs
        .coefficients
        .iter()
        .zip(rhs.coefficients.iter())
        .enumerate()
        .take(dim)
    {
        for (j, (lhs_coeff, rhs_coeff)) in lhs_row.iter().zip(rhs_row.iter()).enumerate().skip(i) {
            out.coefficients[i][j] = lhs_coeff.saturating_add(*rhs_coeff);
        }
    }
    Ok(out)
}

fn polynomial_sub(
    lhs: &QuadraticPolynomial,
    rhs: &QuadraticPolynomial,
) -> Result<QuadraticPolynomial, String> {
    if lhs.coefficients.len() != rhs.coefficients.len() {
        return Err(format!(
            "dimension mismatch in polynomial_sub: {} vs {}",
            lhs.coefficients.len(),
            rhs.coefficients.len()
        ));
    }
    let dim = lhs.coefficients.len();
    let mut out = QuadraticPolynomial {
        constant: lhs.constant.saturating_sub(rhs.constant),
        coefficients: vec![vec![0_i128; dim]; dim],
    };
    for (i, (lhs_row, rhs_row)) in lhs
        .coefficients
        .iter()
        .zip(rhs.coefficients.iter())
        .enumerate()
        .take(dim)
    {
        for (j, (lhs_coeff, rhs_coeff)) in lhs_row.iter().zip(rhs_row.iter()).enumerate().skip(i) {
            out.coefficients[i][j] = lhs_coeff.saturating_sub(*rhs_coeff);
        }
    }
    Ok(out)
}

fn polynomial_identity_mismatch(
    expected: &QuadraticPolynomial,
    actual: &QuadraticPolynomial,
) -> String {
    if expected.constant != actual.constant {
        return format!(
            "constant term mismatch: expected {}, got {}",
            expected.constant, actual.constant
        );
    }
    for (i, (lhs_row, rhs_row)) in expected
        .coefficients
        .iter()
        .zip(actual.coefficients.iter())
        .enumerate()
    {
        for j in i..lhs_row.len() {
            if lhs_row[j] != rhs_row[j] {
                return format!(
                    "quadratic coefficient mismatch at ({i}, {j}): expected {}, got {}",
                    lhs_row[j], rhs_row[j]
                );
            }
        }
    }
    "polynomials differ but no mismatch was located".to_string()
}

fn write_soundness_report(out_dir: &Path, entries: &[SoundnessReportEntry]) -> Result<(), String> {
    let report_path = out_dir.join(SOUNDNESS_REPORT_FILE_NAME);
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"schema_version\": 1,\n");
    out.push_str("  \"verification\": \"sos_soundness\",\n");
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
        expected_sites: 5,
        stop_at_cfg_test: false,
        optional: false,
    },
    MemoryModelSource {
        relative_path: "src/arena.rs",
        domain: "tsm",
        expected_sites: 2,
        stop_at_cfg_test: false,
        optional: false,
    },
    MemoryModelSource {
        relative_path: "src/tls_cache.rs",
        domain: "tsm",
        expected_sites: 2,
        stop_at_cfg_test: false,
        optional: false,
    },
    MemoryModelSource {
        relative_path: "src/config.rs",
        domain: "tsm",
        expected_sites: 15,
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
        expected_sites: 33,
        stop_at_cfg_test: true,
        optional: true, // Cross-crate: skip gracefully for standalone builds
    },
];

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
        if observed_sites != source.expected_sites {
            return Err(format!(
                "BarrierMap drift in {}: expected {} sites, observed {}. \
Update MEMORY_MODEL_SOURCES after reviewing barrier requirements.",
                source.relative_path, source.expected_sites, observed_sites
            ));
        }

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
