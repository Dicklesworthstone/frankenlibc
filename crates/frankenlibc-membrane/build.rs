use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const FRAGMENTATION_TASK_PATH: &str = "artifacts/sos/fragmentation_certificate.task";
const GENERATED_RS_PATH: &str = "sos_fragmentation_generated.rs";

#[derive(Debug)]
struct FragmentationTask {
    dimension: usize,
    monomial_degree: u32,
    barrier_budget_milli: i64,
    gram_matrix: Vec<Vec<i64>>,
}

fn main() {
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR must be available for build script"),
    );
    let task_path = manifest_dir.join(FRAGMENTATION_TASK_PATH);
    println!("cargo:rerun-if-changed={}", task_path.display());

    let task = parse_fragmentation_task(&task_path).unwrap_or_else(|err| {
        panic!(
            "failed to parse SOS task artifact {}: {err}",
            task_path.display()
        )
    });
    validate_task(&task)
        .unwrap_or_else(|err| panic!("invalid SOS task artifact {}: {err}", task_path.display()));

    let proof_hash = compute_proof_hash(
        task.dimension,
        task.monomial_degree,
        task.barrier_budget_milli,
        &task.gram_matrix,
    );
    let task_sha256_hex =
        compute_file_sha256_hex(&task_path).expect("failed to hash task artifact bytes");

    let out_dir =
        PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be available for build script"));
    let generated_path = out_dir.join(GENERATED_RS_PATH);
    let generated = render_generated_rs(&task, proof_hash, &task_sha256_hex);
    fs::write(&generated_path, generated).unwrap_or_else(|err| {
        panic!(
            "failed to write generated artifact {}: {err}",
            generated_path.display()
        )
    });
}

fn parse_fragmentation_task(path: &Path) -> Result<FragmentationTask, String> {
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

    Ok(FragmentationTask {
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

fn validate_task(task: &FragmentationTask) -> Result<(), String> {
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

fn render_generated_rs(
    task: &FragmentationTask,
    proof_hash: [u8; 32],
    task_sha256_hex: &str,
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

    format!(
        "// @generated by crates/frankenlibc-membrane/build.rs from {FRAGMENTATION_TASK_PATH}\n\
pub(crate) const FRAGMENTATION_CERT_DIM: usize = {dimension};\n\
pub(crate) const FRAGMENTATION_MONOMIAL_DEGREE: u32 = {monomial_degree};\n\
pub(crate) const FRAGMENTATION_BARRIER_BUDGET_MILLI: i64 = {barrier_budget_milli};\n\
pub(crate) const FRAGMENTATION_TASK_SOURCE_SHA256_HEX: &str = \"{task_sha256_hex}\";\n\
pub(crate) static FRAGMENTATION_GRAM_MATRIX: [[i64; FRAGMENTATION_CERT_DIM]; FRAGMENTATION_CERT_DIM] = [\n\
{gram_matrix_rows}];\n\
pub(crate) const FRAGMENTATION_PROOF_HASH: [u8; 32] = [{proof_hash_bytes}];\n",
        dimension = task.dimension,
        monomial_degree = task.monomial_degree,
        barrier_budget_milli = task.barrier_budget_milli,
        task_sha256_hex = task_sha256_hex,
        gram_matrix_rows = gram_matrix_rows,
        proof_hash_bytes = proof_hash_bytes,
    )
}
