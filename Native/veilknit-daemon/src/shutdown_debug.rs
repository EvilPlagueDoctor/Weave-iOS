//! Shutdown diagnostics
//!
//! Diagnostics are always retained in a capped text file. They are intentionally quiet on the
//! normal console/dashboard so long-running background nodes do not have their display overwritten.
//! Set VEILKNIT_DIAGNOSTICS_STDERR=1 before launch to mirror these lines to stderr for a live
//! debugging session. The file keeps at most 100,000 lines; when full it trims back to 90,000.

use std::{
    collections::VecDeque,
    fs::{create_dir_all, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, Once, OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

const TRACE_PATH: &str = "./user_data/shutdown-debug.log";
const MAX_TRACE_LINES: usize = 100_000;
const TRIM_TO_LINES: usize = 90_000;
static SESSION_HEADER: Once = Once::new();
static FILE_WARNING_PRINTED: AtomicBool = AtomicBool::new(false);
static STDERR_ENABLED: OnceLock<bool> = OnceLock::new();
static TRACE_STATE: OnceLock<Mutex<TraceFileState>> = OnceLock::new();

#[derive(Default)]
struct TraceFileState {
    line_count: Option<usize>,
}

fn trace_state() -> &'static Mutex<TraceFileState> {
    TRACE_STATE.get_or_init(|| Mutex::new(TraceFileState::default()))
}

fn diagnostics_to_stderr() -> bool {
    *STDERR_ENABLED.get_or_init(|| {
        std::env::var("VEILKNIT_DIAGNOSTICS_STDERR")
            .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
    })
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn count_lines(path: &Path) -> std::io::Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    let reader = BufReader::new(File::open(path)?);
    let mut count = 0usize;
    for line in reader.lines() {
        line?;
        count = count.saturating_add(1);
    }
    Ok(count)
}

fn trim_file_to_tail(path: &Path, keep_lines: usize) -> std::io::Result<usize> {
    if !path.exists() {
        return Ok(0);
    }

    let reader = BufReader::new(File::open(path)?);
    let mut tail = VecDeque::with_capacity(keep_lines);
    for line in reader.lines() {
        let line = line?;
        if tail.len() == keep_lines {
            tail.pop_front();
        }
        tail.push_back(line);
    }

    let retained = tail.len();
    let mut file = File::create(path)?;
    for line in tail {
        writeln!(file, "{line}")?;
    }
    file.flush()?;
    Ok(retained)
}

fn append_line(line: &str) -> std::io::Result<()> {
    let path = Path::new(TRACE_PATH);
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let mut state = trace_state()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut line_count = match state.line_count {
        Some(count) => count,
        None => count_lines(path)?,
    };

    if line_count >= MAX_TRACE_LINES {
        line_count = trim_file_to_tail(path, TRIM_TO_LINES)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "[{millis}] {line}", millis = unix_millis())?;
    file.flush()?;
    state.line_count = Some(line_count.saturating_add(1));
    Ok(())
}

/// Record one diagnostic line. File output is always on; stderr mirroring is opt-in.
pub fn log(message: String) {
    if diagnostics_to_stderr() {
        eprintln!("[shutdown-debug] {message}");
    }

    SESSION_HEADER.call_once(|| {
        let _ = append_line(&format!(
            "========== shutdown diagnostic session: pid={} ==========",
            std::process::id()
        ));
    });

    if let Err(error) = append_line(&format!("[shutdown-debug] {message}")) {
        if !FILE_WARNING_PRINTED.swap(true, Ordering::Relaxed) {
            eprintln!(
                "[shutdown-debug] WARNING: could not append {}: {}",
                TRACE_PATH, error
            );
        }
    }
}

pub const fn trace_path() -> &'static str {
    TRACE_PATH
}

#[macro_export]
macro_rules! shutdown_debug {
    ($($arg:tt)*) => {{
        $crate::shutdown_debug::log(format!($($arg)*));
    }};
}
