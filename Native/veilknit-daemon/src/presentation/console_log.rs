//! Small cross-platform console logger used by the daemon and its modules.
//!
//! Every call writes one complete line while holding stdout/stderr's lock so
//! messages from concurrent Tokio tasks do not get interleaved mid-line.

use std::{
    collections::VecDeque,
    fmt,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};


const MAX_SESSION_LOG_LINES: usize = 100_000;
static SESSION_LOG: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();

fn session_log() -> &'static Mutex<VecDeque<String>> {
    SESSION_LOG.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn remember_line(line: &str) {
    let mut log = session_log().lock().unwrap_or_else(|error| error.into_inner());
    log.push_back(line.to_string());
    while log.len() > MAX_SESSION_LOG_LINES {
        log.pop_front();
    }
}

#[derive(Debug, Clone)]
pub struct SavedSessionLog {
    pub path: PathBuf,
    pub lines: usize,
}

pub fn save_session_log(requested_path: Option<&str>) -> io::Result<SavedSessionLog> {
    let path = requested_path
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_session_log_path);

    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }

    let snapshot: Vec<String> = session_log()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .cloned()
        .collect();
    let mut file = File::create(&path)?;
    for line in &snapshot {
        writeln!(file, "{line}")?;
    }
    file.flush()?;
    Ok(SavedSessionLog {
        path,
        lines: snapshot.len(),
    })
}

fn default_session_log_path() -> PathBuf {
    let filename = format!("session_{}.log", filename_timestamp());
    Path::new("session_logs").join(filename)
}

fn filename_timestamp() -> String {
    utc_timestamp()
        .trim_end_matches(" UTC")
        .replace([':', ' '], "-")
        .replace('.', "-")
}

pub(crate) fn utc_timestamp() -> String {
    let total_millis = crate::support::timing::unix_millis();
    let total_seconds = (total_millis / 1_000) as i64;
    let millis = (total_millis % 1_000) as u32;

    let days = total_seconds.div_euclid(86_400);
    let seconds_today = total_seconds.rem_euclid(86_400);
    let hour = seconds_today / 3_600;
    let minute = (seconds_today % 3_600) / 60;
    let second = seconds_today % 60;

    // Convert days since 1970-01-01 to a Gregorian date without another crate.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096)
            / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);

    format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{millis:03} UTC"
    )
}

pub fn stdout_line(args: fmt::Arguments<'_>) {
    let line = format!("[{}] {}", utc_timestamp(), args);
    remember_line(&line);
    #[cfg(any(target_os = "android", target_os = "ios"))]
    crate::mobile_bridge::publish_log(&line);
    if crate::console_ui::try_log(line.clone()) {
        return;
    }
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let _ = writeln!(out, "{line}");
}

pub fn stderr_line(args: fmt::Arguments<'_>) {
    let line = format!("[{}] [stderr] {}", utc_timestamp(), args);
    remember_line(&line);
    #[cfg(any(target_os = "android", target_os = "ios"))]
    crate::mobile_bridge::publish_log(&line);
    if crate::console_ui::try_log(line.clone()) {
        return;
    }
    let stderr = io::stderr();
    let mut out = stderr.lock();
    let _ = writeln!(out, "{line}");
}

#[macro_export]
macro_rules! tprintln {
    () => {
        $crate::console_log::stdout_line(format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::console_log::stdout_line(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! teprintln {
    () => {
        $crate::console_log::stderr_line(format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::console_log::stderr_line(format_args!($($arg)*))
    };
}
