//! Three-region terminal administration console.
//!
//! The dashboard owns terminal drawing while active. Operational `tprintln!`
//! output is redirected into its scrollable activity pane, and existing
//! synchronous prompts are serviced by a small line editor in the command
//! region so background activity never corrupts user input.

use std::{
    collections::VecDeque,
    io::{self, Write},
    sync::{
        mpsc::{self, Receiver, Sender, SyncSender},
        Mutex, OnceLock,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Print, SetAttribute},
    terminal::{
        self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
    },
};

use crate::{
    network_events::{EventSeverity, NetworkEvent, NetworkEventEnvelope, StartupStageState},
    network_supervisor::NetworkStatus,
};

const MAX_ACTIVITY_LINES: usize = 2_000;
const HEADER_HEIGHT: u16 = 3;
const COMMAND_HEIGHT: u16 = 6;
const REDRAW_INTERVAL: Duration = Duration::from_millis(100);

static DASHBOARD_SENDER: OnceLock<Mutex<Option<Sender<ConsoleMessage>>>> = OnceLock::new();

fn sender_slot() -> &'static Mutex<Option<Sender<ConsoleMessage>>> {
    DASHBOARD_SENDER.get_or_init(|| Mutex::new(None))
}

#[derive(Debug)]
enum ConsoleMessage {
    Log(String),
    Event(NetworkEventEnvelope),
    Prompt {
        label: String,
        response: SyncSender<String>,
    },
    Shutdown,
}

pub struct ConsoleDashboard {
    sender: Sender<ConsoleMessage>,
    thread: Option<JoinHandle<()>>,
}

impl ConsoleDashboard {
    pub fn start(status: NetworkStatus) -> io::Result<Self> {
        let (sender, receiver) = mpsc::channel();
        {
            let mut slot = sender_slot().lock().unwrap_or_else(|e| e.into_inner());
            *slot = Some(sender.clone());
        }

        let thread = thread::Builder::new()
            .name("network-console-dashboard".to_string())
            .spawn(move || run_dashboard(receiver, status))?;

        Ok(Self {
            sender,
            thread: Some(thread),
        })
    }

    pub fn send_event(&self, event: NetworkEventEnvelope) {
        let _ = self.sender.send(ConsoleMessage::Event(event));
    }

    pub fn sender(&self) -> ConsoleDashboardSender {
        ConsoleDashboardSender {
            sender: self.sender.clone(),
        }
    }

    pub fn shutdown(mut self) {
        let _ = self.sender.send(ConsoleMessage::Shutdown);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let mut slot = sender_slot().lock().unwrap_or_else(|e| e.into_inner());
        *slot = None;
    }
}

impl Drop for ConsoleDashboard {
    fn drop(&mut self) {
        if self.thread.is_some() {
            let _ = self.sender.send(ConsoleMessage::Shutdown);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            let mut slot = sender_slot().lock().unwrap_or_else(|e| e.into_inner());
            *slot = None;
        }
    }
}

#[derive(Clone)]
pub struct ConsoleDashboardSender {
    sender: Sender<ConsoleMessage>,
}

impl ConsoleDashboardSender {
    pub fn send_event(&self, event: NetworkEventEnvelope) {
        let _ = self.sender.send(ConsoleMessage::Event(event));
    }
}

/// Redirect a complete already-timestamped line into the dashboard.
/// Returns false when no dashboard is active, allowing the caller to fall
/// back to ordinary stdout/stderr.
pub fn try_log(line: String) -> bool {
    let sender = {
        let slot = sender_slot().lock().unwrap_or_else(|e| e.into_inner());
        slot.clone()
    };
    sender
        .map(|sender| sender.send(ConsoleMessage::Log(line)).is_ok())
        .unwrap_or(false)
}

pub fn is_active() -> bool {
    sender_slot()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_some()
}

/// Obtain a line from the dashboard's command editor. Returns `None` when the
/// dashboard is not active or has closed, so callers can use stdin normally.
pub fn prompt(label: &str) -> Option<String> {
    let sender = {
        let slot = sender_slot().lock().unwrap_or_else(|e| e.into_inner());
        slot.clone()
    }?;
    let (response_tx, response_rx) = mpsc::sync_channel(1);
    sender
        .send(ConsoleMessage::Prompt {
            label: label.to_string(),
            response: response_tx,
        })
        .ok()?;
    loop {
        if crate::mobile_bridge::stop_requested() {
            return Some(String::new());
        }
        match response_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(value) => return Some(value),
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}

#[derive(Default)]
struct HeaderState {
    lifecycle: String,
    attached: bool,
    dht_verified: bool,
    last_handshake: String,
    walk: String,
    mailbox: String,
    last_event: String,
    uptime_ms: u64,
}

struct PendingPrompt {
    label: String,
    input: String,
    cursor: usize,
    response: SyncSender<String>,
}

struct DashboardState {
    header: HeaderState,
    activity: VecDeque<String>,
    scroll_offset: usize,
    prompt: Option<PendingPrompt>,
    dirty: bool,
    compact: bool,
}

impl DashboardState {
    fn new(status: NetworkStatus) -> Self {
        Self {
            header: HeaderState {
                lifecycle: format!("{:?}", status.lifecycle),
                attached: status.network_attached,
                dht_verified: status.dht_network_verified,
                last_handshake: "none".to_string(),
                walk: "idle".to_string(),
                mailbox: "idle".to_string(),
                last_event: "console started".to_string(),
                ..HeaderState::default()
            },
            activity: VecDeque::new(),
            scroll_offset: 0,
            prompt: None,
            dirty: true,
            compact: false,
        }
    }

    fn push_line(&mut self, line: String) {
        for line in line.lines() {
            self.activity.push_back(line.to_string());
        }
        while self.activity.len() > MAX_ACTIVITY_LINES {
            self.activity.pop_front();
        }
        if self.scroll_offset == 0 {
            self.dirty = true;
        }
    }

    fn apply_event(&mut self, envelope: NetworkEventEnvelope) {
        self.header.uptime_ms = envelope.uptime_ms;
        match envelope.event {
            NetworkEvent::StartupStageChanged { stage, state, .. } => {
                self.header.lifecycle = match state {
                    StartupStageState::Failed => "Startup failed".to_string(),
                    _ => format!("Starting: {}", stage.label()),
                };
            }
            NetworkEvent::StartupCompleted { .. } => {
                self.header.lifecycle = "Running".to_string();
                self.header.last_event = "startup complete".to_string();
            }
            NetworkEvent::StartupFailed { .. } => {
                self.header.lifecycle = "Startup incomplete".to_string();
                self.header.last_event = "startup failure".to_string();
            }
            NetworkEvent::NetworkAttachmentChanged { attached, state } => {
                self.header.attached = attached;
                self.header.last_event = format!("attachment: {state}");
            }
            NetworkEvent::DhtNetworkVerified { duration_ms, .. } => {
                self.header.dht_verified = true;
                self.header.last_event = format!("DHT verified in {duration_ms} ms");
            }
            NetworkEvent::HandshakeStarted { peer, verification } => {
                self.header.last_handshake = format!(
                    "{} {}",
                    if verification { "verify" } else { "start" },
                    shorten(&peer, 24)
                );
            }
            NetworkEvent::HandshakeSucceeded { peer, duration_ms } => {
                self.header.last_handshake =
                    format!("OK {} ({} ms)", shorten(&peer, 20), duration_ms);
            }
            NetworkEvent::HandshakeFailed { peer, reason, duration_ms } => {
                self.header.last_handshake = format!(
                    "FAIL {}: {} ({} ms)",
                    shorten(&peer, 14),
                    shorten(&reason, 24),
                    duration_ms
                );
            }
            NetworkEvent::HandshakeSkipped { peer, reason } => {
                self.header.last_handshake = format!(
                    "skip {}: {}",
                    shorten(&peer, 14),
                    shorten(&reason, 24)
                );
            }
            NetworkEvent::WalkScheduled { reason, delay_ms } => {
                self.header.walk = format!("scheduled {} in {}s", reason, delay_ms / 1000);
            }
            NetworkEvent::WalkStarted { reason, requested_hops } => {
                self.header.walk = format!("{} 0/{}", reason, requested_hops);
            }
            NetworkEvent::WalkProgress { completed_hops, requested_hops, .. } => {
                self.header.walk = format!("running {completed_hops}/{requested_hops}");
            }
            NetworkEvent::WalkFinished { completed_hops, new_nodes, duration_ms, .. } => {
                self.header.walk =
                    format!("done {completed_hops} hops, +{new_nodes} ({}ms)", duration_ms);
            }
            NetworkEvent::WalkFailed { reason, .. } => {
                self.header.walk = format!("failed: {}", shorten(&reason, 30));
            }
            NetworkEvent::MailStored { recipient, duration_ms, .. } => {
                self.header.mailbox =
                    format!("stored for {} ({}ms)", shorten(&recipient, 18), duration_ms);
            }
            NetworkEvent::MailboxActivity { activity, detail } => {
                self.header.mailbox =
                    format!("{}: {}", activity, shorten(&detail, 28));
            }
            NetworkEvent::MailOperationFailed { operation, reason, .. } => {
                self.header.mailbox =
                    format!("{} failed: {}", operation, shorten(&reason, 24));
            }
            NetworkEvent::ServiceStopping { service } => {
                self.header.lifecycle = format!("Stopping {service}");
            }
            NetworkEvent::ServiceStopped { service, error, .. } => {
                self.header.last_event = match error {
                    Some(error) => format!("{service}: {}", shorten(&error, 30)),
                    None => format!("{service} stopped"),
                };
            }
            NetworkEvent::Diagnostic { message, .. } => {
                self.header.last_event = shorten(&message, 52);
            }
            other => {
                self.header.last_event = shorten(&format!("{other:?}"), 52);
            }
        }

        if matches!(envelope.severity, EventSeverity::Warning | EventSeverity::Error) {
            self.push_line(format!(
                "[event {:?}] {:?}", envelope.severity, envelope.event_id
            ));
        }
        self.dirty = true;
    }
}

fn run_dashboard(receiver: Receiver<ConsoleMessage>, status: NetworkStatus) {
    let mut stdout = io::stdout();
    if terminal::enable_raw_mode().is_err()
        || execute!(stdout, EnterAlternateScreen, Hide).is_err()
    {
        let mut slot = sender_slot().lock().unwrap_or_else(|e| e.into_inner());
        *slot = None;
        return;
    }

    let mut state = DashboardState::new(status);
    let mut last_draw = Instant::now() - REDRAW_INTERVAL;
    let mut running = true;

    while running {
        while let Ok(message) = receiver.try_recv() {
            match message {
                ConsoleMessage::Log(line) => state.push_line(line),
                ConsoleMessage::Event(event) => state.apply_event(event),
                ConsoleMessage::Prompt { label, response } => {
                    state.prompt = Some(PendingPrompt {
                        label,
                        input: String::new(),
                        cursor: 0,
                        response,
                    });
                    state.dirty = true;
                }
                ConsoleMessage::Shutdown => {
                    running = false;
                    break;
                }
            }
        }

        if !running {
            break;
        }

        if event::poll(Duration::from_millis(25)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                // Windows terminals may emit both Press and Release events.
                // Treating releases as input duplicates every character after
                // a short delay, so only Press/Repeat events reach the editor.
                if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                    handle_key(key, &mut state);
                }
            }
        }

        if state.dirty && last_draw.elapsed() >= REDRAW_INTERVAL {
            let _ = draw(&mut stdout, &state);
            state.dirty = false;
            last_draw = Instant::now();
        }
    }

    let _ = execute!(stdout, Show, LeaveAlternateScreen, Clear(ClearType::All));
    let _ = terminal::disable_raw_mode();
}

fn handle_key(key: KeyEvent, state: &mut DashboardState) {
    // In raw terminal mode Ctrl-C may arrive as a crossterm key event instead of an OS signal.
    // Feed it into the exact same host stop flag used by the desktop signal handler / Android
    // foreground service so the main command prompt wakes and enters Lifecycle shutdown.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        crate::mobile_bridge::request_stop();
        state.dirty = true;
        return;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('l') {
        state.dirty = true;
        return;
    }
    if key.code == KeyCode::F(2) {
        state.compact = !state.compact;
        state.dirty = true;
        return;
    }

    match key.code {
        KeyCode::PageUp => {
            state.scroll_offset = state.scroll_offset.saturating_add(10)
                .min(state.activity.len().saturating_sub(1));
            state.dirty = true;
        }
        KeyCode::PageDown => {
            state.scroll_offset = state.scroll_offset.saturating_sub(10);
            state.dirty = true;
        }
        KeyCode::End => {
            state.scroll_offset = 0;
            state.dirty = true;
        }
        _ => {}
    }

    let Some(prompt) = state.prompt.as_mut() else {
        return;
    };

    match key.code {
        KeyCode::Enter => {
            let value = prompt.input.trim().to_string();
            let _ = prompt.response.send(value);
            state.prompt = None;
            state.scroll_offset = 0;
            state.dirty = true;
        }
        KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            prompt.input.insert(prompt.cursor, ch);
            prompt.cursor += ch.len_utf8();
            state.dirty = true;
        }
        KeyCode::Backspace if prompt.cursor > 0 => {
            let previous = prompt.input[..prompt.cursor]
                .char_indices()
                .next_back()
                .map(|(index, _)| index)
                .unwrap_or(0);
            prompt.input.drain(previous..prompt.cursor);
            prompt.cursor = previous;
            state.dirty = true;
        }
        KeyCode::Delete if prompt.cursor < prompt.input.len() => {
            let next = prompt.input[prompt.cursor..]
                .char_indices()
                .nth(1)
                .map(|(index, _)| prompt.cursor + index)
                .unwrap_or(prompt.input.len());
            prompt.input.drain(prompt.cursor..next);
            state.dirty = true;
        }
        KeyCode::Left if prompt.cursor > 0 => {
            prompt.cursor = prompt.input[..prompt.cursor]
                .char_indices()
                .next_back()
                .map(|(index, _)| index)
                .unwrap_or(0);
            state.dirty = true;
        }
        KeyCode::Right if prompt.cursor < prompt.input.len() => {
            prompt.cursor = prompt.input[prompt.cursor..]
                .char_indices()
                .nth(1)
                .map(|(index, _)| prompt.cursor + index)
                .unwrap_or(prompt.input.len());
            state.dirty = true;
        }
        KeyCode::Home => {
            prompt.cursor = 0;
            state.dirty = true;
        }
        KeyCode::End => {
            prompt.cursor = prompt.input.len();
            state.dirty = true;
        }
        _ => {}
    }
}

fn draw(stdout: &mut io::Stdout, state: &DashboardState) -> io::Result<()> {
    let (width, height) = terminal::size().unwrap_or((120, 30));
    let width = width.max(40);
    let height = height.max(12);
    let activity_top = HEADER_HEIGHT;
    let command_top = height.saturating_sub(COMMAND_HEIGHT);
    let activity_height = command_top.saturating_sub(activity_top + 1);

    queue!(stdout, MoveTo(0, 0), Clear(ClearType::All), SetAttribute(Attribute::Bold))?;
    write_padded(
        stdout,
        0,
        width,
        &format!(
            "Network: {} | Attached: {} | DHT: {} | Uptime: {}",
            state.header.lifecycle,
            yes_no(state.header.attached),
            if state.header.dht_verified { "verified" } else { "pending" },
            format_duration(state.header.uptime_ms)
        ),
    )?;
    queue!(stdout, SetAttribute(Attribute::Reset))?;
    write_padded(
        stdout,
        1,
        width,
        &format!(
            "Handshake: {} | Walk: {} | Mail: {}",
            state.header.last_handshake, state.header.walk, state.header.mailbox
        ),
    )?;
    write_padded(
        stdout,
        2,
        width,
        &format!("Last: {}", state.header.last_event),
    )?;

    draw_rule(stdout, activity_top, width, " Recent activity ")?;
    draw_activity(stdout, state, activity_top + 1, activity_height, width)?;
    draw_rule(stdout, command_top, width, " Commands ")?;

    let hints = if state.compact {
        "help | mail | H handshake | T walk | U save-log | Q quit"
    } else {
        "N New  G Inspect  W Write  A Write-all  R/L Owned-read  E/X/Y External-read"
    };
    write_padded(stdout, command_top + 1, width, hints)?;
    if state.compact {
        write_padded(stdout, command_top + 2, width, "F2 full commands | PgUp/PgDn activity | End latest")?;
    } else {
        write_padded(
            stdout,
            command_top + 2,
            width,
            "S Save  C Route  D Debug  H Handshake  K Handshake-status  T/P/O Walk",
        )?;
        write_padded(
            stdout,
            command_top + 3,
            width,
            "I Nodes  mail ... Mailbox  V App-reputation  Z Retract-app  U Save-log  Q Quit",
        )?;
    }

    let prompt_row = height.saturating_sub(2);
    let help_row = height.saturating_sub(1);
    let (prompt_text, cursor_col) = if let Some(prompt) = &state.prompt {
        render_prompt(prompt, width.saturating_sub(1) as usize)
    } else {
        ("Working...".to_string(), 0)
    };
    write_padded(stdout, prompt_row, width, &prompt_text)?;
    write_padded(
        stdout,
        help_row,
        width,
        "Enter submit | arrows edit | PgUp/PgDn scroll | End latest | F2 compact",
    )?;
    queue!(stdout, MoveTo(cursor_col.min(width - 1), prompt_row), Show)?;
    stdout.flush()
}

fn draw_activity(
    stdout: &mut io::Stdout,
    state: &DashboardState,
    top: u16,
    height: u16,
    width: u16,
) -> io::Result<()> {
    let available = height as usize;
    let content_width = width.max(1) as usize;

    // Activity entries are stored unmodified and wrapped at draw time. This
    // preserves complete record keys and adapts automatically when the user
    // resizes the terminal.
    let visual_lines: Vec<String> = state
        .activity
        .iter()
        .flat_map(|line| wrap_line(line, content_width))
        .collect();

    let len = visual_lines.len();
    let end = len.saturating_sub(state.scroll_offset);
    let start = end.saturating_sub(available);
    let mut row = top;
    for line in visual_lines.iter().skip(start).take(end - start) {
        write_padded(stdout, row, width, line)?;
        row += 1;
    }
    while row < top + height {
        write_padded(stdout, row, width, "")?;
        row += 1;
    }
    if state.scroll_offset > 0 && height > 0 {
        let marker = format!("[{} visual lines above latest]", state.scroll_offset);
        let x = width.saturating_sub(marker.len() as u16 + 1);
        queue!(stdout, MoveTo(x, top), Print(marker))?;
    }
    Ok(())
}

fn wrap_line(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }

    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
        return vec![String::new()];
    }

    chars
        .chunks(width)
        .map(|chunk| chunk.iter().collect())
        .collect()
}

fn draw_rule(stdout: &mut io::Stdout, row: u16, width: u16, title: &str) -> io::Result<()> {
    let mut line = "-".repeat(width as usize);
    let title = shorten(title, width.saturating_sub(2) as usize);
    if width as usize > title.len() + 2 {
        let start = 1;
        line.replace_range(start..start + title.len(), &title);
    }
    write_padded(stdout, row, width, &line)
}

fn write_padded(stdout: &mut io::Stdout, row: u16, width: u16, text: &str) -> io::Result<()> {
    let clipped = shorten(text, width as usize);
    queue!(stdout, MoveTo(0, row), Clear(ClearType::CurrentLine), Print(clipped))
}

fn shorten(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_string();
    }
    if max_chars <= 3 {
        return ".".repeat(max_chars);
    }
    text.chars().take(max_chars - 3).collect::<String>() + "..."
}

fn render_prompt(prompt: &PendingPrompt, max_chars: usize) -> (String, u16) {
    let full = format!("{}{}", prompt.label, prompt.input);
    let chars: Vec<char> = full.chars().collect();
    let cursor_chars = prompt.label.chars().count()
        + prompt.input[..prompt.cursor].chars().count();
    let window_start = chars.len().saturating_sub(max_chars);
    let visible = chars.iter().skip(window_start).collect::<String>();
    let cursor = cursor_chars
        .saturating_sub(window_start)
        .min(max_chars) as u16;
    (visible, cursor)
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn format_duration(ms: u64) -> String {
    let total_seconds = ms / 1000;
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}
