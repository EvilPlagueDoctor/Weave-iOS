//! No-terminal fallback used when the `console-ui` feature is disabled.

use std::io;

use crate::{
    network_events::NetworkEventEnvelope,
    network_supervisor::NetworkStatus,
};

pub struct ConsoleDashboard;

impl ConsoleDashboard {
    pub fn start(_status: NetworkStatus) -> io::Result<Self> {
        Ok(Self)
    }

    pub fn send_event(&self, _event: NetworkEventEnvelope) {}

    pub fn sender(&self) -> ConsoleDashboardSender {
        ConsoleDashboardSender
    }

    pub fn shutdown(self) {}
}

#[derive(Clone)]
pub struct ConsoleDashboardSender;

impl ConsoleDashboardSender {
    pub fn send_event(&self, _event: NetworkEventEnvelope) {}
}

pub fn try_log(_line: String) -> bool {
    false
}

pub fn is_active() -> bool {
    false
}

pub fn prompt(_label: &str) -> Option<String> {
    None
}
