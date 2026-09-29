// Optional example module showing how another subsystem can observe walks.

use futures::future::BoxFuture;

use crate::walk_task::{HopDirective, HopEvent, WalkRunReport, WalkSubscriber};

pub struct WalkConsoleLogger;

impl WalkSubscriber for WalkConsoleLogger {
    fn on_hop<'a>(&'a self, event: HopEvent) -> BoxFuture<'a, HopDirective> {
        Box::pin(async move {
            let parsed = event.snapshot.parse_full_user_dht();

            crate::tprintln!(
                "[walk subscriber] hop {}/{}: {} | {} record-table entries | {} new frontier candidates",
                event.hop_index,
                event.requested_hops,
                event.snapshot.target,
                parsed.record_table.len(),
                event.discovered_this_hop,
            );

            HopDirective::Continue
        })
    }

    fn on_walk_complete<'a>(&'a self, report: WalkRunReport) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            crate::tprintln!("[walk subscriber] finished: {report:?}");
        })
    }
}
