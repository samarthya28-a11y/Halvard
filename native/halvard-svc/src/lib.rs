//! Halvard native service, Stage A prototype.
//! `brain` decides, `replay` feeds it recorded events (the same fixtures the Python reference replays), `watch` and `suspend` are the Windows parts.
pub mod brain;
pub mod guard;
pub mod logsink;
pub mod replay;
#[cfg(windows)]
pub mod etw;
#[cfg(windows)]
pub mod service;
#[cfg(windows)]
pub mod suspend;
#[cfg(windows)]
pub mod watch;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
