//! Safe wrapper around the ExeRay C++ engine.

mod control;
mod events;
mod monitoring;

use crate::ffi;
use crate::view_state::ViewState;

// Note: These modules extend Engine with impl blocks, no items to re-export.

/// Safe wrapper around the ExeRay C++ engine.
pub struct Engine(pub(crate) cxx::UniquePtr<ffi::Handle>);

impl Engine {
    /// Create a new engine with the specified arena size (in MB) and thread count.
    pub fn new(arena_mb: usize, threads: usize) -> Self {
        Self(ffi::create(arena_mb, threads))
    }

    /// Submit work to the engine.
    pub fn submit(&mut self) {
        self.0.pin_mut().submit();
    }

    /// Poll the current engine state.
    pub fn poll(&self) -> ViewState {
        ViewState {
            generation: self.0.generation(),
            timestamp_ns: self.0.timestamp_ns(),
            flags: self.0.flags(),
            progress: self.0.progress(),
        }
    }

    /// Check if the engine is idle.
    pub fn idle(&self) -> bool {
        self.0.idle()
    }

    /// Get the number of worker threads.
    pub fn threads(&self) -> usize {
        self.0.threads()
    }
}
