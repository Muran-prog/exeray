//! FFI bindings for the ExeRay C++ core library.
//!
//! Provides safe Rust wrappers around the C++ ExeRay engine,
//! including access to the EventGraph for event monitoring.

#[cxx::bridge(namespace = "exeray")]
mod ffi {
    /// Event category classification.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Category {
        FileSystem = 0,
        Registry = 1,
        Network = 2,
        Process = 3,
        Scheduler = 4,
        Input = 5,
    }

    /// Operation result status.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Status {
        Success = 0,
        Denied = 1,
        Pending = 2,
        Error = 3,
    }

    unsafe extern "C++" {
        include!("exeray/ffi.hpp");

        type Handle;

        fn create(arena_mb: usize, threads: usize) -> UniquePtr<Handle>;
        fn submit(self: Pin<&mut Handle>);
        fn generation(self: &Handle) -> u64;
        fn timestamp_ns(self: &Handle) -> u64;
        fn flags(self: &Handle) -> u64;
        fn progress(self: &Handle) -> f32;
        fn idle(self: &Handle) -> bool;
        fn threads(self: &Handle) -> usize;

        // Event graph accessors
        fn event_count(handle: &Handle) -> usize;
        fn event_get_id(handle: &Handle, index: usize) -> u64;
        fn event_get_parent(handle: &Handle, index: usize) -> u64;
        fn event_get_timestamp(handle: &Handle, index: usize) -> u64;
        fn event_get_category(handle: &Handle, index: usize) -> u8;
        fn event_get_status(handle: &Handle, index: usize) -> u8;
        fn event_get_operation(handle: &Handle, index: usize) -> u8;

        // Monitoring control
        fn start_monitoring(self: Pin<&mut Handle>, exe_path: &str) -> bool;
        fn stop_monitoring(self: Pin<&mut Handle>);

        // Target process control
        fn freeze_target(self: Pin<&mut Handle>);
        fn unfreeze_target(self: Pin<&mut Handle>);
        fn kill_target(self: Pin<&mut Handle>);

        // Target state
        fn target_pid(self: &Handle) -> u32;
        fn target_running(self: &Handle) -> bool;
    }
}

pub use ffi::Category;
pub use ffi::Status;

/// Engine view state for UI updates.
pub struct ViewState {
    pub generation: u64,
    pub timestamp_ns: u64,
    pub flags: u64,
    pub progress: f32,
}

impl ViewState {
    pub const IDLE: u64 = 0;
    pub const PENDING: u64 = 1 << 0;
    pub const COMPLETE: u64 = 1 << 1;
    pub const READY: u64 = 1 << 2;
    pub const ERROR: u64 = 1 << 3;

    pub fn is_complete(&self) -> bool {
        self.flags & Self::COMPLETE != 0
    }

    pub fn is_pending(&self) -> bool {
        self.flags & Self::PENDING != 0
    }
}

/// A single event from the EventGraph.
#[derive(Debug, Clone, Copy)]
pub struct Event {
    pub id: u64,
    pub parent_id: u64,
    pub timestamp: u64,
    pub category: Category,
    pub status: Status,
    pub operation: u8,
}

/// Iterator over events in the EventGraph.
pub struct EventIter<'a> {
    engine: &'a Engine,
    index: usize,
    count: usize,
}

impl<'a> Iterator for EventIter<'a> {
    type Item = Event;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        let event = self.engine.get_event(self.index);
        self.index += 1;
        event
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.count.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for EventIter<'_> {}

/// Safe wrapper around the ExeRay C++ engine.
pub struct Engine(cxx::UniquePtr<ffi::Handle>);

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

    /// Get the current event count.
    pub fn event_count(&self) -> usize {
        ffi::event_count(&self.0)
    }

    /// Get an event by index.
    ///
    /// Returns `None` if the index is out of bounds.
    pub fn get_event(&self, index: usize) -> Option<Event> {
        if index >= self.event_count() {
            return None;
        }

        // cxx shared enums are repr(transparent) structs with a repr field.
        // Direct construction avoids manual match statements and is type-safe.
        Some(Event {
            id: ffi::event_get_id(&self.0, index),
            parent_id: ffi::event_get_parent(&self.0, index),
            timestamp: ffi::event_get_timestamp(&self.0, index),
            category: Category {
                repr: ffi::event_get_category(&self.0, index),
            },
            status: Status {
                repr: ffi::event_get_status(&self.0, index),
            },
            operation: ffi::event_get_operation(&self.0, index),
        })
    }

    /// Iterate over all events.
    pub fn iter_events(&self) -> EventIter<'_> {
        EventIter {
            engine: self,
            index: 0,
            count: self.event_count(),
        }
    }

    // -------------------------------------------------------------------------
    // Monitoring Control
    // -------------------------------------------------------------------------

    /// Start monitoring a target process.
    ///
    /// Launches the executable in suspended mode, creates an ETW session,
    /// enables kernel providers, and starts event capture.
    ///
    /// # Arguments
    /// * `exe_path` - Path to the executable to launch and monitor (UTF-8).
    ///
    /// # Returns
    /// `true` if monitoring started successfully, `false` on failure.
    pub fn start_monitoring(&mut self, exe_path: &str) -> bool {
        self.0.pin_mut().start_monitoring(exe_path)
    }

    /// Stop monitoring and terminate the target process.
    ///
    /// Stops the ETW session, joins the consumer thread, and terminates
    /// the target process if still running.
    pub fn stop_monitoring(&mut self) {
        self.0.pin_mut().stop_monitoring();
    }

    // -------------------------------------------------------------------------
    // Target Process Control
    // -------------------------------------------------------------------------

    /// Freeze (suspend) the target process.
    pub fn freeze_target(&mut self) {
        self.0.pin_mut().freeze_target();
    }

    /// Unfreeze (resume) the target process.
    pub fn unfreeze_target(&mut self) {
        self.0.pin_mut().unfreeze_target();
    }

    /// Terminate the target process.
    pub fn kill_target(&mut self) {
        self.0.pin_mut().kill_target();
    }

    // -------------------------------------------------------------------------
    // Target State
    // -------------------------------------------------------------------------

    /// Get the target process ID.
    ///
    /// Returns 0 if not currently monitoring a process.
    pub fn target_pid(&self) -> u32 {
        self.0.target_pid()
    }

    /// Check if the target process is still running.
    ///
    /// Returns `true` if currently monitoring and the target is running.
    pub fn target_running(&self) -> bool {
        self.0.target_running()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_count_initially_zero() {
        let engine = Engine::new(64, 1);
        assert_eq!(engine.event_count(), 0);
    }

    #[test]
    fn test_get_event_out_of_bounds() {
        let engine = Engine::new(64, 1);
        assert!(engine.get_event(0).is_none());
        assert!(engine.get_event(100).is_none());
    }

    #[test]
    fn test_iter_events_empty() {
        let engine = Engine::new(64, 1);
        assert_eq!(engine.iter_events().count(), 0);
    }

    #[test]
    fn test_category_enum_values() {
        assert_eq!(Category::FileSystem.repr, 0);
        assert_eq!(Category::Registry.repr, 1);
        assert_eq!(Category::Network.repr, 2);
        assert_eq!(Category::Process.repr, 3);
        assert_eq!(Category::Scheduler.repr, 4);
        assert_eq!(Category::Input.repr, 5);
    }

    #[test]
    fn test_status_enum_values() {
        assert_eq!(Status::Success.repr, 0);
        assert_eq!(Status::Denied.repr, 1);
        assert_eq!(Status::Pending.repr, 2);
        assert_eq!(Status::Error.repr, 3);
    }

    // -------------------------------------------------------------------------
    // Monitoring API Presence Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_start_stop_monitoring_api_exists() {
        let mut engine = Engine::new(64, 1);
        // On non-Windows, start_monitoring returns false (no ETW support)
        // On Windows without a valid exe, it will also return false
        // This test verifies the API is callable without panicking
        let _ = engine.start_monitoring("nonexistent.exe");
        engine.stop_monitoring();
    }

    #[test]
    fn test_freeze_unfreeze_api_exists() {
        let mut engine = Engine::new(64, 1);
        // These should be no-ops when not monitoring
        engine.freeze_target();
        engine.unfreeze_target();
    }

    #[test]
    fn test_kill_target_api_exists() {
        let mut engine = Engine::new(64, 1);
        // Should be no-op when not monitoring
        engine.kill_target();
    }

    #[test]
    fn test_target_state_api_exists() {
        let engine = Engine::new(64, 1);
        // PID should be 0 when not monitoring
        assert_eq!(engine.target_pid(), 0);
        // Should not be running when not monitoring
        assert!(!engine.target_running());
    }
}
