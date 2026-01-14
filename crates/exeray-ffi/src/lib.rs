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
}
