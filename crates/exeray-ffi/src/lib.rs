//! FFI bindings for the ExeRay C++ core library.
//!
//! Provides safe Rust wrappers around the C++ ExeRay engine,
//! including access to the EventGraph for event monitoring.

pub mod engine;
pub mod event;
pub mod event_iter;
mod tests;
pub mod view_state;

// CXX bridge must be in lib.rs for cxxbridge tool to find it
#[cxx::bridge(namespace = "exeray")]
mod ffi {
    /// Event category classification.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Category {
        FileSystem = 0,
        Registry = 1,
        Network = 2,
        Process = 3,
        Scheduler = 4,
        Input = 5,
    }

    /// Operation result status.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Status {
        Success = 0,
        Denied = 1,
        Pending = 2,
        Error = 3,
    }

    unsafe extern "C++" {
        include!("exeray/ffi.hpp");

        pub type Handle;

        pub fn create(arena_mb: usize, threads: usize) -> UniquePtr<Handle>;
        pub fn submit(self: Pin<&mut Handle>);
        pub fn generation(self: &Handle) -> u64;
        pub fn timestamp_ns(self: &Handle) -> u64;
        pub fn flags(self: &Handle) -> u64;
        pub fn progress(self: &Handle) -> f32;
        pub fn idle(self: &Handle) -> bool;
        pub fn threads(self: &Handle) -> usize;

        // Event graph accessors
        pub fn event_count(handle: &Handle) -> usize;
        pub fn event_get_id(handle: &Handle, index: usize) -> u64;
        pub fn event_get_parent(handle: &Handle, index: usize) -> u64;
        pub fn event_get_timestamp(handle: &Handle, index: usize) -> u64;
        pub fn event_get_category(handle: &Handle, index: usize) -> u8;
        pub fn event_get_status(handle: &Handle, index: usize) -> u8;
        pub fn event_get_operation(handle: &Handle, index: usize) -> u8;

        // Monitoring control
        pub fn start_monitoring(self: Pin<&mut Handle>, exe_path: &str) -> bool;
        pub fn stop_monitoring(self: Pin<&mut Handle>);

        // Target process control
        pub fn freeze_target(self: Pin<&mut Handle>);
        pub fn unfreeze_target(self: Pin<&mut Handle>);
        pub fn kill_target(self: Pin<&mut Handle>);

        // Target state
        pub fn target_pid(self: &Handle) -> u32;
        pub fn target_running(self: &Handle) -> bool;
    }
}

// Re-export public API
pub use engine::Engine;
pub use event::Event;
pub use event_iter::EventIter;
pub use ffi::Category;
pub use ffi::Status;
pub use view_state::ViewState;
