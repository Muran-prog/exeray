//! Event access methods for the Engine.

use super::Engine;
use crate::event::Event;
use crate::event_iter::EventIter;
use crate::ffi::{self, Category, Status};

/// Convert a raw u8 to Category using exhaustive match.
///
/// This ensures compile-time safety: if the CXX enum definition changes,
/// this function will fail to compile until updated.
fn category_from_u8(val: u8) -> Category {
    match val {
        0 => Category::FileSystem,
        1 => Category::Registry,
        2 => Category::Network,
        3 => Category::Process,
        4 => Category::Scheduler,
        5 => Category::Input,
        6 => Category::Image,
        7 => Category::Thread,
        8 => Category::Memory,
        9 => Category::Script,
        10 => Category::Amsi,
        11 => Category::Dns,
        12 => Category::Security,
        13 => Category::Service,
        14 => Category::Wmi,
        15 => Category::Clr,
        // Unknown values default to FileSystem to avoid panics.
        // C++ side guarantees valid values; this is a safety fallback.
        _ => Category::FileSystem,
    }
}

/// Convert a raw u8 to Status using exhaustive match.
///
/// This ensures compile-time safety: if the CXX enum definition changes,
/// this function will fail to compile until updated.
fn status_from_u8(val: u8) -> Status {
    match val {
        0 => Status::Success,
        1 => Status::Denied,
        2 => Status::Pending,
        3 => Status::Error,
        4 => Status::Suspicious,
        // Unknown values default to Error to avoid panics.
        // C++ side guarantees valid values; this is a safety fallback.
        _ => Status::Error,
    }
}

impl Engine {
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

        Some(Event {
            id: ffi::event_get_id(&self.0, index),
            parent_id: ffi::event_get_parent(&self.0, index),
            timestamp: ffi::event_get_timestamp(&self.0, index),
            category: category_from_u8(ffi::event_get_category(&self.0, index)),
            status: status_from_u8(ffi::event_get_status(&self.0, index)),
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
