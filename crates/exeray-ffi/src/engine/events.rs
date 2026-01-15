//! Event access methods for the Engine.

use super::Engine;
use crate::event::Event;
use crate::event_iter::EventIter;
use crate::ffi::{self, Category, Status};

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
