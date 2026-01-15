//! Event struct representing a single event from the EventGraph.

use crate::ffi::{Category, Status};

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
