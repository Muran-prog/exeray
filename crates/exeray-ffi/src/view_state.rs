//! Engine view state for UI updates.

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
