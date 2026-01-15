//! Target process control methods for the Engine.

use super::Engine;

impl Engine {
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
