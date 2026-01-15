//! Monitoring control methods for the Engine.

use super::Engine;

impl Engine {
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
}
