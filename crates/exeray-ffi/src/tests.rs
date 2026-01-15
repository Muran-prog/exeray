//! Unit tests for the ExeRay FFI module.

#[cfg(test)]
mod tests {
    use crate::engine::Engine;
    use crate::ffi::{Category, Status};

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

    #[test]
    fn test_start_stop_monitoring_api_exists() {
        let mut engine = Engine::new(64, 1);
        let _ = engine.start_monitoring("nonexistent.exe");
        engine.stop_monitoring();
    }

    #[test]
    fn test_freeze_unfreeze_api_exists() {
        let mut engine = Engine::new(64, 1);
        engine.freeze_target();
        engine.unfreeze_target();
    }

    #[test]
    fn test_kill_target_api_exists() {
        let mut engine = Engine::new(64, 1);
        engine.kill_target();
    }

    #[test]
    fn test_target_state_api_exists() {
        let engine = Engine::new(64, 1);
        assert_eq!(engine.target_pid(), 0);
        assert!(!engine.target_running());
    }
}
