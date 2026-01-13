use exeray_ffi::{Engine, ViewState};

pub struct App {
    engine: Engine,
    state: ViewState,
}

impl App {
    pub fn new(arena_mb: usize, threads: usize) -> Self {
        Self {
            engine: Engine::new(arena_mb, threads),
            state: ViewState {
                generation: 0,
                timestamp_ns: 0,
                flags: 0,
                progress: 0.0,
            },
        }
    }

    pub fn start(&mut self) {
        if self.engine.idle() || self.state.is_complete() {
            self.engine.submit();
        }
    }

    pub fn tick(&mut self) {
        self.state = self.engine.poll();
    }

    pub fn state(&self) -> &ViewState {
        &self.state
    }

    pub fn threads(&self) -> usize {
        self.engine.threads()
    }
}
