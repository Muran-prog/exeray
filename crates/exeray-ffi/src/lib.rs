#[cxx::bridge(namespace = "exeray")]
mod ffi {
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
    }
}

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

pub struct Engine(cxx::UniquePtr<ffi::Handle>);

impl Engine {
    pub fn new(arena_mb: usize, threads: usize) -> Self {
        Self(ffi::create(arena_mb, threads))
    }

    pub fn submit(&mut self) {
        self.0.pin_mut().submit();
    }

    pub fn poll(&self) -> ViewState {
        ViewState {
            generation: self.0.generation(),
            timestamp_ns: self.0.timestamp_ns(),
            flags: self.0.flags(),
            progress: self.0.progress(),
        }
    }

    pub fn idle(&self) -> bool {
        self.0.idle()
    }

    pub fn threads(&self) -> usize {
        self.0.threads()
    }
}
