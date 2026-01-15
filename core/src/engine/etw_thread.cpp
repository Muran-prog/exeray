/// @file engine/etw_thread.cpp
/// @brief Private methods: process, etw_thread_func.

#include "exeray/engine.hpp"
#include "exeray/etw/session.hpp"

#include <chrono>
#include <thread>

namespace exeray {

void Engine::process() {
    for (int i = 0; i <= 100; ++i) {
        progress_.store(static_cast<float>(i) / 100.0f, std::memory_order_relaxed);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    generation_.fetch_add(1, std::memory_order_release);
    flags_.store(StatusFlags::COMPLETE | StatusFlags::READY, std::memory_order_release);
}

void Engine::etw_thread_func() {
#ifdef _WIN32
    if (etw_session_) {
        // ProcessTrace blocks until session is stopped
        etw::start_trace_processing(etw_session_->trace_handle());
    }
#endif
}

}  // namespace exeray
