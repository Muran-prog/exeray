/// @file engine/control.cpp
/// @brief Process control: freeze, unfreeze, kill, target_pid.

#include "exeray/engine.hpp"

namespace exeray {

void Engine::freeze_target() {
    if (target_ && target_->is_running()) {
        target_->suspend();
    }
}

void Engine::unfreeze_target() {
    if (target_ && target_->is_running()) {
        target_->resume();
    }
}

void Engine::kill_target() {
    if (target_) {
        target_->terminate();
    }
}

uint32_t Engine::target_pid() const noexcept {
    return target_pid_.load(std::memory_order_acquire);
}

}  // namespace exeray
