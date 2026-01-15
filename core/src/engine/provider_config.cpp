/// @file engine/provider_config.cpp
/// @brief Provider configuration API: enable_provider, disable_provider, is_provider_enabled.

#include "exeray/engine.hpp"
#include "exeray/logging.hpp"

namespace exeray {

void Engine::enable_provider(std::string_view name) {
    std::lock_guard lock(providers_mutex_);
    std::string key(name);
    auto it = config_.providers.find(key);
    if (it != config_.providers.end()) {
        it->second.enabled = true;
        EXERAY_DEBUG("Provider {} enabled (takes effect on next start_monitoring)", name);
    } else {
        EXERAY_WARN("enable_provider: Unknown provider '{}'", name);
    }
}

void Engine::disable_provider(std::string_view name) {
    std::lock_guard lock(providers_mutex_);
    std::string key(name);
    auto it = config_.providers.find(key);
    if (it != config_.providers.end()) {
        it->second.enabled = false;
        EXERAY_DEBUG("Provider {} disabled (takes effect on next start_monitoring)", name);
    } else {
        EXERAY_WARN("disable_provider: Unknown provider '{}'", name);
    }
}

bool Engine::is_provider_enabled(std::string_view name) const {
    std::lock_guard lock(providers_mutex_);
    std::string key(name);
    auto it = config_.providers.find(key);
    if (it != config_.providers.end()) {
        return it->second.enabled;
    }
    return false;
}

}  // namespace exeray
