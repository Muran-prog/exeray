/// @file engine/provider_mapping.cpp
/// @brief Provider name to GUID mapping utility.

#include "provider_mapping.hpp"

#ifdef _WIN32
#include "exeray/etw/session.hpp"

namespace exeray::internal {

std::optional<GUID> get_provider_guid(std::string_view name) {
    // Static registry of provider name → GUID mappings
    if (name == "Process") return etw::providers::KERNEL_PROCESS;
    if (name == "File") return etw::providers::KERNEL_FILE;
    if (name == "Registry") return etw::providers::KERNEL_REGISTRY;
    if (name == "Network") return etw::providers::KERNEL_NETWORK;
    if (name == "Image") return etw::providers::KERNEL_IMAGE;
    if (name == "Thread") return etw::providers::KERNEL_THREAD;
    if (name == "Memory") return etw::providers::KERNEL_MEMORY;
    if (name == "PowerShell") return etw::providers::POWERSHELL;
    if (name == "AMSI") return etw::providers::AMSI;
    if (name == "DNS") return etw::providers::DNS_CLIENT;
    if (name == "WMI") return etw::providers::WMI_ACTIVITY;
    if (name == "CLR") return etw::providers::CLR_RUNTIME;
    if (name == "Security") return etw::providers::SECURITY_AUDITING;
    return std::nullopt;
}

}  // namespace exeray::internal
#endif
