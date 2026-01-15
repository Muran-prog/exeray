/// @file etw/providers/mapping.cpp
/// @brief Provider name to GUID mapping implementation.

#include "exeray/etw/provider_mapping.hpp"

#ifdef _WIN32
#include "exeray/etw/providers/guids.hpp"

namespace exeray::etw {

std::optional<GUID> get_provider_guid(std::string_view name) {
    // Static registry of provider name → GUID mappings
    if (name == "Process") return providers::KERNEL_PROCESS;
    if (name == "File") return providers::KERNEL_FILE;
    if (name == "Registry") return providers::KERNEL_REGISTRY;
    if (name == "Network") return providers::KERNEL_NETWORK;
    if (name == "Image") return providers::KERNEL_IMAGE;
    if (name == "Thread") return providers::KERNEL_THREAD;
    if (name == "Memory") return providers::KERNEL_MEMORY;
    if (name == "PowerShell") return providers::POWERSHELL;
    if (name == "AMSI") return providers::AMSI;
    if (name == "DNS") return providers::DNS_CLIENT;
    if (name == "WMI") return providers::WMI_ACTIVITY;
    if (name == "CLR") return providers::CLR_RUNTIME;
    if (name == "Security") return providers::SECURITY_AUDITING;
    return std::nullopt;
}

}  // namespace exeray::etw
#endif
