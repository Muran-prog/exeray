/// @file constants.hpp
/// @brief WMI Activity event constants.

#pragma once

#include <cstdint>

namespace exeray::etw::wmi {

/// WMI Activity event IDs from Microsoft-Windows-WMI-Activity provider.
enum class WmiEventId : uint16_t {
    NamespaceConnect = 5,           ///< IWbemLocator::ConnectServer
    ExecQuery = 11,                 ///< IWbemServices::ExecQuery
    ExecNotificationQuery = 22,     ///< IWbemServices::ExecNotificationQuery
    ExecMethod = 23                 ///< IWbemServices::ExecMethod
};

}  // namespace exeray::etw::wmi
