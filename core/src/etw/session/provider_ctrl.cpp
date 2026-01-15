/// @file provider_ctrl.cpp
/// @brief Session provider enable/disable implementations.

#ifdef _WIN32

#include "exeray/etw/session.hpp"
#include "helpers.hpp"

namespace exeray::etw {

bool Session::enable_provider(const GUID& provider_guid, uint8_t level,
                               uint64_t keywords) {
    ULONG status = EnableTraceEx2(
        session_handle_,
        &provider_guid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        level,
        keywords,
        0,  // MatchAllKeyword
        0,  // Timeout (async)
        nullptr  // EnableParameters
    );

    if (status != ERROR_SUCCESS) {
        session::log_error(L"EnableTraceEx2", status);
        return false;
    }
    return true;
}

void Session::disable_provider(const GUID& provider_guid) {
    ULONG status = EnableTraceEx2(
        session_handle_,
        &provider_guid,
        EVENT_CONTROL_CODE_DISABLE_PROVIDER,
        0,
        0,
        0,
        0,
        nullptr
    );

    if (status != ERROR_SUCCESS) {
        session::log_error(L"DisableProvider", status);
    }
}

}  // namespace exeray::etw

#endif  // _WIN32
