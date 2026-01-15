/// @file guids.cpp
/// @brief Well-known ETW provider GUID definitions.

#ifdef _WIN32
#include "exeray/etw/providers/guids.hpp"
#else
// For non-Windows, include session.hpp to get GUID struct definition
#include "exeray/etw/session.hpp"
#endif

namespace exeray::etw::providers {

#ifdef _WIN32

// Microsoft-Windows-Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
const GUID KERNEL_PROCESS = {
    0x22FB2CD6, 0x0E7B, 0x422B, {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}
};

// Microsoft-Windows-Kernel-File {EDD08927-9CC4-4E65-B970-C2560FB5C289}
const GUID KERNEL_FILE = {
    0xEDD08927, 0x9CC4, 0x4E65, {0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}
};

// Microsoft-Windows-Kernel-Registry {70EB4F03-C1DE-4F73-A051-33D13D5413BD}
const GUID KERNEL_REGISTRY = {
    0x70EB4F03, 0xC1DE, 0x4F73, {0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD}
};

// Microsoft-Windows-Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88}
const GUID KERNEL_NETWORK = {
    0x7DD42A49, 0x5329, 0x4832, {0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88}
};

// Image Load provider {2CB15D1D-5FC1-11D2-ABE1-00A0C911F518}
const GUID KERNEL_IMAGE = {
    0x2CB15D1D, 0x5FC1, 0x11D2, {0xAB, 0xE1, 0x00, 0xA0, 0xC9, 0x11, 0xF5, 0x18}
};

// Thread events provider {3D6FA8D1-FE05-11D0-9DDA-00C04FD7BA7C}
const GUID KERNEL_THREAD = {
    0x3D6FA8D1, 0xFE05, 0x11D0, {0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C}
};

// Virtual memory events provider {3D6FA8D3-FE05-11D0-9DDA-00C04FD7BA7C}
const GUID KERNEL_MEMORY = {
    0x3D6FA8D3, 0xFE05, 0x11D0, {0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C}
};

// Microsoft-Windows-PowerShell {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
const GUID POWERSHELL = {
    0xA0C1853B, 0x5C40, 0x4B15, {0x87, 0x66, 0x3C, 0xF1, 0xC5, 0x8F, 0x98, 0x5A}
};

// Microsoft-Antimalware-Scan-Interface {2A576B87-09A7-520E-C21A-4942F0271D67}
const GUID AMSI = {
    0x2A576B87, 0x09A7, 0x520E, {0xC2, 0x1A, 0x49, 0x42, 0xF0, 0x27, 0x1D, 0x67}
};

// Microsoft-Windows-DNS-Client {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
const GUID DNS_CLIENT = {
    0x1C95126E, 0x7EEA, 0x49A9, {0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D}
};

// Microsoft-Windows-Security-Auditing {54849625-5478-4994-A5BA-3E3B0328C30D}
const GUID SECURITY_AUDITING = {
    0x54849625, 0x5478, 0x4994, {0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28, 0xC3, 0x0D}
};

// Microsoft-Windows-WMI-Activity {1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}
const GUID WMI_ACTIVITY = {
    0x1418EF04, 0xB0B4, 0x4623, {0xBF, 0x7E, 0xD7, 0x4A, 0xB4, 0x7B, 0xBD, 0xAA}
};

// Microsoft-Windows-DotNETRuntime {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}
const GUID CLR_RUNTIME = {
    0xE13C0D23, 0xCCBC, 0x4E12, {0x93, 0x1B, 0xD9, 0xCC, 0x2E, 0xEE, 0x27, 0xE4}
};

#else  // !_WIN32

// Stub GUIDs for non-Windows platforms
const GUID KERNEL_PROCESS = {0, 0, 0, {0}};
const GUID KERNEL_FILE = {0, 0, 0, {0}};
const GUID KERNEL_REGISTRY = {0, 0, 0, {0}};
const GUID KERNEL_NETWORK = {0, 0, 0, {0}};
const GUID KERNEL_IMAGE = {0, 0, 0, {0}};
const GUID KERNEL_THREAD = {0, 0, 0, {0}};
const GUID KERNEL_MEMORY = {0, 0, 0, {0}};
const GUID POWERSHELL = {0, 0, 0, {0}};
const GUID AMSI = {0, 0, 0, {0}};
const GUID DNS_CLIENT = {0, 0, 0, {0}};
const GUID SECURITY_AUDITING = {0, 0, 0, {0}};
const GUID WMI_ACTIVITY = {0, 0, 0, {0}};
const GUID CLR_RUNTIME = {0, 0, 0, {0}};

#endif  // _WIN32

}  // namespace exeray::etw::providers
