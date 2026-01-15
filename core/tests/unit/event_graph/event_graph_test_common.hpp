#pragma once

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <set>
#include <thread>
#include <vector>

#include "exeray/arena.hpp"
#include "exeray/event/graph.hpp"

namespace exeray::event::test {

// ============================================================================
// Test Fixture
// ============================================================================

class EventGraphTest : public ::testing::Test {
protected:
    static constexpr std::size_t kArenaSize = 64 * 1024 * 1024;  // 64MB
    static constexpr std::size_t kDefaultCapacity = 65536;

    Arena arena_{kArenaSize};
    StringPool strings_{arena_};
    EventGraph graph_{arena_, strings_, kDefaultCapacity};

    // -------------------------------------------------------------------------
    // Helper: Create payloads for each category
    // -------------------------------------------------------------------------

    static EventPayload make_process_payload(uint32_t pid = 1234) {
        EventPayload payload{};
        payload.category = Category::Process;
        payload.process.pid = pid;
        payload.process.parent_pid = 1;
        return payload;
    }

    static EventPayload make_file_payload(StringId path = INVALID_STRING) {
        EventPayload payload{};
        payload.category = Category::FileSystem;
        payload.file.path = path;
        payload.file.size = 1024;
        payload.file.attributes = 0;
        return payload;
    }

    static EventPayload make_registry_payload() {
        EventPayload payload{};
        payload.category = Category::Registry;
        payload.registry.key_path = INVALID_STRING;
        payload.registry.value_name = INVALID_STRING;
        return payload;
    }

    static EventPayload make_network_payload(uint16_t port = 8080) {
        EventPayload payload{};
        payload.category = Category::Network;
        payload.network.local_port = port;
        payload.network.remote_port = 443;
        return payload;
    }

    static EventPayload make_scheduler_payload() {
        EventPayload payload{};
        payload.category = Category::Scheduler;
        return payload;
    }

    static EventPayload make_input_payload() {
        EventPayload payload{};
        payload.category = Category::Input;
        return payload;
    }

    static EventPayload make_image_payload() {
        EventPayload payload{};
        payload.category = Category::Image;
        payload.image.base_address = 0x7FF00000;
        payload.image.size = 0x10000;
        return payload;
    }

    static EventPayload make_thread_payload(uint32_t tid = 5678) {
        EventPayload payload{};
        payload.category = Category::Thread;
        payload.thread.thread_id = tid;
        payload.thread.start_address = 0x400000;
        return payload;
    }

    static EventPayload make_memory_payload() {
        EventPayload payload{};
        payload.category = Category::Memory;
        payload.memory.base_address = 0x1000;
        payload.memory.region_size = 4096;
        return payload;
    }

    static EventPayload make_script_payload() {
        EventPayload payload{};
        payload.category = Category::Script;
        payload.script.script_block = INVALID_STRING;
        return payload;
    }

    static EventPayload make_amsi_payload() {
        EventPayload payload{};
        payload.category = Category::Amsi;
        payload.amsi.content = INVALID_STRING;
        return payload;
    }

    static EventPayload make_dns_payload() {
        EventPayload payload{};
        payload.category = Category::Dns;
        payload.dns.domain = INVALID_STRING;
        return payload;
    }

    static EventPayload make_security_payload() {
        EventPayload payload{};
        payload.category = Category::Security;
        payload.security.target_user = INVALID_STRING;
        return payload;
    }

    static EventPayload make_service_payload() {
        EventPayload payload{};
        payload.category = Category::Service;
        payload.service.service_name = INVALID_STRING;
        return payload;
    }

    static EventPayload make_wmi_payload() {
        EventPayload payload{};
        payload.category = Category::Wmi;
        payload.wmi.query = INVALID_STRING;
        return payload;
    }

    static EventPayload make_clr_payload() {
        EventPayload payload{};
        payload.category = Category::Clr;
        payload.clr.assembly_name = INVALID_STRING;
        return payload;
    }

    EventPayload make_payload_for_category(Category cat) {
        switch (cat) {
            case Category::FileSystem: return make_file_payload();
            case Category::Registry: return make_registry_payload();
            case Category::Network: return make_network_payload();
            case Category::Process: return make_process_payload();
            case Category::Scheduler: return make_scheduler_payload();
            case Category::Input: return make_input_payload();
            case Category::Image: return make_image_payload();
            case Category::Thread: return make_thread_payload();
            case Category::Memory: return make_memory_payload();
            case Category::Script: return make_script_payload();
            case Category::Amsi: return make_amsi_payload();
            case Category::Dns: return make_dns_payload();
            case Category::Security: return make_security_payload();
            case Category::Service: return make_service_payload();
            case Category::Wmi: return make_wmi_payload();
            case Category::Clr: return make_clr_payload();
            case Category::Count: break;
        }
        return make_file_payload();  // Fallback
    }
};

}  // namespace exeray::event::test
