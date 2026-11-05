#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include "noescape/core/types.hpp"

namespace noescape::memory {

struct HookInfo {
    std::string function_name;
    uintptr_t function_address{0};
    std::string hook_type;
    uintptr_t target_destination{0};
    std::vector<uint8_t> patched_bytes;
};

class Unhooker {
public:
    static Unhooker& Instance();

    // Check a specific function address for known inline hook signatures
    std::optional<HookInfo> InspectFunction(const char* name, void* function_ptr);

    // Checks critical system APIs for inline hooks and automatically attempts restoration
    std::vector<core::DetectionEvent> AuditSystemHooks();

    // Attempts to remove the hook by restoring original instructions
    bool RestoreHook(const HookInfo& hook, const uint8_t* original_bytes, size_t length);

    // Automatically inspects the on-disk clean binary to retrieve original instructions and neutralize the hook
    bool AutoRestoreHook(const HookInfo& hook);

private:
    Unhooker() = default;
};

} // namespace noescape::memory
