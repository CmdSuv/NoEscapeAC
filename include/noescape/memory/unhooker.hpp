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

enum class UnhookRepairPolicy : uint8_t {
    DETECT_ONLY = 0,
    REPAIR_CONTROLLED_ONLY = 1,
    REPAIR_ALL = 2
};

class Unhooker {
public:
    static Unhooker& Instance();

    // Check a specific function address for known inline hook signatures
    std::optional<HookInfo> InspectFunction(const char* name, void* function_ptr);

    // Checks critical system APIs for inline hooks and automatically attempts restoration per policy
    std::vector<core::DetectionEvent> AuditSystemHooks();

    // Audits ELF GOT/PLT and Windows PE IAT/EAT tables for pointer redirection to unbacked/unexpected memory
    std::vector<core::DetectionEvent> AuditImportExportTables();

    // Inspects a single IAT/GOT/EAT pointer entry for module provenance & executable backing
    std::optional<core::DetectionEvent> InspectTableEntry(
        const std::string& table_type,
        const std::string& symbol_name,
        uintptr_t slot_address,
        uintptr_t resolved_target
    );

    // Attempts to remove the hook by restoring original instructions
    bool RestoreHook(const HookInfo& hook, const uint8_t* original_bytes, size_t length);

    // Automatically inspects the on-disk clean binary to retrieve original instructions and neutralize the hook
    bool AutoRestoreHook(const HookInfo& hook);

    // Self-repair policy configuration
    void SetRepairPolicy(UnhookRepairPolicy policy) { repair_policy_ = policy; }
    UnhookRepairPolicy GetRepairPolicy() const { return repair_policy_; }

private:
    Unhooker() = default;
    UnhookRepairPolicy repair_policy_{UnhookRepairPolicy::REPAIR_CONTROLLED_ONLY};
};

} // namespace noescape::memory
