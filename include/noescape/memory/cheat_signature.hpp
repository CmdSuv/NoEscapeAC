#pragma once

#include <string>
#include <string_view>
#include <cstdint>
#include "noescape/core/types.hpp"
#include "noescape/memory/pattern_scanner.hpp"

namespace noescape::memory {

enum class SignatureCategory : uint32_t {
    GENERIC = 0,
    HOOK_FRAMEWORK,
    INJECTOR_STUB,
    DMA_TOOL,
    DEBUGGER_INTERFACE,
    SHELLCODE_PROLOGUE,
    OVERLAY_HOOK,
    PACKER_PROTECTOR,
    SPEEDHACK_WRAPPER
};

enum class MemoryTargetRule : uint32_t {
    UNBACKED_ONLY = 0,    // Only anonymous / unbacked executable memory
    ALL_EXECUTABLE,       // All executable memory (file-backed and unbacked)
    ANONYMOUS_DATA,       // Anonymous / unbacked readable non-executable memory
    ANY_ANONYMOUS,        // Any anonymous / unbacked memory (executable or data)
    ALL_REGIONS           // All readable memory
};

class CheatSignature : public Pattern {
public:
    CheatSignature() = default;

    CheatSignature(
        std::string_view ida_pattern,
        std::string name,
        SignatureCategory category = SignatureCategory::GENERIC,
        uint32_t threat_score = 100,
        core::Severity severity = core::Severity::FATAL_BAN,
        MemoryTargetRule target_rule = MemoryTargetRule::UNBACKED_ONLY,
        std::string description = ""
    ) : Pattern(ida_pattern, std::move(name)),
        category_(category),
        threat_score_(threat_score),
        severity_(severity),
        target_rule_(target_rule),
        description_(std::move(description)) {}

    CheatSignature(
        const uint8_t* bytes,
        const char* mask,
        std::string name,
        SignatureCategory category = SignatureCategory::GENERIC,
        uint32_t threat_score = 100,
        core::Severity severity = core::Severity::FATAL_BAN,
        MemoryTargetRule target_rule = MemoryTargetRule::UNBACKED_ONLY,
        std::string description = ""
    ) : Pattern(bytes, mask, std::move(name)),
        category_(category),
        threat_score_(threat_score),
        severity_(severity),
        target_rule_(target_rule),
        description_(std::move(description)) {}

    CheatSignature(
        const Pattern& pattern,
        SignatureCategory category = SignatureCategory::GENERIC,
        uint32_t threat_score = 100,
        core::Severity severity = core::Severity::FATAL_BAN,
        MemoryTargetRule target_rule = MemoryTargetRule::UNBACKED_ONLY,
        std::string description = ""
    ) : Pattern(pattern),
        category_(category),
        threat_score_(threat_score),
        severity_(severity),
        target_rule_(target_rule),
        description_(std::move(description)) {}

    SignatureCategory GetCategory() const { return category_; }
    uint32_t GetThreatScore() const { return threat_score_; }
    core::Severity GetSeverity() const { return severity_; }
    MemoryTargetRule GetTargetRule() const { return target_rule_; }
    const std::string& GetDescription() const { return description_; }

    void SetCategory(SignatureCategory cat) { category_ = cat; }
    void SetThreatScore(uint32_t score) { threat_score_ = score; }
    void SetSeverity(core::Severity sev) { severity_ = sev; }
    void SetTargetRule(MemoryTargetRule rule) { target_rule_ = rule; }
    void SetDescription(std::string desc) { description_ = std::move(desc); }

    static const char* CategoryToString(SignatureCategory cat);
    static const char* RuleToString(MemoryTargetRule rule);

    static bool IsTargetMatched(MemoryTargetRule rule, bool isGenuineFile, bool isExecutable, bool isReadable);

private:
    SignatureCategory category_{SignatureCategory::GENERIC};
    uint32_t threat_score_{100};
    core::Severity severity_{core::Severity::FATAL_BAN};
    MemoryTargetRule target_rule_{MemoryTargetRule::UNBACKED_ONLY};
    std::string description_;
};

} // namespace noescape::memory
