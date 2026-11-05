#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>

namespace noescape::core {

enum class DetectionType : uint32_t {
    UNKNOWN = 0,
    ANTI_DEBUG_TRACER,
    ANTI_DEBUG_HARDWARE_BP,
    ANTI_DEBUG_TOOL,
    SELF_INTEGRITY_VIOLATION,
    SPEEDHACK_TIMING_DISCREPANCY,
    UNBACKED_EXECUTABLE_MEMORY,
    MEMORY_SIGNATURE_MATCH,
    INLINE_HOOK_DETECTED,
    ENVIRONMENT_TAMPERING,
    FORENSICS_ARTIFACT_DETECTED,
    SUSPICIOUS_PROCESS_DETECTED,
    DMA_LATENCY_JITTER_ANOMALY,
    DMA_PCIE_LEECH_DEVICE,
    KINEMATICS_AIMBOT_SNAP,
    KINEMATICS_PERFECT_LINEARITY,
    KINEMATICS_ARTIFICIAL_SMOOTHING,
    HEARTBEAT_TAMPERING,
    OVERLAY_HIJACK_DETECTED,
    RENDERING_HOOK_DETECTED,
    CANARY_TAMPERED,
    PHANTOM_ENTITY_TARGETED
};

enum class Severity : uint32_t {
    INFO = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4,
    FATAL_BAN = 5
};

struct DetectionEvent {
    DetectionType type{DetectionType::UNKNOWN};
    Severity severity{Severity::INFO};
    std::string component;
    std::string details;
    uint64_t timestamp{0};
    uint32_t threat_score{0};

    static const char* TypeToString(DetectionType t) {
        switch (t) {
            case DetectionType::ANTI_DEBUG_TRACER: return "ANTI_DEBUG_TRACER";
            case DetectionType::ANTI_DEBUG_HARDWARE_BP: return "ANTI_DEBUG_HARDWARE_BP";
            case DetectionType::ANTI_DEBUG_TOOL: return "ANTI_DEBUG_TOOL";
            case DetectionType::SELF_INTEGRITY_VIOLATION: return "SELF_INTEGRITY_VIOLATION";
            case DetectionType::SPEEDHACK_TIMING_DISCREPANCY: return "SPEEDHACK_TIMING_DISCREPANCY";
            case DetectionType::UNBACKED_EXECUTABLE_MEMORY: return "UNBACKED_EXECUTABLE_MEMORY";
            case DetectionType::MEMORY_SIGNATURE_MATCH: return "MEMORY_SIGNATURE_MATCH";
            case DetectionType::INLINE_HOOK_DETECTED: return "INLINE_HOOK_DETECTED";
            case DetectionType::ENVIRONMENT_TAMPERING: return "ENVIRONMENT_TAMPERING";
            case DetectionType::FORENSICS_ARTIFACT_DETECTED: return "FORENSICS_ARTIFACT_DETECTED";
            case DetectionType::SUSPICIOUS_PROCESS_DETECTED: return "SUSPICIOUS_PROCESS_DETECTED";
            case DetectionType::DMA_LATENCY_JITTER_ANOMALY: return "DMA_LATENCY_JITTER_ANOMALY";
            case DetectionType::DMA_PCIE_LEECH_DEVICE: return "DMA_PCIE_LEECH_DEVICE";
            case DetectionType::KINEMATICS_AIMBOT_SNAP: return "KINEMATICS_AIMBOT_SNAP";
            case DetectionType::KINEMATICS_PERFECT_LINEARITY: return "KINEMATICS_PERFECT_LINEARITY";
            case DetectionType::KINEMATICS_ARTIFICIAL_SMOOTHING: return "KINEMATICS_ARTIFICIAL_SMOOTHING";
            case DetectionType::HEARTBEAT_TAMPERING: return "HEARTBEAT_TAMPERING";
            case DetectionType::OVERLAY_HIJACK_DETECTED: return "OVERLAY_HIJACK_DETECTED";
            case DetectionType::RENDERING_HOOK_DETECTED: return "RENDERING_HOOK_DETECTED";
            case DetectionType::CANARY_TAMPERED: return "CANARY_TAMPERED";
            case DetectionType::PHANTOM_ENTITY_TARGETED: return "PHANTOM_ENTITY_TARGETED";
            default: return "UNKNOWN";
        }
    }

    static const char* SeverityToString(Severity s) {
        switch (s) {
            case Severity::INFO: return "INFO";
            case Severity::LOW: return "LOW";
            case Severity::MEDIUM: return "MEDIUM";
            case Severity::HIGH: return "HIGH";
            case Severity::CRITICAL: return "CRITICAL";
            case Severity::FATAL_BAN: return "FATAL_BAN";
            default: return "UNKNOWN";
        }
    }
};

struct EngineConfig {
    std::string panelUrl{"http://127.0.0.1:8080/api/ac"};
    std::string secretKey{"NoEscape_Secret_Key_v2.0"};
    std::string blackboxDumpDirectory{""};
    bool enforceBanOnViolation{true};
    uint32_t banScoreThreshold{100};
    bool enableAntiDebug{true};
    bool enableIntegrityScan{true};
    bool enableSpeedhackDetection{true};
    bool enableMemoryScan{true};
    bool enableUnhooker{true};
    bool enableForensics{true};
    bool enableDmaDetection{true};
    bool enableKinematics{true};
    bool enableOverlayDetection{true};
    bool enableBlackboxDump{true};
    bool enableHeartbeat{true};
    // Periodically verify the global ban list. Unreachable/invalid panel replies raise a
    // score (never an instant ban) so offline players are not punished.
    bool verifyPanelBan{false};
    bool terminateProcessOnBan{false};
    bool showBanUi{false};
    std::string banUiExecutable{""};

    std::vector<std::string> blacklistedProcesses{
        "x64dbg", "x32dbg", "ollydbg", "ida64", "ida", "ghidra",
        "cheatengine", "cheatengine-x86_64", "processhacker", "wireshark",
        "ksdumper", "scyllascan", "vape", "liquidbounce", "meteor",
        "wurst", "aristois", "killaura", "aimbot", "radare2", "gdb", "lldb"
    };

    std::vector<std::string> blacklistedArtifacts{
        "cheatengine", "libmemhack.so", "inject.so", "aimbot.so",
        "hook.so", "ksdumper", "dbk64.sys", "winring0", "leechcore",
        "fpga_mem.bin"
    };
};

} // namespace noescape::core
