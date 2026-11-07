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
    PHANTOM_ENTITY_TARGETED,
    THREAD_PROVENANCE_ANOMALY,
    MODULE_PROVENANCE_ANOMALY,
    IAT_GOT_HOOK_DETECTED,
    KINEMATICS_SYNTHETIC_INPUT,
    KINEMATICS_TRIGGERBOT,
    KINEMATICS_RECOIL_AUTOMATION,
    SERVER_ESP_VIOLATION
};

enum class DetectionCategory : uint32_t {
    UNKNOWN = 0,
    MEMORY_INTEGRITY,
    MODULE_PROVENANCE,
    THREAD_PROVENANCE,
    API_HOOK,
    PROCESS_HANDLE,
    OVERLAY_RENDERING,
    BEHAVIORAL_KINEMATICS,
    PHANTOM_ESP,
    HARDWARE_DMA,
    ENVIRONMENT_DEBUG,
    TIMING_HEARTBEAT,
    NETWORK_ATTESTATION
};

enum class ConfidenceLevel : uint32_t {
    OBSERVATION = 0,
    SUSPICION = 1,
    CORROBORATED_ANOMALY = 2,
    HIGH_CONFIDENCE_VIOLATION = 3,
    INDEPENDENTLY_VERIFIED = 4,
    // Convenient aliases
    LOW = SUSPICION,
    MEDIUM = CORROBORATED_ANOMALY,
    HIGH = HIGH_CONFIDENCE_VIOLATION,
    CONFIRMED = HIGH_CONFIDENCE_VIOLATION
};

enum class EvidenceState : uint32_t {
    OBSERVED = 0,
    SUSPICIOUS = 1,
    CORROBORATED = 2,
    SERVER_VERIFIED = 3,
    HIGH_CONFIDENCE = 4,
    DISPUTED = 5,
    EXPIRED = 6
};

enum class ConfigurationProfile : uint32_t {
    DEVELOPMENT = 0,
    TESTING = 1,
    SHADOW_PRODUCTION = 2,
    PRODUCTION = 3,
    OFFLINE_DIAGNOSTICS = 4
};

enum class EnforcementMode : uint32_t {
    REPORT_ONLY = 0,
    SHADOW = 1,
    MATCH_RESTRICTION = 2,
    SERVER_SESSION_REJECT = 3,
    ENFORCE = 4
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
    std::string component{};
    std::string details{};
    uint64_t timestamp{0};
    uint32_t threat_score{0};

    // Extended structured forensic metadata (Release 1.3)
    uint64_t event_id{0};
    DetectionCategory category{DetectionCategory::UNKNOWN};
    ConfidenceLevel confidence{ConfidenceLevel::OBSERVATION};
    std::string platform{
#if defined(_WIN32)
        "Windows"
#else
        "Linux"
#endif
    };
    std::string evidence_source{};
    std::string evidence_hash{};
    uint64_t first_seen_timestamp{0};
    uint64_t last_seen_timestamp{0};
    uint32_t occurrence_count{1};
    uint32_t corroborating_sources{1};
    bool server_verified{false};
    EvidenceState evidence_state{EvidenceState::OBSERVED};
    std::string session_id{"default_session"};
    std::string match_id{"default_match"};
    std::string root_cause_id{};
    uint64_t expiration_timestamp{0};
    std::string detection_version{"7.0.13"};
    std::vector<uint64_t> related_event_ids{};

    DetectionEvent() = default;

    DetectionEvent(
        DetectionType t,
        Severity s,
        std::string comp,
        std::string det,
        uint64_t ts = 0,
        uint32_t score = 0,
        DetectionCategory cat = DetectionCategory::UNKNOWN,
        ConfidenceLevel conf = ConfidenceLevel::OBSERVATION
    ) : type(t), severity(s), component(std::move(comp)), details(std::move(det)),
        timestamp(ts), threat_score(score), category(cat), confidence(conf),
        first_seen_timestamp(ts), last_seen_timestamp(ts) {}

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
            case DetectionType::THREAD_PROVENANCE_ANOMALY: return "THREAD_PROVENANCE_ANOMALY";
            case DetectionType::MODULE_PROVENANCE_ANOMALY: return "MODULE_PROVENANCE_ANOMALY";
            case DetectionType::IAT_GOT_HOOK_DETECTED: return "IAT_GOT_HOOK_DETECTED";
            case DetectionType::KINEMATICS_SYNTHETIC_INPUT: return "KINEMATICS_SYNTHETIC_INPUT";
            case DetectionType::KINEMATICS_TRIGGERBOT: return "KINEMATICS_TRIGGERBOT";
            case DetectionType::KINEMATICS_RECOIL_AUTOMATION: return "KINEMATICS_RECOIL_AUTOMATION";
            case DetectionType::SERVER_ESP_VIOLATION: return "SERVER_ESP_VIOLATION";
            default: return "UNKNOWN";
        }
    }

    static DetectionCategory CategoryFromType(DetectionType t) {
        switch (t) {
            case DetectionType::SELF_INTEGRITY_VIOLATION:
            case DetectionType::UNBACKED_EXECUTABLE_MEMORY:
            case DetectionType::MEMORY_SIGNATURE_MATCH:
            case DetectionType::CANARY_TAMPERED:
                return DetectionCategory::MEMORY_INTEGRITY;
            case DetectionType::MODULE_PROVENANCE_ANOMALY:
                return DetectionCategory::MODULE_PROVENANCE;
            case DetectionType::THREAD_PROVENANCE_ANOMALY:
                return DetectionCategory::THREAD_PROVENANCE;
            case DetectionType::INLINE_HOOK_DETECTED:
            case DetectionType::IAT_GOT_HOOK_DETECTED:
                return DetectionCategory::API_HOOK;
            case DetectionType::SUSPICIOUS_PROCESS_DETECTED:
            case DetectionType::FORENSICS_ARTIFACT_DETECTED:
                return DetectionCategory::PROCESS_HANDLE;
            case DetectionType::OVERLAY_HIJACK_DETECTED:
            case DetectionType::RENDERING_HOOK_DETECTED:
                return DetectionCategory::OVERLAY_RENDERING;
            case DetectionType::KINEMATICS_AIMBOT_SNAP:
            case DetectionType::KINEMATICS_PERFECT_LINEARITY:
            case DetectionType::KINEMATICS_ARTIFICIAL_SMOOTHING:
            case DetectionType::KINEMATICS_SYNTHETIC_INPUT:
            case DetectionType::KINEMATICS_TRIGGERBOT:
            case DetectionType::KINEMATICS_RECOIL_AUTOMATION:
                return DetectionCategory::BEHAVIORAL_KINEMATICS;
            case DetectionType::PHANTOM_ENTITY_TARGETED:
            case DetectionType::SERVER_ESP_VIOLATION:
                return DetectionCategory::PHANTOM_ESP;
            case DetectionType::DMA_LATENCY_JITTER_ANOMALY:
            case DetectionType::DMA_PCIE_LEECH_DEVICE:
                return DetectionCategory::HARDWARE_DMA;
            case DetectionType::ANTI_DEBUG_TRACER:
            case DetectionType::ANTI_DEBUG_HARDWARE_BP:
            case DetectionType::ANTI_DEBUG_TOOL:
            case DetectionType::ENVIRONMENT_TAMPERING:
                return DetectionCategory::ENVIRONMENT_DEBUG;
            case DetectionType::SPEEDHACK_TIMING_DISCREPANCY:
            case DetectionType::HEARTBEAT_TAMPERING:
                return DetectionCategory::TIMING_HEARTBEAT;
            default:
                return DetectionCategory::UNKNOWN;
        }
    }

    static const char* CategoryToString(DetectionCategory c) {
        switch (c) {
            case DetectionCategory::MEMORY_INTEGRITY: return "MEMORY_INTEGRITY";
            case DetectionCategory::MODULE_PROVENANCE: return "MODULE_PROVENANCE";
            case DetectionCategory::THREAD_PROVENANCE: return "THREAD_PROVENANCE";
            case DetectionCategory::API_HOOK: return "API_HOOK";
            case DetectionCategory::PROCESS_HANDLE: return "PROCESS_HANDLE";
            case DetectionCategory::OVERLAY_RENDERING: return "OVERLAY_RENDERING";
            case DetectionCategory::BEHAVIORAL_KINEMATICS: return "BEHAVIORAL_KINEMATICS";
            case DetectionCategory::PHANTOM_ESP: return "PHANTOM_ESP";
            case DetectionCategory::HARDWARE_DMA: return "HARDWARE_DMA";
            case DetectionCategory::ENVIRONMENT_DEBUG: return "ENVIRONMENT_DEBUG";
            case DetectionCategory::TIMING_HEARTBEAT: return "TIMING_HEARTBEAT";
            case DetectionCategory::NETWORK_ATTESTATION: return "NETWORK_ATTESTATION";
            default: return "UNKNOWN";
        }
    }

    static const char* ConfidenceToString(ConfidenceLevel c) {
        switch (c) {
            case ConfidenceLevel::OBSERVATION: return "OBSERVATION";
            case ConfidenceLevel::SUSPICION: return "SUSPICION";
            case ConfidenceLevel::CORROBORATED_ANOMALY: return "CORROBORATED_ANOMALY";
            case ConfidenceLevel::HIGH_CONFIDENCE_VIOLATION: return "HIGH_CONFIDENCE_VIOLATION";
            case ConfidenceLevel::INDEPENDENTLY_VERIFIED: return "INDEPENDENTLY_VERIFIED";
            default: return "OBSERVATION";
        }
    }

    static const char* EnforcementModeToString(EnforcementMode m) {
        switch (m) {
            case EnforcementMode::REPORT_ONLY: return "REPORT_ONLY";
            case EnforcementMode::SHADOW: return "SHADOW";
            case EnforcementMode::MATCH_RESTRICTION: return "MATCH_RESTRICTION";
            case EnforcementMode::SERVER_SESSION_REJECT: return "SERVER_SESSION_REJECT";
            case EnforcementMode::ENFORCE: return "ENFORCE";
            default: return "ENFORCE";
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

    static const char* EvidenceStateToString(EvidenceState s) {
        switch (s) {
            case EvidenceState::OBSERVED: return "OBSERVED";
            case EvidenceState::SUSPICIOUS: return "SUSPICIOUS";
            case EvidenceState::CORROBORATED: return "CORROBORATED";
            case EvidenceState::SERVER_VERIFIED: return "SERVER_VERIFIED";
            case EvidenceState::HIGH_CONFIDENCE: return "HIGH_CONFIDENCE";
            case EvidenceState::DISPUTED: return "DISPUTED";
            case EvidenceState::EXPIRED: return "EXPIRED";
            default: return "OBSERVED";
        }
    }
};

struct EngineConfig {
    ConfigurationProfile profile{ConfigurationProfile::PRODUCTION};
    std::string panelUrl{""};
    std::string secretKey{""};
    // Optional SHA-256 (hex) of the panel's TLS SubjectPublicKeyInfo. When set, https:// panel
    // connections succeed only if the server presents exactly this key.
    std::string panelPinSha256{""};
    // Optional asymmetric server verification key (Ed25519 / P-256 / public verification key).
    std::string serverPublicKey{""};
    std::string keyId{"default-v1"};
    std::string clientBuildVersion{"7.0.13"};
    // Host embeds a JIT (LuaJIT, V8/CEF, Mono, ...): anonymous executable memory is expected.
    bool hostUsesJit{false};
    std::string blackboxDumpDirectory{""};
    bool enforceBanOnViolation{false};
    EnforcementMode enforcementMode{EnforcementMode::SERVER_SESSION_REJECT};
    bool requireMultiSignalCorroboration{true};
    uint32_t banScoreThreshold{100};
    uint64_t memoryScanBudgetMs{25};
    bool enableAdaptiveScanning{true};
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

    static EngineConfig DevelopmentProfile() {
        EngineConfig cfg;
        cfg.profile = ConfigurationProfile::DEVELOPMENT;
        cfg.enforcementMode = EnforcementMode::REPORT_ONLY;
        cfg.enforceBanOnViolation = false;
        cfg.terminateProcessOnBan = false;
        cfg.showBanUi = false;
        cfg.requireMultiSignalCorroboration = true;
        cfg.enableAntiDebug = false;
        cfg.enableHeartbeat = false;
        cfg.verifyPanelBan = false;
        cfg.secretKey = "";
        cfg.panelUrl = "";
        return cfg;
    }

    static EngineConfig TestingProfile() {
        EngineConfig cfg;
        cfg.profile = ConfigurationProfile::TESTING;
        cfg.enforcementMode = EnforcementMode::ENFORCE;
        cfg.enforceBanOnViolation = true;
        cfg.terminateProcessOnBan = false;
        cfg.showBanUi = false;
        cfg.banScoreThreshold = 100;
        cfg.requireMultiSignalCorroboration = false;
        cfg.enableAntiDebug = true;
        cfg.enableHeartbeat = false;
        cfg.verifyPanelBan = false;
        cfg.blackboxDumpDirectory = "/tmp";
        cfg.secretKey = "NoEscape_Test_Key";
        cfg.panelUrl = "";
        return cfg;
    }

    static EngineConfig ShadowProductionProfile() {
        EngineConfig cfg;
        cfg.profile = ConfigurationProfile::SHADOW_PRODUCTION;
        cfg.enforcementMode = EnforcementMode::SHADOW;
        cfg.enforceBanOnViolation = false;
        cfg.terminateProcessOnBan = false;
        cfg.showBanUi = false;
        cfg.requireMultiSignalCorroboration = true;
        cfg.enableHeartbeat = true;
        cfg.verifyPanelBan = false;
        cfg.secretKey = "";
        cfg.panelUrl = "";
        return cfg;
    }

    static EngineConfig ProductionProfile() {
        EngineConfig cfg;
        cfg.profile = ConfigurationProfile::PRODUCTION;
        cfg.enforcementMode = EnforcementMode::SERVER_SESSION_REJECT;
        cfg.enforceBanOnViolation = false;
        cfg.terminateProcessOnBan = false;
        cfg.showBanUi = false;
        cfg.requireMultiSignalCorroboration = true;
        cfg.enableHeartbeat = true;
        cfg.verifyPanelBan = true;
        cfg.secretKey = "";
        cfg.panelUrl = "";
        return cfg;
    }

    static EngineConfig OfflineDiagnosticsProfile() {
        EngineConfig cfg;
        cfg.profile = ConfigurationProfile::OFFLINE_DIAGNOSTICS;
        cfg.enforcementMode = EnforcementMode::REPORT_ONLY;
        cfg.enforceBanOnViolation = false;
        cfg.terminateProcessOnBan = false;
        cfg.showBanUi = false;
        cfg.enableHeartbeat = false;
        cfg.verifyPanelBan = false;
        cfg.requireMultiSignalCorroboration = true;
        cfg.secretKey = "";
        cfg.panelUrl = "";
        return cfg;
    }

    static EngineConfig FromProfile(ConfigurationProfile p) {
        switch (p) {
            case ConfigurationProfile::DEVELOPMENT: return DevelopmentProfile();
            case ConfigurationProfile::TESTING: return TestingProfile();
            case ConfigurationProfile::SHADOW_PRODUCTION: return ShadowProductionProfile();
            case ConfigurationProfile::PRODUCTION: return ProductionProfile();
            case ConfigurationProfile::OFFLINE_DIAGNOSTICS: return OfflineDiagnosticsProfile();
            default: return DevelopmentProfile();
        }
    }
};

} // namespace noescape::core
