#include "noescape_sdk.h"
#include "noescape/core/engine.hpp"
#include "noescape/overlay/overlay_detector.hpp"
#include "noescape/core/logger.hpp"

#include <memory>
#include <mutex>
#include <atomic>
#include <string>
#include <cmath>

namespace {

std::mutex g_lifecycle_mutex;
std::shared_ptr<noescape::core::AntiCheatEngine> g_engine;
// Shared ownership: callers hold a reference for the duration of a call, so a concurrent
// Shutdown()/Init() can never free the engine under them.
std::mutex g_ptr_mutex;
std::shared_ptr<noescape::core::AntiCheatEngine> g_active_engine;
std::atomic<NoEscapeViolationCallback> g_callback{nullptr};

std::shared_ptr<noescape::core::AntiCheatEngine> ActiveEngine() {
    std::lock_guard<std::mutex> l(g_ptr_mutex);
    return g_active_engine;
}
void SetActiveEngine(std::shared_ptr<noescape::core::AntiCheatEngine> e) {
    std::lock_guard<std::mutex> l(g_ptr_mutex);
    g_active_engine = std::move(e);
}

// Dedicated high-frequency input mutex to guarantee zero-stutter mouse processing
std::mutex g_input_mutex;
std::mutex g_preinit_mutex;
std::string g_panel_pin;
bool g_host_uses_jit = false;
float g_accum_pitch = 0.0f;
float g_accum_yaw = 0.0f;

} // namespace

extern "C" {

NoEscapeConfig NoEscape_GetProfileConfig(NoEscapeProfile profile) {
    NoEscapeConfig cfg{};
    cfg.struct_size = sizeof(NoEscapeConfig);
    cfg.config_version = 2;

    noescape::core::ConfigurationProfile coreProfile;
    switch (profile) {
        case NOESCAPE_PROFILE_DEVELOPMENT: coreProfile = noescape::core::ConfigurationProfile::DEVELOPMENT; break;
        case NOESCAPE_PROFILE_TESTING: coreProfile = noescape::core::ConfigurationProfile::TESTING; break;
        case NOESCAPE_PROFILE_SHADOW_PRODUCTION: coreProfile = noescape::core::ConfigurationProfile::SHADOW_PRODUCTION; break;
        case NOESCAPE_PROFILE_PRODUCTION: coreProfile = noescape::core::ConfigurationProfile::PRODUCTION; break;
        case NOESCAPE_PROFILE_OFFLINE_DIAGNOSTICS: coreProfile = noescape::core::ConfigurationProfile::OFFLINE_DIAGNOSTICS; break;
        default: coreProfile = noescape::core::ConfigurationProfile::DEVELOPMENT; break;
    }

    auto coreCfg = noescape::core::EngineConfig::FromProfile(coreProfile);
    static const std::string s_panel_url = "http://127.0.0.1:8080/api/ac";
    static const std::string s_secret_key = "NoEscape_Secret_Key_v2.0";
    static const std::string s_key_id = "default-v1";
    static const std::string s_client_version = "7.0.13";

    cfg.panel_url = coreCfg.panelUrl.empty() ? nullptr : s_panel_url.c_str();
    cfg.secret_key = coreCfg.secretKey.empty() ? nullptr : s_secret_key.c_str();
    cfg.key_id = s_key_id.c_str();
    cfg.client_build_version = s_client_version.c_str();
    cfg.server_public_key = nullptr;
    cfg.blackbox_dump_dir = coreCfg.blackboxDumpDirectory.empty() ? nullptr : "/tmp";
    cfg.ban_threshold = coreCfg.banScoreThreshold;
    cfg.enforce_ban = coreCfg.enforceBanOnViolation;
    cfg.enforcement_mode = static_cast<int>(coreCfg.enforcementMode);
    cfg.require_multi_signal_corroboration = coreCfg.requireMultiSignalCorroboration;
    cfg.memory_scan_budget_ms = coreCfg.memoryScanBudgetMs;
    cfg.enable_anti_debug = coreCfg.enableAntiDebug;
    cfg.enable_integrity_scan = coreCfg.enableIntegrityScan;
    cfg.enable_speedhack_detection = coreCfg.enableSpeedhackDetection;
    cfg.enable_memory_scan = coreCfg.enableMemoryScan;
    cfg.enable_unhooker = coreCfg.enableUnhooker;
    cfg.enable_forensics = coreCfg.enableForensics;
    cfg.enable_dma_detection = coreCfg.enableDmaDetection;
    cfg.enable_kinematics = coreCfg.enableKinematics;
    cfg.enable_overlay_detection = coreCfg.enableOverlayDetection;
    cfg.enable_blackbox_dump = coreCfg.enableBlackboxDump;
    cfg.enable_heartbeat = coreCfg.enableHeartbeat;
    cfg.terminate_on_ban = coreCfg.terminateProcessOnBan;
    cfg.show_ban_ui = coreCfg.showBanUi;
    cfg.ban_ui_path = nullptr;

    return cfg;
}

NoEscapeConfig NoEscape_GetDefaultConfig(void) {
    NoEscapeConfig cfg{};
    cfg.struct_size = sizeof(NoEscapeConfig);
    cfg.config_version = 2;
    cfg.panel_url = "http://127.0.0.1:8080/api/ac";
    cfg.secret_key = "NoEscape_Secret_Key_v2.0";
    cfg.blackbox_dump_dir = nullptr;
    cfg.ban_threshold = 100;
    cfg.enforce_ban = true;
    cfg.enable_anti_debug = true;
    cfg.enable_integrity_scan = true;
    cfg.enable_speedhack_detection = true;
    cfg.enable_memory_scan = true;
    cfg.enable_unhooker = true;
    cfg.enable_forensics = true;
    cfg.enable_dma_detection = true;
    cfg.enable_kinematics = true;
    cfg.enable_overlay_detection = true;
    cfg.enable_blackbox_dump = true;
    cfg.enable_heartbeat = false;
    cfg.terminate_on_ban = false;
    cfg.show_ban_ui = true;
    cfg.ban_ui_path = nullptr;

    cfg.server_public_key = nullptr;
    cfg.key_id = "default-v1";
    cfg.client_build_version = "7.0.13";
    cfg.enforcement_mode = static_cast<int>(noescape::core::EnforcementMode::ENFORCE);
    cfg.require_multi_signal_corroboration = false;
    cfg.memory_scan_budget_ms = 25;
    return cfg;
}

int NoEscape_Init(const NoEscapeConfig* config) {
    std::lock_guard<std::mutex> lock(g_lifecycle_mutex);

    if (g_engine) {
        SetActiveEngine(nullptr);
        g_engine->Stop();
        g_engine.reset();
    }

    {
        std::lock_guard<std::mutex> inLock(g_input_mutex);
        g_accum_pitch = 0.0f;
        g_accum_yaw = 0.0f;
    }

    noescape::core::EngineConfig engineCfg;
    if (config) {
        if (config->panel_url) engineCfg.panelUrl = config->panel_url;
        if (config->secret_key) engineCfg.secretKey = config->secret_key;
        if (config->blackbox_dump_dir) engineCfg.blackboxDumpDirectory = config->blackbox_dump_dir;
        // A zero threshold (zero-initialised struct) would ban on the very first event
        if (config->ban_threshold > 0) engineCfg.banScoreThreshold = config->ban_threshold;
        engineCfg.enforceBanOnViolation = config->enforce_ban;
        engineCfg.enableAntiDebug = config->enable_anti_debug;
        engineCfg.enableIntegrityScan = config->enable_integrity_scan;
        engineCfg.enableSpeedhackDetection = config->enable_speedhack_detection;
        engineCfg.enableMemoryScan = config->enable_memory_scan;
        engineCfg.enableUnhooker = config->enable_unhooker;
        engineCfg.enableForensics = config->enable_forensics;
        engineCfg.enableDmaDetection = config->enable_dma_detection;
        engineCfg.enableKinematics = config->enable_kinematics;
        engineCfg.enableOverlayDetection = config->enable_overlay_detection;
        engineCfg.enableBlackboxDump = config->enable_blackbox_dump;
        engineCfg.enableHeartbeat = config->enable_heartbeat;
        engineCfg.terminateProcessOnBan = config->terminate_on_ban;
        engineCfg.showBanUi = config->show_ban_ui;
        if (config->ban_ui_path) engineCfg.banUiExecutable = config->ban_ui_path;

        if (config->struct_size >= sizeof(NoEscapeConfig)) {
            if (config->server_public_key) engineCfg.serverPublicKey = config->server_public_key;
            if (config->key_id) engineCfg.keyId = config->key_id;
            if (config->client_build_version) engineCfg.clientBuildVersion = config->client_build_version;
            engineCfg.enforcementMode = static_cast<noescape::core::EnforcementMode>(config->enforcement_mode);
            engineCfg.requireMultiSignalCorroboration = config->require_multi_signal_corroboration;
            if (config->memory_scan_budget_ms > 0) engineCfg.memoryScanBudgetMs = config->memory_scan_budget_ms;
        }
    } else {
        engineCfg.enableHeartbeat = false;
    }

    {
        std::lock_guard<std::mutex> l(g_preinit_mutex);
        engineCfg.panelPinSha256 = g_panel_pin;
        engineCfg.hostUsesJit = g_host_uses_jit;
    }
    g_engine = std::make_shared<noescape::core::AntiCheatEngine>(engineCfg);

    // Wire violation callback to notify the registered C callback for every detection event
    g_engine->SetViolationCallback([](const noescape::core::DetectionEvent& ev) {
        if (auto cb = g_callback.load()) {
            cb(static_cast<int>(ev.type), 
                       static_cast<int>(ev.threat_score), 
                       ev.details.c_str());
        }
    });

    if (!g_engine->Initialize()) {
        g_engine.reset();
        SetActiveEngine(nullptr);
        return -1;
    }

    SetActiveEngine(g_engine);
    return 0;
}

void NoEscape_Shutdown(void) {
    std::lock_guard<std::mutex> lock(g_lifecycle_mutex);
    SetActiveEngine(nullptr);

    if (g_engine) {
        g_engine->Stop();
        g_engine.reset();
    }

    std::lock_guard<std::mutex> inLock(g_input_mutex);
    g_accum_pitch = 0.0f;
    g_accum_yaw = 0.0f;
}

void NoEscape_Start(void) {
    std::lock_guard<std::mutex> lock(g_lifecycle_mutex);
    if (g_engine) {
        g_engine->Start();
    }
}

void NoEscape_Stop(void) {
    std::lock_guard<std::mutex> lock(g_lifecycle_mutex);
    if (g_engine) {
        g_engine->Stop();
    }
}

void NoEscape_Tick(void) {
    auto engine = ActiveEngine();
    if (!engine) return;

    // AuditCycle() runs synchronous module checks and dispatches any detected events
    // through ProcessDetection(), which automatically notifies the registered ViolationCallback.
    engine->AuditCycle();
}

void NoEscape_PushMouseEvent(float delta_yaw, float delta_pitch, uint64_t timestamp_ms) {
    auto engine = ActiveEngine();
    if (!engine) return;

    // Reject non-finite / absurd deltas at the ABI boundary (NaN poisons the accumulators,
    // +/-inf or 1e30 would spin the wrap-around loops below forever)
    if (!std::isfinite(delta_yaw) || !std::isfinite(delta_pitch) ||
        std::fabs(delta_yaw) > 3600.0f || std::fabs(delta_pitch) > 3600.0f) {
        return;
    }

    float p = 0.0f, y = 0.0f;
    {
        std::lock_guard<std::mutex> lock(g_input_mutex);
        g_accum_pitch += delta_pitch;
        if (g_accum_pitch > 89.0f) g_accum_pitch = 89.0f;
        if (g_accum_pitch < -89.0f) g_accum_pitch = -89.0f;

        g_accum_yaw += delta_yaw;
        while (g_accum_yaw > 180.0f) g_accum_yaw -= 360.0f;
        while (g_accum_yaw < -180.0f) g_accum_yaw += 360.0f;
        p = g_accum_pitch;
        y = g_accum_yaw;
    }

    // Pass sample into the engine's internal synchronized input queue without holding SDK mutex
    engine->PushInputSample(p, y, timestamp_ms);
}

void NoEscape_PushRawInput(uint64_t interval_us, int32_t dx, int32_t dy) {
    auto engine = ActiveEngine();
    if (engine) engine->PushRawInput(interval_us, dx, dy);
}

void NoEscape_RecordTargetAcquire(uint64_t timestamp_ms) {
    auto engine = ActiveEngine();
    if (engine) engine->RecordTargetAcquire(timestamp_ms);
}

void NoEscape_PushWeaponFire(uint64_t timestamp_ms) {
    auto engine = ActiveEngine();
    if (engine) engine->PushWeaponFire(timestamp_ms);
}

void NoEscape_PushRecoilEvent(float weapon_pitch, float weapon_yaw, float player_pitch, float player_yaw) {
    auto engine = ActiveEngine();
    if (engine) engine->PushRecoilEvent(weapon_pitch, weapon_yaw, player_pitch, player_yaw);
}

void NoEscape_ResetInput(void) {
    auto engine = ActiveEngine();
    {
        std::lock_guard<std::mutex> lock(g_input_mutex);
        g_accum_pitch = 0.0f;
        g_accum_yaw = 0.0f;
    }
    if (engine) {
        engine->ResetInput();
    }
}

uint32_t NoEscape_GetThreatScore(void) {
    auto engine = ActiveEngine();
    if (!engine) return 0;
    return engine->GetThreatScore();
}

bool NoEscape_IsBanned(void) {
    auto engine = ActiveEngine();
    if (!engine) return false;
    return engine->IsBanned();
}

void NoEscape_SetPanelPin(const char* spki_sha256_hex) {
    std::lock_guard<std::mutex> l(g_preinit_mutex);
    g_panel_pin = spki_sha256_hex ? spki_sha256_hex : "";
}

void NoEscape_SetHostUsesJit(bool uses_jit) {
    std::lock_guard<std::mutex> l(g_preinit_mutex);
    g_host_uses_jit = uses_jit;
}

void NoEscape_SetViolationCallback(NoEscapeViolationCallback callback) {
    g_callback.store(callback);
}

void NoEscape_AddPhantom(uint32_t id, float x, float y, float z) {
    auto engine = ActiveEngine();
    if (engine) engine->GetPhantomMonitor().AddPhantom(id, x, y, z);
}

void NoEscape_UpdatePhantom(uint32_t id, float x, float y, float z) {
    auto engine = ActiveEngine();
    if (engine) engine->GetPhantomMonitor().UpdatePhantom(id, x, y, z);
}

void NoEscape_PushView(float x, float y, float z, float pitch, float yaw, uint64_t timestamp_ms) {
    auto engine = ActiveEngine();
    if (engine) engine->PushViewSample(x, y, z, pitch, yaw, timestamp_ms);
}

void NoEscape_SetViewport(int x, int y, int width, int height) {
    noescape::overlay::OverlayDetector::Instance().SetGameViewport(x, y, width, height);
}

} // extern "C"
