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
float g_accum_pitch = 0.0f;
float g_accum_yaw = 0.0f;

} // namespace

extern "C" {

NoEscapeConfig NoEscape_GetDefaultConfig(void) {
    NoEscapeConfig cfg{};
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
    } else {
        engineCfg.enableHeartbeat = false;
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
