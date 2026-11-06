#pragma once

#include <memory>
#include <atomic>
#include <functional>
#include <vector>
#include <mutex>
#include <thread>
#include "noescape/core/types.hpp"
#include "noescape/core/thread_pool.hpp"
#include "noescape/core/logger.hpp"
#include "noescape/network/panel_client.hpp"
#include "noescape/kinematics/aim_analyzer.hpp"
#include "noescape/kinematics/phantom_monitor.hpp"
#include "noescape/memory/cheat_signature.hpp"

namespace noescape::core {

class AntiCheatEngine {
public:
    using BanCallback = std::function<void(const std::string& reason, uint32_t finalScore)>;
    using ViolationCallback = std::function<void(const DetectionEvent& event)>;

    explicit AntiCheatEngine(EngineConfig config = EngineConfig());
    ~AntiCheatEngine();

    // Initializes all security baselines (integrity hashes, TSC calibration, DMA baseline)
    bool Initialize();

    // Starts background audit worker loops
    void Start();

    // Stops background audit workers
    void Stop();

    // Queries the panel's global ban list once. Banned -> ban; repeated unreachable or
    // invalidly-signed replies -> scored event (offline play is never an instant ban).
    std::vector<DetectionEvent> VerifyPanelStatus();

    // Single synchronous audit pass over all enabled modules (useful for deterministic tests)
    std::vector<DetectionEvent> AuditCycle();

    // Feed an input sample into kinematics aim analyzer
    void PushInputSample(float pitch, float yaw, uint64_t timestamp_ms);

    // Process a newly triggered detection event
    void ProcessDetection(const DetectionEvent& event);

    // Queries current threat status
    uint32_t GetThreatScore() const { return threat_score_.load(); }
    bool IsBanned() const { return is_banned_.load(); }
    std::vector<DetectionEvent> GetDetectionHistory() const;

    // Callbacks and configuration
    void SetBanCallback(BanCallback cb) { ban_callback_ = std::move(cb); }
    void SetViolationCallback(ViolationCallback cb) { violation_callback_ = std::move(cb); }
    const EngineConfig& GetConfig() const { return config_; }

    kinematics::AimAnalyzer& GetAimAnalyzer() { return aim_analyzer_; }
    kinematics::PhantomMonitor& GetPhantomMonitor() { return phantom_monitor_; }

    // Feed camera position/orientation for decoy-entity (phantom) analysis
    void PushViewSample(float x, float y, float z, float pitch, float yaw, uint64_t timestamp_ms);
    const std::vector<uint8_t>& GetLastBlackboxPayload() const { return last_blackbox_payload_; }

    // Watchdog heartbeat monitoring & testing interface
    void UpdateAuditHeartbeat();
    uint64_t GetLastAuditHeartbeatMs() const { return last_audit_heartbeat_ms_.load(std::memory_order_acquire); }
    void SetAuditHeartbeatForTesting(uint64_t timestamp_ms) { last_audit_heartbeat_ms_.store(timestamp_ms, std::memory_order_release); }
    void FreezeBackgroundLoopForTesting(bool freeze) { freeze_background_loop_for_testing_.store(freeze, std::memory_order_release); }

private:
    EngineConfig config_;
    std::atomic<uint32_t> threat_score_{0};
    std::atomic<bool> is_banned_{false};
    std::atomic<bool> running_{false};
    std::atomic<bool> freeze_background_loop_for_testing_{false};

    ThreadPool thread_pool_;
    network::PanelClient panel_client_;
    kinematics::AimAnalyzer aim_analyzer_;
    kinematics::PhantomMonitor phantom_monitor_;

    mutable std::mutex history_mutex_;
    mutable std::mutex input_mutex_;
    std::vector<DetectionEvent> history_;
    std::vector<uint8_t> last_blackbox_payload_;
    std::vector<memory::CheatSignature> default_signatures_;
    BanCallback ban_callback_;
    ViolationCallback violation_callback_;

    void TriggerBan(const std::string& reason, 
                    DetectionType type = DetectionType::UNKNOWN, 
                    const std::string& component = "AntiCheatEngine::Enforcement");
    void SpawnBanScreen(const std::string& reason, 
                        uint32_t finalScore, 
                        const std::string& component, 
                        DetectionType type);
    void BackgroundLoop();
    void WatchdogLoop();
    uint32_t panel_failures_{0};

    std::thread watchdog_thread_;
    std::atomic<uint64_t> last_audit_heartbeat_ms_{0};
};

using SecurityEngine = AntiCheatEngine;

} // namespace noescape::core
