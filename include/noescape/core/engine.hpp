#pragma once

#include <memory>
#include <atomic>
#include <functional>
#include <vector>
#include <mutex>
#include <thread>
#include <set>
#include <string>
#include "noescape/core/types.hpp"
#include "noescape/core/evidence_correlator.hpp"
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

    // Queries current threat & enforcement status
    uint32_t GetThreatScore() const { return threat_score_.load(); }
    bool IsBanned() const { return is_banned_.load(); }
    bool IsShadowFlagged() const { return is_shadow_flagged_.load(); }
    bool IsMatchRestricted() const { return is_match_restricted_.load(); }
    bool IsSessionRejected() const { return is_session_rejected_.load(); }
    std::vector<DetectionEvent> GetDetectionHistory() const;
    const EvidenceCorrelator& GetEvidenceCorrelator() const { return correlator_; }

    // Audit cycle performance telemetry (microseconds)
    uint64_t GetLastAuditDurationUs() const { return last_audit_duration_us_.load(std::memory_order_relaxed); }

    // Callbacks and configuration
    void SetBanCallback(BanCallback cb) { std::lock_guard<std::mutex> l(history_mutex_); ban_callback_ = std::move(cb); }
    void SetViolationCallback(ViolationCallback cb) { std::lock_guard<std::mutex> l(history_mutex_); violation_callback_ = std::move(cb); }

    // Thread-safe reset of the aim analyzer history (respawn / teleport)
    void ResetInput();
    const EngineConfig& GetConfig() const { return config_; }

    kinematics::AimAnalyzer& GetAimAnalyzer() { return aim_analyzer_; }
    kinematics::PhantomMonitor& GetPhantomMonitor() { return phantom_monitor_; }

    // Feed camera position/orientation for decoy-entity (phantom) analysis
    void PushViewSample(float x, float y, float z, float pitch, float yaw, uint64_t timestamp_ms);
    const std::vector<uint8_t>& GetLastBlackboxPayload() const { return last_blackbox_payload_; }

    // Watchdog heartbeat monitoring & testing interface
    void UpdateAuditHeartbeat();
    uint64_t GetLastAuditHeartbeatMs() const { return last_audit_heartbeat_ms_.load(std::memory_order_acquire); }
    void SetAuditHeartbeatForTesting(uint64_t timestamp_ms) {
        std::lock_guard<std::mutex> lock(heartbeat_mutex_);
        last_audit_heartbeat_ms_.store(timestamp_ms, std::memory_order_release);
    }
    uint64_t GetWatchdogHeartbeatMs() const { return watchdog_heartbeat_ms_.load(std::memory_order_acquire); }
    void SetWatchdogHeartbeatForTesting(uint64_t ts) {
        std::lock_guard<std::mutex> lock(heartbeat_mutex_);
        watchdog_heartbeat_ms_.store(ts, std::memory_order_release);
    }
    void FreezeWatchdogForTesting(bool f) {
        std::lock_guard<std::mutex> lock(heartbeat_mutex_);
        freeze_watchdog_for_testing_.store(f, std::memory_order_release);
    }
    void FreezeBackgroundLoopForTesting(bool freeze) {
        std::lock_guard<std::mutex> lock(heartbeat_mutex_);
        freeze_background_loop_for_testing_.store(freeze, std::memory_order_release);
    }
    // Simulates OS-wide sleep/hibernate wake recovery on the watchdog
    void SimulateSystemWakeRecoveryForTesting();

private:
    EngineConfig config_;
    std::atomic<uint32_t> threat_score_{0};
    std::atomic<bool> is_banned_{false};
    std::atomic<bool> is_shadow_flagged_{false};
    std::atomic<bool> is_match_restricted_{false};
    std::atomic<bool> is_session_rejected_{false};
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::atomic<uint32_t> audit_cycle_counter_{0};
    std::atomic<uint64_t> last_dma_audit_ms_{0};
    std::atomic<uint64_t> last_audit_duration_us_{0};
    std::set<std::string> scored_keys_;
    std::mutex audit_mutex_;
    std::atomic<std::thread::id> background_thread_id_{};
    std::atomic<uint64_t> last_heavy_scan_ms_{0};
    std::atomic<bool> freeze_background_loop_for_testing_{false};
    std::atomic<bool> freeze_watchdog_for_testing_{false};

    EvidenceCorrelator correlator_;
    network::PanelClient panel_client_;
    kinematics::AimAnalyzer aim_analyzer_;
    kinematics::PhantomMonitor phantom_monitor_;

    mutable std::mutex history_mutex_;
    mutable std::mutex input_mutex_;
    mutable std::mutex heartbeat_mutex_;
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
    void NetworkLoop();
    void HandleAttestation(const network::HeartbeatResult& hb);
    std::atomic<uint32_t> panel_failures_{0};
    [[maybe_unused]] bool dumpable_modified_{false};

    std::thread background_thread_;
    std::thread watchdog_thread_;
    std::thread network_thread_;
    std::atomic<uint64_t> last_audit_heartbeat_ms_{0};
    // Mutual supervision: the audit loop watches the watchdog the same way the watchdog watches it
    std::atomic<uint64_t> watchdog_heartbeat_ms_{0};
    std::atomic<bool> watchdog_exited_{false};      // set by the watchdog when it ends on purpose
    std::atomic<bool> watchdog_reported_{false};
    void CheckWatchdogHealth();
};

using SecurityEngine = AntiCheatEngine;

} // namespace noescape::core
