#include "tests/test_framework.hpp"
#include "noescape/core/evidence_correlator.hpp"
#include "noescape/core/engine.hpp"
#include "noescape/overlay/overlay_detector.hpp"
#include "noescape/server/server_integration.hpp"
#include "noescape/kinematics/aim_analyzer.hpp"
#include "noescape/network/crypto_util.hpp"
#include "noescape/network/panel_client.hpp"
#include "noescape/forensics/artifact_analyzer.hpp"
#include "noescape_sdk.h"

#include <thread>
#include <chrono>

using namespace noescape;
using namespace noescape::core;
using namespace noescape::server;
using namespace noescape::kinematics;
using namespace noescape::overlay;
using namespace noescape::network;
using namespace noescape::forensics;

// ============================================================================
// 1. EvidenceCorrelator Temporal & Session Verification
// ============================================================================

TEST(CorrelatorV2, TemporalWindowPruningAndExpiration) {
    EvidenceCorrelator correlator;
    correlator.SetTimeWindowMs(5000); // 5-second sliding window
    correlator.SetSessionId("session-alpha");
    correlator.SetMatchId("match-101");

    uint64_t now_ms = 100000;

    // Event 1: Unbacked memory (Memory category) - 10 seconds ago (expired)
    DetectionEvent ev1;
    ev1.type = DetectionType::UNBACKED_EXECUTABLE_MEMORY;
    ev1.severity = Severity::HIGH;
    ev1.component = "MemoryScanner";
    ev1.details = "Executable anonymous region 0x7000";
    ev1.timestamp = now_ms - 10000;

    correlator.Evaluate(ev1, 0, 100);

    // Event 2: Speedhack (Timing category) - current
    DetectionEvent ev2;
    ev2.type = DetectionType::SPEEDHACK_TIMING_DISCREPANCY;
    ev2.severity = Severity::HIGH;
    ev2.component = "TimingMonitor";
    ev2.details = "TSC tick divergence 3.2x";
    ev2.timestamp = now_ms;

    correlator.Evaluate(ev2, 40, 100);

    // Active category count within current 5s window should be 1 (ev1 pruned)
    ASSERT_EQ(correlator.GetActiveCategoryCount(now_ms), 1u);
}

TEST(CorrelatorV2, SessionAndMatchBoundaryIsolation) {
    EvidenceCorrelator correlator;
    correlator.SetTimeWindowMs(60000);

    correlator.SetSessionId("session-1");
    correlator.SetMatchId("match-A");

    DetectionEvent ev1;
    ev1.type = DetectionType::UNBACKED_EXECUTABLE_MEMORY;
    ev1.severity = Severity::HIGH;
    ev1.component = "MemoryScanner";
    ev1.details = "Executable heap region 0x1000";
    ev1.timestamp = 0; // Current
    correlator.Evaluate(ev1, 0, 100);

    ASSERT_EQ(correlator.GetAggregatedEvidence().size(), 1u);

    // Switch session: old session events must not influence new session
    correlator.SetSessionId("session-2");
    correlator.SetMatchId("match-B");

    ASSERT_EQ(correlator.GetAggregatedEvidence().size(), 0u);
    ASSERT_EQ(correlator.GetActiveCategoryCount(), 0u);
}

TEST(CorrelatorV2, RootCauseDeduplicationSuppression) {
    EvidenceCorrelator correlator;
    correlator.SetTimeWindowMs(60000);

    // Two events referring to the same root fault/memory address
    DetectionEvent ev1;
    ev1.type = DetectionType::UNBACKED_EXECUTABLE_MEMORY;
    ev1.severity = Severity::HIGH;
    ev1.component = "MemoryScanner";
    ev1.details = "Executable anonymous region 0x7fff0000";
    ev1.timestamp = 0;

    DetectionEvent ev2;
    ev2.type = DetectionType::UNBACKED_EXECUTABLE_MEMORY;
    ev2.severity = Severity::HIGH;
    ev2.component = "MemoryScanner";
    ev2.details = "Executable anonymous region 0x7fff0000";
    ev2.timestamp = 0;

    correlator.Evaluate(ev1, 0, 100);
    correlator.Evaluate(ev2, 50, 100);

    // Bounded category count remains 1 and root cause is deduplicated
    ASSERT_EQ(correlator.GetActiveCategoryCount(), 1u);
    ASSERT_EQ(correlator.GetAggregatedEvidence().size(), 1u);
}

TEST(CorrelatorV2, BoundedStorageEvictionCap) {
    EvidenceCorrelator correlator;
    correlator.SetTimeWindowMs(60000);
    correlator.SetMaxStoredEvents(32); // Max capacity = 32 events
    uint64_t now = static_cast<uint64_t>(std::time(nullptr)) * 1000;

    for (uint32_t i = 0; i < 50; ++i) {
        DetectionEvent ev;
        ev.type = DetectionType::ENVIRONMENT_TAMPERING;
        ev.severity = Severity::LOW;
        ev.component = "HeuristicScan";
        ev.details = "Observation iteration " + std::to_string(i);
        ev.timestamp = now + (i * 10);
        correlator.Evaluate(ev, 0, 100);
    }

    // Must never exceed bounded cap of 32
    ASSERT_LE(correlator.GetAggregatedEvidence().size(), 32u);
}

// ============================================================================
// 2. Server ESP Culling Behind Close-Proximity Walls
// ============================================================================

TEST(ServerIntegrationV2, CloseProximityOccludedTargetCulled) {
    ServerEspFilter filter;

    // Solid concrete wall at y = 2.0 (depth 0.4 meters)
    OccluderBox wall{-10.0f, 1.8f, -5.0f, 10.0f, 2.2f, 5.0f, false};
    filter.AddOccluder(wall);

    ObserverState observer;
    observer.player_id = 1;
    observer.x = 0.0f; observer.y = 0.0f; observer.z = 1.0f;

    // Target is only 3.0 meters away (<= 6.0m close_proximity_radius_), but directly behind wall at y = 3.0
    TargetEntityState target_occluded;
    target_occluded.entity_id = 42;
    target_occluded.x = 0.0f; target_occluded.y = 3.0f; target_occluded.z = 1.0f;
    target_occluded.is_making_sound = false;

    auto decision = filter.EvaluateEntityReplication(observer, target_occluded);

    // Full 3D transform must NOT be replicated despite close proximity
    ASSERT_FALSE(decision.replicate_full_transform);
    ASSERT_TRUE(decision.culled_by_occlusion);
    ASSERT_FALSE(decision.replicate_acoustic_cue_only);

    // If target makes footsteps behind the wall, only acoustic cues should replicate
    target_occluded.is_making_sound = true;
    target_occluded.sound_radius = 10.0f;

    auto decisionSound = filter.EvaluateEntityReplication(observer, target_occluded);
    ASSERT_FALSE(decisionSound.replicate_full_transform);
    ASSERT_TRUE(decisionSound.culled_by_occlusion);
    ASSERT_TRUE(decisionSound.replicate_acoustic_cue_only);
}

// ============================================================================
// 3. AimAnalyzer Kinematics Telemetry & Engine Integration
// ============================================================================

TEST(KinematicsV2, SyntheticInputQuantizationDetection) {
    AimAnalyzer analyzer(64);

    // Feed 35 samples with zero timing jitter (perfect 1000us intervals from HID macro)
    std::optional<DetectionEvent> lastEv;
    for (int i = 0; i < 40; ++i) {
        auto ev = analyzer.RecordRawInputSample(1000, 5, 2);
        if (ev) lastEv = ev;
    }

    ASSERT_TRUE(lastEv.has_value());
    ASSERT_EQ(lastEv->type, DetectionType::KINEMATICS_SYNTHETIC_INPUT);
}

TEST(KinematicsV2, TriggerbotReactionLatencyDetection) {
    AimAnalyzer analyzer(64);
    uint64_t t = 10000;

    // Minimum 6 samples required for triggerbot reaction distribution analysis
    std::optional<DetectionEvent> lastEv;
    for (int i = 0; i < 7; ++i) {
        analyzer.RecordCrosshairTargetAcquire(t);
        // Weapon fires 15ms later (inhuman sub-45ms reaction time)
        auto ev = analyzer.RecordWeaponFire(t + 15);
        if (ev) lastEv = ev;
        t += 2000;
    }

    ASSERT_TRUE(lastEv.has_value());
    ASSERT_EQ(lastEv->type, DetectionType::KINEMATICS_TRIGGERBOT);
}

TEST(KinematicsV2, RecoilCompensationNegationDetection) {
    AimAnalyzer analyzer(64);

    std::optional<DetectionEvent> lastEv;
    // Feed 20 consecutive shots where player pitch input perfectly negates weapon vertical kick
    for (int i = 0; i < 25; ++i) {
        float kickPitch = 2.4f;
        float kickYaw = 0.8f;
        float counterPitch = -2.399f; // 99.9% perfect robotic counter-pull
        float counterYaw = -0.799f;
        auto ev = analyzer.RecordRecoilCompensation(kickPitch, kickYaw, counterPitch, counterYaw);
        if (ev) lastEv = ev;
    }

    ASSERT_TRUE(lastEv.has_value());
    ASSERT_EQ(lastEv->type, DetectionType::KINEMATICS_RECOIL_AUTOMATION);
}

// ============================================================================
// 4. Extended SDK Configuration & Profile Inspection
// ============================================================================

TEST(SdkV2, ProfileConfigurationsAndExtendedFields) {
    // Production profile
    NoEscapeConfig prodCfg = NoEscape_GetProfileConfig(NOESCAPE_PROFILE_PRODUCTION);
    ASSERT_EQ(prodCfg.struct_size, sizeof(NoEscapeConfig));
    ASSERT_EQ(prodCfg.config_version, 2u);
    ASSERT_FALSE(prodCfg.enforce_ban);
    ASSERT_TRUE(prodCfg.require_multi_signal_corroboration);
    ASSERT_EQ(prodCfg.enforcement_mode, static_cast<int>(EnforcementMode::SERVER_SESSION_REJECT));

    // Shadow production profile
    NoEscapeConfig shadowCfg = NoEscape_GetProfileConfig(NOESCAPE_PROFILE_SHADOW_PRODUCTION);
    ASSERT_EQ(shadowCfg.enforcement_mode, static_cast<int>(EnforcementMode::SHADOW));
    ASSERT_TRUE(shadowCfg.require_multi_signal_corroboration);

    // Testing profile
    NoEscapeConfig testCfg = NoEscape_GetProfileConfig(NOESCAPE_PROFILE_TESTING);
    ASSERT_TRUE(testCfg.enforce_ban);
    ASSERT_FALSE(testCfg.require_multi_signal_corroboration);

    // Initialize SDK with Production config
    int rc = NoEscape_Init(&prodCfg);
    ASSERT_EQ(rc, 0);

    // Exercise new SDK kinematics C wrappers safely
    NoEscape_PushRawInput(1000, 2, 1);
    NoEscape_RecordTargetAcquire(5000);
    NoEscape_PushWeaponFire(5100);
    NoEscape_PushRecoilEvent(1.5f, 0.5f, -1.0f, -0.3f);

    NoEscape_Shutdown();
}

// ============================================================================
// 5. Hardening & Anti-False-Positive Verifications
// ============================================================================

TEST(CorrelatorV2, StrictCorroborationPreventsSingleSignalPermanentBan) {
    EvidenceCorrelator correlator;
    correlator.SetTimeWindowMs(60000);

    // Single high-severity event without independent corroborating signal
    DetectionEvent singleEv;
    singleEv.type = DetectionType::UNBACKED_EXECUTABLE_MEMORY;
    singleEv.severity = Severity::FATAL_BAN;
    singleEv.component = "MemoryScanner";
    singleEv.details = "Executable anonymous region 0x7fff0000";
    singleEv.threat_score = 100;

    // Under strict corroboration mode (Production), permanent ban MUST be refused
    auto decisionStrict = correlator.Evaluate(singleEv, 0, 100, true);
    ASSERT_FALSE(decisionStrict.eligible_for_permanent_ban);
    ASSERT_LT(decisionStrict.effective_score_delta, 100u);

    // Under testing mode (strict=false), permanent ban is allowed
    EvidenceCorrelator correlatorTest;
    auto decisionTest = correlatorTest.Evaluate(singleEv, 0, 100, false);
    ASSERT_TRUE(decisionTest.eligible_for_permanent_ban);
}

TEST(CorrelatorV2, MultiSignalCorroborationEnablesPermanentBan) {
    EvidenceCorrelator correlator;
    correlator.SetTimeWindowMs(60000);

    // Event 1: Memory category
    DetectionEvent ev1;
    ev1.type = DetectionType::UNBACKED_EXECUTABLE_MEMORY;
    ev1.severity = Severity::HIGH;
    ev1.component = "MemoryScanner";
    ev1.details = "Executable anonymous region 0x7fff0000";
    ev1.threat_score = 60;
    correlator.Evaluate(ev1, 0, 100, true);

    // Event 2: Independent Process category with distinct root cause
    DetectionEvent ev2;
    ev2.type = DetectionType::SUSPICIOUS_PROCESS_DETECTED;
    ev2.severity = Severity::HIGH;
    ev2.component = "ProcessAnalyzer";
    ev2.details = "Blacklisted injector tool: PID 9999";
    ev2.threat_score = 50;

    auto decision = correlator.Evaluate(ev2, 60, 100, true);
    // Two independent categories present: corroboration satisfied
    ASSERT_GE(decision.independent_category_count, 2u);
    ASSERT_TRUE(decision.eligible_for_permanent_ban);
}

TEST(OverlayV2, UnverifiedPidDoesNotTriggerImmediateHijack) {
    auto& detector = OverlayDetector::Instance();
    detector.ClearMockWindows();

    // A legitimate window titled "Steam Overlay", but PID is inaccessible / unverified (PID 0)
    // Even if is_topmost is true, whitelisted title matching must NOT false-positive on generic keyword checks
    OverlayWindowInfo win{};
    win.title = "Steam Overlay";
    win.class_name = "ValveSteamOverlay";
    win.pid = 0;
    win.is_layered = false;
    win.is_transparent = false;
    win.is_topmost = true;
    detector.AddMockWindow(win);

    // Must not be flagged as a suspicious cheating overlay hijack
    auto alerts = detector.DetectSuspiciousWindows();
    ASSERT_EQ(alerts.size(), 0u);
    detector.ClearMockWindows();
}

TEST(OverlayV2, SpoofedTitleDetectedViaExePath) {
    auto& detector = OverlayDetector::Instance();
    detector.ClearMockWindows();

    // A rogue cheat window masquerading under the title "Steam Overlay" but executing from /tmp/
    OverlayWindowInfo win{};
    win.title = "Steam Overlay";
    win.class_name = "ValveSteamOverlay";
    win.pid = 9999;
    win.exe_path = "/tmp/cheat_overlay";
    win.is_topmost = true;
    detector.AddMockWindow(win);

    // Must detect the spoofed overlay because the binary path is suspicious
    auto alerts = detector.DetectSuspiciousWindows();
    ASSERT_EQ(alerts.size(), 1u);
    ASSERT_EQ(alerts[0].type, DetectionType::OVERLAY_HIJACK_DETECTED);
    detector.ClearMockWindows();
}

TEST(WatchdogV2, WatchdogDelayDoesNotCausePermanentBanInProduction) {
    EngineConfig prodCfg = EngineConfig::ProductionProfile();
    prodCfg.enableHeartbeat = false; // avoid spinning background threads in unit test

    AntiCheatEngine engine(prodCfg);
    ASSERT_TRUE(engine.Initialize());

    // Inject a watchdog heartbeat timeout anomaly into production engine
    DetectionEvent watchdogEv;
    watchdogEv.type = DetectionType::HEARTBEAT_TAMPERING;
    watchdogEv.severity = Severity::CRITICAL;
    watchdogEv.component = "AntiCheatEngine::Watchdog";
    watchdogEv.details = "Watchdog heartbeat timeout: background audit loop delayed (> 3000ms)";
    watchdogEv.threat_score = 100;

    engine.ProcessDetection(watchdogEv);

    // Production profile MUST NOT issue a permanent ban on scheduling delay
    ASSERT_FALSE(engine.IsBanned());
    ASSERT_LT(engine.GetThreatScore(), 100u);
}

TEST(CorrelatorV2, HighEventSaturationStressTest) {
    EvidenceCorrelator correlator;
    correlator.SetTimeWindowMs(60000);
    // Rapidly feed 5,000 synthetic events within the temporal window
    for (uint32_t i = 0; i < 5000; ++i) {
        DetectionEvent ev;
        ev.type = DetectionType::SPEEDHACK_TIMING_DISCREPANCY;
        ev.severity = Severity::MEDIUM;
        ev.component = "TimingAnomaly::Rdtsc";
        ev.details = "Delta sample " + std::to_string(i % 10);
        ev.threat_score = 15;
        ev.timestamp = 1000 + (i / 100);
        auto decision = correlator.Evaluate(ev, 0, 100, true);
        // Single heuristic must be identified as weak single signal
        ASSERT_TRUE(decision.is_weak_single_signal);
        // Must never exceed ban threshold or promote to permanent ban
        ASSERT_FALSE(decision.eligible_for_permanent_ban);
    }
}

TEST(NetworkV2, EmptySecretKeyRefusesHmacVerification) {
    // Unconfigured client with empty server public key and empty secret key
    PanelClient client("http://127.0.0.1:18433", "");
    std::string msg = "{\"status\":\"banned\",\"reason\":\"test\"}";
    std::string forgedHmac = CryptoUtil::HmacSha256("", msg);

    // Verification must fail closed: an unconfigured client must NEVER accept empty-key HMAC signatures
    ASSERT_FALSE(client.VerifyServerSignature(msg, forgedHmac));
}

TEST(ArtifactV2, VulnerableOemDriverIsMediumSeverityNotFatalBan) {
    auto& analyzer = forensics::ArtifactAnalyzer::Instance();
    std::vector<std::string> drivers = {"ene.sys", "speedfan.sys", "asio64.sys"};
    auto events = analyzer.PerformAudit({}, drivers);
    for (const auto& ev : events) {
        if (ev.component == "ArtifactAnalyzer::DriverWatch") {
            // OEM vulnerable driver posture warnings must be MEDIUM severity (score 30), never FATAL_BAN
            ASSERT_EQ(ev.severity, Severity::MEDIUM);
            ASSERT_EQ(ev.threat_score, 30u);
            ASSERT_NE(ev.details.find("Vulnerable OEM"), std::string::npos);
        }
    }
}


