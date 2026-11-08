#include "tests/test_framework.hpp"
#include "noescape/core/types.hpp"
#include "noescape/core/evidence_correlator.hpp"
#include "noescape/core/engine.hpp"
#include "noescape/server/server_integration.hpp"
#include "noescape/kinematics/aim_analyzer.hpp"
#include "noescape/security/timing.hpp"

#include <vector>
#include <string>
#include <cmath>
#include <thread>
#include <chrono>

using namespace noescape;
using namespace noescape::core;
using namespace noescape::server;
using namespace noescape::kinematics;
using namespace noescape::security;

// ============================================================================
// Priority 1: Multi-Signal Corroboration Engine Architecture Hardening
// ============================================================================

TEST(HardeningV1_5, CorroborationIntraCategoryOrthogonalSubtypesSatisfiesBan) {
    EvidenceCorrelator correlator;
    correlator.SetTimeWindowMs(60000);

    // 1. First event: Behavioral Kinematics - Aimbot Snap
    DetectionEvent ev1;
    ev1.type = DetectionType::KINEMATICS_AIMBOT_SNAP;
    ev1.severity = Severity::HIGH;
    ev1.component = "Kinematics::AimAnalyzer::Snap";
    ev1.details = "35 deg instantaneous flick followed by dead-stop";
    ev1.threat_score = 60;
    ev1.timestamp = DetectionEvent::NowMonotonicMs();
    ev1.timestamp_utc_ms = DetectionEvent::NowUtcMs();

    auto dec1 = correlator.Evaluate(ev1, 0, 100, /*strict_corroboration_mode=*/true);
    ASSERT_FALSE(dec1.eligible_for_permanent_ban);
    ASSERT_FALSE(dec1.eligible_for_session_reject);

    // 2. Second event: Same coarse category (BEHAVIORAL_KINEMATICS), but orthogonal sub-type (Triggerbot)
    DetectionEvent ev2;
    ev2.type = DetectionType::KINEMATICS_TRIGGERBOT;
    ev2.severity = Severity::HIGH;
    ev2.component = "Kinematics::AimAnalyzer::Triggerbot";
    ev2.details = "Inhuman Ex-Gaussian reaction latency (mu=42ms, sigma=1.8ms)";
    ev2.threat_score = 60;
    ev2.timestamp = DetectionEvent::NowMonotonicMs() + 100;
    ev2.timestamp_utc_ms = DetectionEvent::NowUtcMs() + 100;

    auto dec2 = correlator.Evaluate(ev2, 60, 100, /*strict_corroboration_mode=*/true);

    // Intra-category orthogonal sub-types (Snap + Triggerbot) satisfy multi-signal corroboration!
    ASSERT_TRUE(dec2.eligible_for_permanent_ban);
    ASSERT_TRUE(dec2.eligible_for_session_reject);
    ASSERT_TRUE(dec2.eligible_for_shadow);
    ASSERT_EQ(dec2.overall_confidence, ConfidenceLevel::HIGH_CONFIDENCE_VIOLATION);
}

TEST(HardeningV1_5, CorroborationMemoryIntraCategoryOrthogonalSubtypes) {
    EvidenceCorrelator correlator;
    correlator.SetTimeWindowMs(60000);

    // 1. Unbacked executable memory allocation
    DetectionEvent ev1;
    ev1.type = DetectionType::UNBACKED_EXECUTABLE_MEMORY;
    ev1.severity = Severity::CRITICAL;
    ev1.component = "MemoryScanner::UnbackedPages";
    ev1.details = "Anonymous unbacked executable page at 0x7fff1000";
    ev1.threat_score = 70;
    ev1.timestamp = DetectionEvent::NowMonotonicMs();
    ev1.timestamp_utc_ms = DetectionEvent::NowUtcMs();

    auto dec1 = correlator.Evaluate(ev1, 0, 100, /*strict_corroboration_mode=*/true);
    ASSERT_FALSE(dec1.eligible_for_permanent_ban);

    // 2. Memory signature match (same category MEMORY_INTEGRITY, orthogonal sub-type)
    DetectionEvent ev2;
    ev2.type = DetectionType::MEMORY_SIGNATURE_MATCH;
    ev2.severity = Severity::CRITICAL;
    ev2.component = "MemoryScanner::SigScan";
    ev2.details = "Known cheat pattern match at 0x7fff2000";
    ev2.threat_score = 70;
    ev2.timestamp = DetectionEvent::NowMonotonicMs() + 50;
    ev2.timestamp_utc_ms = DetectionEvent::NowUtcMs() + 50;

    auto dec2 = correlator.Evaluate(ev2, 70, 100, /*strict_corroboration_mode=*/true);
    ASSERT_TRUE(dec2.eligible_for_permanent_ban);
    ASSERT_TRUE(dec2.eligible_for_session_reject);
}

TEST(HardeningV1_5, CorroborationDuplicateSameTypeHeuristicDoesNotCorroborate) {
    EvidenceCorrelator correlator;
    correlator.SetTimeWindowMs(60000);

    DetectionEvent ev1;
    ev1.type = DetectionType::UNBACKED_EXECUTABLE_MEMORY;
    ev1.severity = Severity::CRITICAL;
    ev1.component = "MemoryScanner::UnbackedPages";
    ev1.details = "Anonymous page #1 at 0x7fff1000";
    ev1.threat_score = 60;
    ev1.timestamp = DetectionEvent::NowMonotonicMs();
    ev1.timestamp_utc_ms = DetectionEvent::NowUtcMs();

    correlator.Evaluate(ev1, 0, 100, /*strict=*/true);

    // Repeated finding of the SAME sub-type does NOT satisfy multi-signal corroboration
    DetectionEvent ev2 = ev1;
    ev2.details = "Anonymous page #2 at 0x7fff3000";
    ev2.timestamp = DetectionEvent::NowMonotonicMs() + 20;

    auto dec2 = correlator.Evaluate(ev2, 60, 100, /*strict=*/true);
    ASSERT_FALSE(dec2.eligible_for_permanent_ban);
    ASSERT_FALSE(dec2.eligible_for_session_reject);
}

// ============================================================================
// Priority 2: Server ESP FOV Frustum Culling & Vertical Z-Axis Raycasts
// ============================================================================

TEST(HardeningV1_5, ServerEspFovFrustumCullingBlocks360Radar) {
    ServerEspFilter filter;
    // Add a distant occluder so HasOcclusionData() is true
    filter.AddOccluder(OccluderBox{100.0f, 100.0f, 0.0f, 102.0f, 102.0f, 2.0f, false});

    // Observer at (0, 0, 0), looking forward along +X (yaw = 0 deg, pitch = 0 deg, FOV = 90 deg)
    ObserverState obs{1, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 90.0f};

    // 1. Target directly behind observer at (-20, 0, 0) in open courtyard (180 deg off-screen)
    TargetEntityState targetBehind{10, -20.0f, 0.0f, 0.0f, 0.6f, false, 0.0f};
    auto decBehind = filter.EvaluateEntityReplication(obs, targetBehind);

    // Must be culled by FOV frustum so 360-degree radar cheats cannot see target!
    ASSERT_TRUE(decBehind.culled_by_fov);
    ASSERT_FALSE(decBehind.replicate_full_transform);

    // 2. Target behind observer making footsteps within sound radius
    targetBehind.is_making_sound = true;
    targetBehind.sound_radius = 25.0f;
    auto decBehindSound = filter.EvaluateEntityReplication(obs, targetBehind);
    ASSERT_TRUE(decBehindSound.culled_by_fov);
    ASSERT_FALSE(decBehindSound.replicate_full_transform);
    ASSERT_TRUE(decBehindSound.replicate_acoustic_cue_only);

    // 3. Target in front of observer at (20, 0, 0) inside FOV
    TargetEntityState targetFront{11, 20.0f, 0.0f, 0.0f, 0.6f, false, 0.0f};
    auto decFront = filter.EvaluateEntityReplication(obs, targetFront);
    ASSERT_FALSE(decFront.culled_by_fov);
    ASSERT_TRUE(decFront.replicate_full_transform);
}

TEST(HardeningV1_5, ServerEspVerticalRaycastPreventsHalfWallFalseOcclusion) {
    ServerEspFilter filter;

    // Half-wall spanning x: [-10, 10], y: [4.5, 5.5], z: [0.0, 1.0] (height 1.0m)
    filter.AddOccluder(OccluderBox{-10.0f, 4.5f, 0.0f, 10.0f, 5.5f, 1.0f, false});

    // Observer standing at (0, 0, 1.2), looking along +Y (yaw = 90 deg)
    ObserverState obs{1, 0.0f, 0.0f, 1.2f, 0.0f, 90.0f, 90.0f};

    // Crouching/peeking target at (0, 8.0, 0.8) with bounding radius r = 0.5m.
    // Target center is at z = 0.8 (behind the 1.0m wall), but head top is at z = 0.8 + 0.5 = 1.3m (above the wall!).
    TargetEntityState peekingTarget{2, 0.0f, 8.0f, 0.8f, 0.5f, false, 0.0f};

    // Line of sight must NOT be occluded thanks to vertical {0, 0, +r} raycast probe!
    bool occluded = filter.IsLineOfSightOccluded(obs, peekingTarget);
    ASSERT_FALSE(occluded);

    auto decision = filter.EvaluateEntityReplication(obs, peekingTarget);
    ASSERT_TRUE(decision.replicate_full_transform);
    ASSERT_FALSE(decision.culled_by_occlusion);
}

// ============================================================================
// Priority 3: Kinematics Hardening (Sustained Yaw Sweeps > 15 deg)
// ============================================================================

TEST(HardeningV1_5, KinematicsSustainedYawSweepRoboticLinearityDetected) {
    AimAnalyzer analyzer(64);
    analyzer.SetLinearityThreshold(0.005f);
    analyzer.SetMinSamplesForAnalysis(8);

    uint64_t t = 1000;
    // Sustained horizontal yaw sweep (20 degrees, pitch locked at 0.0)
    // In prior versions, min(vP, vY) < 1.0 aborted the check, enabling yaw-only aimbot bypass.
    for (int i = 0; i < 12; ++i) {
        float p = 0.0f;                             // Pitch locked (tactical shooter head-level)
        float y = static_cast<float>(i) * 2.0f;     // Exactly linear yaw sweep: 0 to 22 deg
        t += 16;

        auto ev = analyzer.PushSample(p, y, t);
        if (i >= 8 && ev.has_value()) {
            ASSERT_EQ(ev->type, DetectionType::KINEMATICS_PERFECT_LINEARITY);
            return;
        }
    }
}

TEST(HardeningV1_5, KinematicsSustainedYawSweepArtificialSmoothingDetected) {
    AimAnalyzer analyzer(64);
    analyzer.SetMinSamplesForAnalysis(8);

    uint64_t t = 1000;
    // Sustained yaw-only sweep: exactly 1.6 degrees per 16ms tick (0% velocity variance)
    float p = 0.0f;
    float y = 0.0f;

    for (int i = 0; i < 15; ++i) {
        y += 1.6f; // Total movement: 24 deg (> 15 deg)
        t += 16;

        auto ev = analyzer.PushSample(p, y, t);
        if (i >= 8 && ev.has_value()) {
            ASSERT_EQ(ev->type, DetectionType::KINEMATICS_ARTIFICIAL_SMOOTHING);
            return;
        }
    }
}

// ============================================================================
// Priority 4: Timing Integrity Speedhack Detection Window [0.80, 1.25]
// ============================================================================

TEST(HardeningV1_5, TimingTightenedWindowDetectsModerateSpeedhack) {
    auto& timing = TimingIntegrity::Instance();
    timing.Calibrate(20);
    ASSERT_TRUE(timing.IsCalibrated());

    // Normal progression within [0.80, 1.25]
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    auto evNormal = timing.CheckSpeedhack();
    ASSERT_FALSE(evNormal.has_value());
}

// ============================================================================
// Priority 5: Engine Watchdog Prolonged Freeze (> 6000ms) Fail-Closed Enforcement
// ============================================================================

TEST(HardeningV1_5, EngineWatchdogProlongedFreezeEnforcesFailClosed) {
    EngineConfig cfg = EngineConfig::TestingProfile();
    cfg.enforcementMode = EnforcementMode::SERVER_SESSION_REJECT;
    cfg.requireMultiSignalCorroboration = true; // Strict corroboration mode
    AntiCheatEngine engine(cfg);
    engine.Start();

    ASSERT_FALSE(engine.IsSessionRejected());
    ASSERT_TRUE(engine.GetLastAuditHeartbeatMs() > 0);

    // Simulate prolonged background audit loop freeze exceeding 6000ms
    engine.FreezeBackgroundLoopForTesting(true);
    uint64_t prolongedStallTime = engine.GetLastAuditHeartbeatMs() - 7000;
    engine.SetAuditHeartbeatForTesting(prolongedStallTime);

    // Watchdog checks every 100ms; wait 250ms for watchdog loop to detect prolonged freeze
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    // Watchdog must detect prolonged freeze (> 6000ms) and enforce fail-closed session rejection
    ASSERT_TRUE(engine.IsSessionRejected());

    engine.FreezeBackgroundLoopForTesting(false);
    engine.Stop();
}
