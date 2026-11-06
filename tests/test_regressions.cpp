// Regression tests for the issues found in the full code audit.
#include "tests/test_framework.hpp"
#include "noescape_sdk.h"
#include "noescape/core/engine.hpp"
#include "noescape/core/blackbox.hpp"
#include "noescape/core/envutil.hpp"
#include "noescape/kinematics/aim_analyzer.hpp"
#include "noescape/memory/memory_scanner.hpp"
#include "noescape/network/crypto_util.hpp"
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <thread>

using namespace noescape;

TEST(Regression, BlackboxCipherLenOverflowRejected) {
    std::vector<uint8_t> pk(200, 0);
    pk[0] = 'N'; pk[1] = 'E'; pk[2] = 'B'; pk[3] = 'B'; pk[4] = 1;
    uint32_t cl = 0xFFFFFFC0u; // cipherLen + 64 wraps to 0 in 32-bit arithmetic
    for (int i = 0; i < 4; ++i) pk[22 + i] = static_cast<uint8_t>((cl >> (8 * i)) & 0xFF);
    core::BlackboxRecord r;
    ASSERT_FALSE(core::BlackboxDumper::Instance().DecryptAndDeserialize(pk, "k", r));
}

TEST(Regression, ConstantTimeEquals) {
    ASSERT_TRUE(network::CryptoUtil::ConstantTimeEquals("abc", "abc"));
    ASSERT_FALSE(network::CryptoUtil::ConstantTimeEquals("abc", "abd"));
    ASSERT_FALSE(network::CryptoUtil::ConstantTimeEquals("abc", "abcd"));
}

TEST(Regression, NameMatchingIsNotSubstring) {
    ASSERT_TRUE(core::NameMatchesEntry("gdb", "gdb"));
    ASSERT_TRUE(core::NameMatchesEntry("gdb-multiarch", "gdb"));
    ASSERT_FALSE(core::NameMatchesEntry("gdbus", "gdb"));
    ASSERT_FALSE(core::NameMatchesEntry("validator", "ida"));
    ASSERT_FALSE(core::NameMatchesEntry("tidal", "ida"));
}

TEST(Regression, AxisAlignedPanIsNotLinearityCheat) {
    kinematics::AimAnalyzer a(64);
    int hits = 0;
    for (int i = 0; i < 60; ++i) {
        if (a.PushSample(0.0f, i * 2.0f, 1000 + i * 8)) ++hits; // gamepad full-stick yaw pan
    }
    ASSERT_EQ(hits, 0);
}

TEST(Regression, DiagonalRoboticSweepStillDetected) {
    kinematics::AimAnalyzer a(64);
    int hits = 0;
    for (int i = 0; i < 40; ++i) {
        if (a.PushSample(i * 1.0f, i * 2.0f, 1000 + i * 8)) ++hits;
    }
    ASSERT_GT(hits, 0);
}

TEST(Regression, FrameFlickIsNoLongerInstantBan) {
    kinematics::AimAnalyzer a(64);
    a.PushSample(0, 0, 1000);
    a.PushSample(0, 0.3f, 1016);
    auto ev = a.PushSample(0, 25.3f, 1032);
    auto ev2 = a.PushSample(0, 25.4f, 1048);
    auto e = ev ? ev : ev2;
    if (e) ASSERT_NE(static_cast<int>(e->severity), static_cast<int>(core::Severity::FATAL_BAN));
}

TEST(Regression, ClockResetDoesNotDisableAnalysis) {
    kinematics::AimAnalyzer a(64);
    a.PushSample(0, 0, 5'000'000);
    a.PushSample(0, 1, 5'000'010);
    a.PushSample(0, 2, 100); // timer restarted
    ASSERT_EQ(static_cast<int>(a.GetHistorySize()), 1);
}

TEST(Regression, SdkRejectsNonFiniteInput) {
    NoEscapeConfig cfg = NoEscape_GetDefaultConfig();
    cfg.show_ban_ui = false;
    cfg.enable_dma_detection = false;
    ASSERT_EQ(NoEscape_Init(&cfg), 0);
    // Previously: infinite loop (1e30) / permanently poisoned accumulator (NaN)
    NoEscape_PushMouseEvent(1e30f, 0.0f, 100);
    NoEscape_PushMouseEvent(NAN, NAN, 110);
    NoEscape_PushMouseEvent(INFINITY, 0.0f, 120);
    NoEscape_ResetInput();
    NoEscape_Shutdown();
}

TEST(Regression, SdkZeroThresholdKeepsDefault) {
    NoEscapeConfig cfg{};
    cfg.panel_url = "http://127.0.0.1:1/api";
    cfg.secret_key = "k";
    cfg.ban_threshold = 0;
    ASSERT_EQ(NoEscape_Init(&cfg), 0);
    ASSERT_FALSE(NoEscape_IsBanned());
    NoEscape_Shutdown();
}

TEST(Regression, AuditCycleWorksWithoutStart) {
    core::EngineConfig cfg;
    cfg.enableDmaDetection = false;
    cfg.enableSpeedhackDetection = false;
    cfg.enforceBanOnViolation = false;
    cfg.enableHeartbeat = false;
    core::AntiCheatEngine engine(cfg);
    ASSERT_TRUE(engine.Initialize());
    // A persistent finding injected via ProcessDetection must score only once
    core::DetectionEvent ev;
    ev.type = core::DetectionType::SUSPICIOUS_PROCESS_DETECTED;
    ev.severity = core::Severity::HIGH;
    ev.component = "Test";
    ev.details = "Blacklisted process: PID 1";
    ev.threat_score = 80;
    for (int i = 0; i < 20; ++i) engine.ProcessDetection(ev);
    ASSERT_EQ(engine.GetThreatScore(), 80u);
    // Synchronous audit must execute (previously returned immediately unless Start() was called)
    engine.AuditCycle();
    ASSERT_GT(engine.GetLastAuditHeartbeatMs(), 0u);
}

TEST(Regression, PersistentFindingDoesNotSnowballIntoBan) {
    core::EngineConfig cfg;
    cfg.enforceBanOnViolation = true;
    cfg.banScoreThreshold = 100;
    cfg.showBanUi = false;
    cfg.terminateProcessOnBan = false;
    cfg.enableHeartbeat = false;
    setenv("NOESCAPE_TEST_MODE", "1", 1);
    core::AntiCheatEngine engine(cfg);
    core::DetectionEvent ev;
    ev.type = core::DetectionType::ANTI_DEBUG_TOOL;
    ev.severity = core::Severity::HIGH;
    ev.component = "AntiDebug::ProcessScanner";
    ev.details = "tool running: gdb";
    ev.threat_score = 60;
    for (int i = 0; i < 50; ++i) engine.ProcessDetection(ev);
    ASSERT_FALSE(engine.IsBanned());
    ASSERT_EQ(engine.GetThreatScore(), 60u);
}

TEST(Regression, MemoryCacheIsReferenceCounted) {
    auto& ms = memory::MemoryScanner::Instance();
    ms.RefreshCache();
    ms.RefreshCache();
    ms.ClearCache();
    ASSERT_TRUE(ms.IsCacheValid()); // second concurrent audit still holds its snapshot
    ms.ClearCache();
    ASSERT_FALSE(ms.IsCacheValid());
}

TEST(Regression, ScannerHasNoStringSignatureInstantBan) {
    for (const auto& sig : memory::MemoryScanner::GetDefaultCheatSignatures()) {
        if (sig.GetTargetRule() == memory::MemoryTargetRule::ANY_ANONYMOUS) {
            ASSERT_NE(static_cast<int>(sig.GetSeverity()), static_cast<int>(core::Severity::FATAL_BAN));
            ASSERT_LT(sig.GetThreatScore(), 100u);
        }
    }
}
