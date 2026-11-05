#include "tests/test_framework.hpp"
#include "noescape/core/engine.hpp"

using namespace noescape::core;

TEST(Engine, InitializationAndThreatScoring) {
    EngineConfig cfg;
    cfg.enableHeartbeat = false;
    cfg.banScoreThreshold = 100;
    cfg.blackboxDumpDirectory = "/tmp";

    AntiCheatEngine engine(cfg);
    ASSERT_TRUE(engine.Initialize());
    ASSERT_EQ(engine.GetThreatScore(), 0);
    ASSERT_FALSE(engine.IsBanned());

    bool banCalled = false;
    std::string banReason;
    engine.SetBanCallback([&](const std::string& reason, uint32_t finalScore) {
        banCalled = true;
        banReason = reason;
        (void)finalScore;
    });

    // Fire detection 1 (Threat score 40)
    DetectionEvent ev1;
    ev1.type = DetectionType::SUSPICIOUS_PROCESS_DETECTED;
    ev1.severity = Severity::MEDIUM;
    ev1.threat_score = 40;
    ev1.details = "Suspicious process";
    engine.ProcessDetection(ev1);

    ASSERT_EQ(engine.GetThreatScore(), 40);
    ASSERT_FALSE(engine.IsBanned());
    ASSERT_FALSE(banCalled);

    // Fire detection 2 (Threat score 65 -> total 105 >= 100 threshold)
    DetectionEvent ev2;
    ev2.type = DetectionType::UNBACKED_EXECUTABLE_MEMORY;
    ev2.severity = Severity::HIGH;
    ev2.threat_score = 65;
    ev2.details = "Unbacked memory detected";
    engine.ProcessDetection(ev2);

    ASSERT_EQ(engine.GetThreatScore(), 105);
    ASSERT_TRUE(engine.IsBanned());
    ASSERT_TRUE(banCalled);
    ASSERT_EQ(banReason, "Unbacked memory detected");
}

TEST(Engine, FatalBanEnforcement) {
    EngineConfig cfg;
    cfg.enableHeartbeat = false;
    cfg.banScoreThreshold = 500;
    cfg.blackboxDumpDirectory = "/tmp";

    AntiCheatEngine engine(cfg);
    engine.Initialize();

    bool banCalled = false;
    engine.SetBanCallback([&](const std::string&, uint32_t) {
        banCalled = true;
    });

    // FATAL_BAN severity triggers immediate ban regardless of current threat score
    DetectionEvent ev;
    ev.type = DetectionType::ANTI_DEBUG_TRACER;
    ev.severity = Severity::FATAL_BAN;
    ev.threat_score = 100;
    ev.details = "Kernel debugger attached";
    engine.ProcessDetection(ev);

    ASSERT_TRUE(engine.IsBanned());
    ASSERT_TRUE(banCalled);
}

TEST(Engine, VanguardBanScreenConfigAndInvocation) {
    EngineConfig cfg;
    cfg.enableHeartbeat = false;
    cfg.banScoreThreshold = 100;
    cfg.showBanUi = true;
    cfg.terminateProcessOnBan = false;
    cfg.banUiExecutable = "/home/COSMOS/NoEscapeAC/tools/noescape_ban_ui.py";

    AntiCheatEngine engine(cfg);
    ASSERT_TRUE(engine.Initialize());
    ASSERT_TRUE(cfg.showBanUi);
    ASSERT_FALSE(cfg.terminateProcessOnBan);
    ASSERT_EQ(cfg.banUiExecutable, "/home/COSMOS/NoEscapeAC/tools/noescape_ban_ui.py");

    bool banFired = false;
    engine.SetBanCallback([&](const std::string&, uint32_t) {
        banFired = true;
    });

    DetectionEvent ev;
    ev.type = DetectionType::UNBACKED_EXECUTABLE_MEMORY;
    ev.severity = Severity::FATAL_BAN;
    ev.threat_score = 100;
    ev.details = "Simulated injection attack";
    engine.ProcessDetection(ev);

    ASSERT_TRUE(engine.IsBanned());
    ASSERT_TRUE(banFired);
}
