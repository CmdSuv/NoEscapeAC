#include "tests/test_framework.hpp"
#include "noescape_sdk.h"
#include "noescape/core/types.hpp"
#include <string>
#include <thread>

static int g_last_violation_type = -1;
static int g_last_violation_score = 0;
static std::string g_last_violation_details;

static void SdkViolationCallback(int type, int score, const char* details) {
    g_last_violation_type = type;
    g_last_violation_score = score;
    if (details) g_last_violation_details = details;
}

TEST(SDK, DefaultConfiguration) {
    NoEscapeConfig cfg = NoEscape_GetDefaultConfig();
    ASSERT_EQ(cfg.ban_threshold, 100);
    ASSERT_FALSE(cfg.enforce_ban);
    ASSERT_TRUE(cfg.enable_anti_debug);
    ASSERT_TRUE(cfg.enable_overlay_detection);
    ASSERT_TRUE(cfg.enable_blackbox_dump);
    ASSERT_TRUE(cfg.enable_heartbeat);
    ASSERT_TRUE(cfg.require_multi_signal_corroboration);
    ASSERT_EQ(cfg.enforcement_mode, static_cast<int>(noescape::core::EnforcementMode::SERVER_SESSION_REJECT));
}

TEST(SDK, LifecycleAndIdempotency) {
    NoEscapeConfig cfg = NoEscape_GetDefaultConfig();
    cfg.enable_heartbeat = false;
    cfg.enable_anti_debug = false; // Keep quiet in test harness

    // Normal Init
    int rc = NoEscape_Init(&cfg);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(NoEscape_GetThreatScore(), 0);
    ASSERT_FALSE(NoEscape_IsBanned());

    // Idempotent re-initialization
    rc = NoEscape_Init(&cfg);
    ASSERT_EQ(rc, 0);

    // Shutdown
    NoEscape_Shutdown();
    ASSERT_EQ(NoEscape_GetThreatScore(), 0);
    ASSERT_FALSE(NoEscape_IsBanned());

    // Multiple shutdown calls are safe
    NoEscape_Shutdown();
}

TEST(SDK, PushMouseEventAndAimAnalysis) {
    NoEscapeConfig cfg = NoEscape_GetDefaultConfig();
    cfg.enable_heartbeat = false;
    cfg.enable_anti_debug = false;
    cfg.enforce_ban = false;

    ASSERT_EQ(NoEscape_Init(&cfg), 0);

    uint64_t timestamp = 1000;
    // Push smooth human-like mouse movement (constant small deltas)
    for (int i = 0; i < 15; ++i) {
        NoEscape_PushMouseEvent(0.5f, 0.3f, timestamp);
        timestamp += 16;
    }
    ASSERT_EQ(NoEscape_GetThreatScore(), 0);

    // Push instant snap aimbot: 45 degree flick in a single 16ms tick
    NoEscape_PushMouseEvent(45.0f, 15.0f, timestamp);
    timestamp += 16;
    // Followed by instant lock / dead stop (motion delta = 0.0)
    NoEscape_PushMouseEvent(0.0f, 0.0f, timestamp);

    // Threat score should increase due to snap detection
    ASSERT_GT(NoEscape_GetThreatScore(), 0);

    NoEscape_Shutdown();
}

TEST(SDK, ViolationCallbackInvocation) {
    g_last_violation_type = -1;
    g_last_violation_score = 0;
    g_last_violation_details.clear();

    NoEscape_SetViolationCallback(SdkViolationCallback);

    NoEscapeConfig cfg = NoEscape_GetDefaultConfig();
    cfg.enable_heartbeat = false;
    cfg.enable_anti_debug = false;
    cfg.ban_threshold = 50;
    cfg.enforce_ban = true;

    ASSERT_EQ(NoEscape_Init(&cfg), 0);

    // Trigger instant snap aimbot to fire a violation
    uint64_t t = 5000;
    for (int i = 0; i < 10; ++i) {
        NoEscape_PushMouseEvent(0.2f, 0.1f, t);
        t += 16;
    }
    NoEscape_PushMouseEvent(50.0f, 20.0f, t);
    t += 16;
    NoEscape_PushMouseEvent(0.0f, 0.0f, t);

    ASSERT_GT(NoEscape_GetThreatScore(), 0);
    // Explicitly verify the callback was dispatched with genuine detection type and score
    ASSERT_EQ(g_last_violation_type, static_cast<int>(noescape::core::DetectionType::KINEMATICS_AIMBOT_SNAP));
    ASSERT_GT(g_last_violation_score, 0);
    ASSERT_FALSE(g_last_violation_details.empty());

    NoEscape_Shutdown();
}

TEST(SDK, CppWrapperClientAPI) {
    NoEscapeConfig cfg = NoEscape_GetDefaultConfig();
    cfg.enable_heartbeat = false;
    cfg.enable_anti_debug = false;

    ASSERT_TRUE(noescape::sdk::Client::Init(&cfg));
    ASSERT_EQ(noescape::sdk::Client::GetThreatScore(), 0);
    ASSERT_FALSE(noescape::sdk::Client::IsBanned());

    noescape::sdk::Client::SetViewport(0, 0, 2560, 1440);
    noescape::sdk::Client::PushMouseEvent(1.0f, 2.0f, 100);
    noescape::sdk::Client::ResetInput();
    noescape::sdk::Client::Tick();

    noescape::sdk::Client::Shutdown();
}

TEST(SDK, ConcurrentMousePushing) {
    NoEscapeConfig cfg = NoEscape_GetDefaultConfig();
    cfg.enable_heartbeat = false;
    cfg.enable_anti_debug = false;
    cfg.enforce_ban = false;

    ASSERT_EQ(NoEscape_Init(&cfg), 0);

    std::vector<std::thread> threads;
    constexpr int kThreads = 4;
    constexpr int kIterations = 100;

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([t]() {
            uint64_t ts = 10000 + t * 5000;
            for (int i = 0; i < kIterations; ++i) {
                NoEscape_PushMouseEvent(0.05f, 0.02f, ts + i * 2);
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    NoEscape_Tick();
    ASSERT_FALSE(NoEscape_IsBanned());

    NoEscape_Shutdown();
}

TEST(SDK, ResetInputLifecycle) {
    NoEscapeConfig cfg = NoEscape_GetDefaultConfig();
    cfg.enable_heartbeat = false;
    cfg.enable_anti_debug = false;

    ASSERT_EQ(NoEscape_Init(&cfg), 0);
    NoEscape_PushMouseEvent(10.0f, 5.0f, 1000);
    NoEscape_ResetInput();
    ASSERT_EQ(NoEscape_GetThreatScore(), 0);
    NoEscape_Shutdown();
}
