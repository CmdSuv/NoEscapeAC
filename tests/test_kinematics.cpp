#include "tests/test_framework.hpp"
#include "noescape/kinematics/aim_analyzer.hpp"
#include <cmath>

using namespace noescape::kinematics;
using namespace noescape::core;

TEST(Kinematics, NormalHumanMovement) {
    AimAnalyzer analyzer(64);
    uint64_t t = 1000;

    // Simulate natural human movement: curve with tremor and acceleration/deceleration
    float p = 0.0f;
    float y = 0.0f;

    for (int i = 0; i < 20; ++i) {
        float progress = static_cast<float>(i) / 20.0f;
        // Human bell curve velocity
        float vel = std::sin(progress * 3.14159f) * 1.5f;
        // Biological micro-tremor
        float tremor = (i % 2 == 0 ? 0.08f : -0.07f);

        p += vel * 0.4f + tremor;
        y += vel * 0.8f + (tremor * 1.2f);
        t += 16; // 60 FPS tick

        auto ev = analyzer.PushSample(p, y, t);
        ASSERT_FALSE(ev.has_value());
    }
}

TEST(Kinematics, InstantSnapAimbot) {
    AimAnalyzer analyzer(64);
    uint64_t t = 1000;

    // Steady crosshair at target A
    analyzer.PushSample(0.0f, 0.0f, t);
    t += 16;
    analyzer.PushSample(0.1f, 0.1f, t);
    t += 16;

    // Aimbot silent snap: 45 degree flick in a single 16ms frame!
    analyzer.PushSample(15.0f, 42.0f, t);
    t += 16;

    // Followed by instant lock / dead stop (delta = 0.0)
    auto ev = analyzer.PushSample(15.0f, 42.0f, t);
    ASSERT_TRUE(ev.has_value());
    ASSERT_EQ(ev->type, DetectionType::KINEMATICS_AIMBOT_SNAP);
}

TEST(Kinematics, RoboticPerfectLinearity) {
    AimAnalyzer analyzer(64);
    analyzer.SetLinearityThreshold(0.005f);
    analyzer.SetMinSamplesForAnalysis(8);

    uint64_t t = 1000;
    // Pure mathematical line with zero perpendicular noise (y = 2.0 * p)
    for (int i = 0; i < 12; ++i) {
        float p = static_cast<float>(i) * 1.5f;      // 0 to 16.5 deg
        float y = p * 2.0f;                          // Exactly on line
        t += 16;

        auto ev = analyzer.PushSample(p, y, t);
        if (i >= 8 && ev.has_value()) {
            ASSERT_EQ(ev->type, DetectionType::KINEMATICS_PERFECT_LINEARITY);
            return;
        }
    }
}

TEST(Kinematics, ArtificialSmoothingConstantVelocity) {
    AimAnalyzer analyzer(64);
    analyzer.SetMinSamplesForAnalysis(8);

    uint64_t t = 1000;
    // Exact constant velocity: exactly 1.5 degrees per 16ms tick without any variance
    float p = 0.0f;
    float y = 0.0f;

    for (int i = 0; i < 15; ++i) {
        p += 1.0f;
        y += 1.0f;
        t += 16;

        auto ev = analyzer.PushSample(p, y, t);
        if (i >= 8 && ev.has_value()) {
            ASSERT_EQ(ev->type, DetectionType::KINEMATICS_ARTIFICIAL_SMOOTHING);
            return;
        }
    }
}

TEST(Kinematics, NonFiniteAndMalformedInputs) {
    AimAnalyzer analyzer(64);
    uint64_t t = 1000;

    // NAN values should be safely rejected without crashing or infinite loop
    auto evNan1 = analyzer.PushSample(NAN, 10.0f, t);
    ASSERT_FALSE(evNan1.has_value());

    auto evNan2 = analyzer.PushSample(10.0f, NAN, t);
    ASSERT_FALSE(evNan2.has_value());

    // INFINITY values should be rejected and never cause an infinite loop in NormalizeAngleDelta
    auto evInf = analyzer.PushSample(INFINITY, -INFINITY, t);
    ASSERT_FALSE(evInf.has_value());

    // Extreme corrupt pitch (> 180 deg)
    auto evCorrupt = analyzer.PushSample(9999.0f, 0.0f, t);
    ASSERT_FALSE(evCorrupt.has_value());
}

TEST(Kinematics, ComputeCurrentMetricsFull) {
    AimAnalyzer analyzer(64);
    uint64_t t = 1000;

    // Push 6 accelerating points
    for (int i = 0; i < 6; ++i) {
        float angle = static_cast<float>(i * i) * 1.5f;
        analyzer.PushSample(angle, angle * 1.2f, t);
        t += 20;
    }

    auto metrics = analyzer.ComputeCurrentMetrics();
    ASSERT_GT(metrics.angular_velocity, 0.0f);
    ASSERT_GT(metrics.angular_acceleration, 0.0f);
    ASSERT_TRUE(std::isfinite(metrics.angular_jerk));
    ASSERT_TRUE(std::isfinite(metrics.linearity_error));
    ASSERT_TRUE(std::isfinite(metrics.velocity_variance));
}

TEST(Kinematics, SubMillisecondMousePolling) {
    AimAnalyzer analyzer(64);
    uint64_t t = 1000;

    // Multiple samples arriving at the same timestamp (high polling rate mouse)
    auto ev1 = analyzer.PushSample(1.0f, 2.0f, t);
    auto ev2 = analyzer.PushSample(1.2f, 2.4f, t); // Same timestamp_ms
    auto ev3 = analyzer.PushSample(1.4f, 2.8f, t); // Same timestamp_ms

    ASSERT_FALSE(ev1.has_value());
    ASSERT_FALSE(ev2.has_value());
    ASSERT_FALSE(ev3.has_value());
}

TEST(Kinematics, PhaseSpaceAngularCuspDetection) {
    AimAnalyzer analyzer(64);
    uint64_t t = 1000;

    // Sample 0: origin
    analyzer.PushSample(0.0f, 0.0f, t);
    t += 16;

    // Sample 1: high speed sweep along yaw (500 deg/s)
    analyzer.PushSample(0.0f, 8.0f, t);
    t += 16;

    // Sample 2: instantaneous 180-degree velocity reversal at high speed (-437.5 deg/s)
    auto ev = analyzer.PushSample(0.0f, 1.0f, t);

    ASSERT_TRUE(ev.has_value());
    ASSERT_EQ(ev->type, DetectionType::KINEMATICS_AIMBOT_SNAP);
    ASSERT_NE(ev->details.find("Phase-space angular cusp"), std::string::npos);
}

TEST(Kinematics, ExGaussianTriggerbotReactionProfile) {
    AimAnalyzer analyzer(64);
    uint64_t t = 10000;

    std::optional<DetectionEvent> lastEv;
    for (int i = 0; i < 7; ++i) {
        analyzer.RecordCrosshairTargetAcquire(t);
        // Fixed triggerbot sleep: 60ms +/- 0.5ms (mu ~ 60ms, sigma < 1.0ms, tau < 1.0ms)
        uint64_t delay = 60 + (i % 2);
        auto ev = analyzer.RecordWeaponFire(t + delay);
        if (ev) lastEv = ev;
        t += 2000;
    }

    ASSERT_TRUE(lastEv.has_value());
    ASSERT_EQ(lastEv->type, DetectionType::KINEMATICS_TRIGGERBOT);
    ASSERT_NE(lastEv->details.find("ex-gaussian"), std::string::npos);
}

TEST(Kinematics, FlashHoganMinimumJerkViolation) {
    AimAnalyzer analyzer(64);
    uint64_t t = 1000;

    float yawAngles[] = {0.0f, 0.1f, 0.3f, 0.5f, 2.8f, 3.0f, 3.2f, 3.5f, 7.8f, 8.0f, 8.6f};
    std::optional<DetectionEvent> caught;
    for (float yaw : yawAngles) {
        auto ev = analyzer.PushSample(0.0f, yaw, t);
        if (ev) caught = ev;
        t += 40;
    }

    ASSERT_TRUE(caught.has_value());
    ASSERT_EQ(caught->type, DetectionType::KINEMATICS_AIMBOT_SNAP);
    ASSERT_NE(caught->details.find("minimum-jerk violation"), std::string::npos);
}

