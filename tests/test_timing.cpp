#include "tests/test_framework.hpp"
#include "noescape/security/timing.hpp"

using namespace noescape::security;

TEST(Timing, CalibrationAndCheck) {
    auto& timing = TimingIntegrity::Instance();
    bool ok = timing.Calibrate(20);
    ASSERT_TRUE(ok);
    ASSERT_TRUE(timing.IsCalibrated());
    ASSERT_GT(timing.GetCyclesPerMs(), 0.0);

    // Normal progression should not detect any speedhack
    auto ev = timing.CheckSpeedhack();
    ASSERT_FALSE(ev.has_value());
}
