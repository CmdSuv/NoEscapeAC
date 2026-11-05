#include "tests/test_framework.hpp"
#include "noescape/dma/dma_detector.hpp"

using namespace noescape::dma;
using namespace noescape::core;

TEST(DMA, CalibrationAndJitterProfiling) {
    auto& detector = DmaDetector::Instance();

    // Fast calibration with 512KB probe buffer
    bool calibOk = detector.Calibrate(512, 15);
    ASSERT_TRUE(calibOk);

    auto profile = detector.ProfileMemoryBusJitter(15);
    ASSERT_GT(profile.baseline_mean_cycles, 0.0);
    ASSERT_GT(profile.current_mean_cycles, 0.0);
    ASSERT_TRUE(profile.jitter_stddev >= 0.0);
}

TEST(DMA, HardwareDeviceScan) {
    auto& detector = DmaDetector::Instance();
    auto devices = detector.ScanHardwareDevices();
    // Scan completes cleanly on the host system
    for (const auto& dev : devices) {
        ASSERT_FALSE(dev.vendor_id.empty());
    }
}
