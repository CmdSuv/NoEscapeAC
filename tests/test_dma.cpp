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

TEST(DMA, IommuStatusAndConfidenceClassification) {
    auto& detector = DmaDetector::Instance();
    auto iommu = detector.CheckIommuStatus();
    // Query completes cleanly on Linux host
    ASSERT_TRUE(iommu.source.empty() || !iommu.source.empty());

    PciDeviceInfo benign_dev{"0x10de", "0x2484", "NVIDIA GeForce RTX 3070", false};
    auto conf1 = detector.EvaluateHardwareConfidence(benign_dev, false, false);
    ASSERT_EQ(conf1, HardwareConfidenceLevel::BENIGN_DEV_HARDWARE);

    PciDeviceInfo suspicious_fpga{"0x10ee", "0x7021", "Xilinx Artix-7 PCIe FPGA", true};
    auto conf2 = detector.EvaluateHardwareConfidence(suspicious_fpga, false, false);
    ASSERT_EQ(conf2, HardwareConfidenceLevel::SUSPICIOUS_BRIDGE_OR_FPGA);

    auto conf3 = detector.EvaluateHardwareConfidence(suspicious_fpga, false, true);
    ASSERT_EQ(conf3, HardwareConfidenceLevel::KNOWN_CHEAT_HARDWARE);

    auto conf4 = detector.EvaluateHardwareConfidence(suspicious_fpga, true, false);
    ASSERT_EQ(conf4, HardwareConfidenceLevel::CONFIRMED_TOOL_ARTIFACT);

    ASSERT_TRUE(std::string(DmaDetector::ConfidenceLevelToString(conf1)).find("BENIGN") != std::string::npos);
    ASSERT_TRUE(std::string(DmaDetector::ConfidenceLevelToString(conf4)).find("CONFIRMED") != std::string::npos);
}
