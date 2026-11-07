#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <mutex>
#include "noescape/core/types.hpp"

namespace noescape::dma {

struct DmaProfile {
    double baseline_mean_cycles{0.0};
    double current_mean_cycles{0.0};
    double jitter_stddev{0.0};
    uint32_t spike_count{0};
    bool anomalous{false};
};

struct PciDeviceInfo {
    std::string device_id;
    std::string vendor_id;
    std::string description;
    bool is_suspicious{false};
};

enum class HardwareConfidenceLevel : uint8_t {
    KNOWN_LEGITIMATE = 0,
    BENIGN_DEV_HARDWARE = 0,
    TIMING_ANOMALY_ONLY = 1,
    SUSPICIOUS_CHARACTERISTICS = 2,
    SUSPICIOUS_BRIDGE_OR_FPGA = 2,
    KNOWN_CHEAT_HARDWARE = 3,
    CONFIRMED_TOOL_ARTIFACT = 4,
    CORROBORATED_DMA_EVIDENCE = 4
};

struct IommuStatusInfo {
    bool iommu_present{false};
    bool dma_remapping_enabled{false};
    bool dma_remapping_active{false};
    bool strict_mode{false};
    uint32_t isolated_group_count{0};
    std::string source{};
    std::string provider{};
};

class DmaDetector {
public:
    static DmaDetector& Instance();

    // Calibrate baseline memory bus latency
    bool Calibrate(size_t probe_size_kb = 4096, size_t iterations = 100);

    // Profile memory bus latency jitter to detect DMA memory bus polling / contention
    DmaProfile ProfileMemoryBusJitter(size_t iterations = 50);

    // Scan PCIe and USB bus for known FPGA / DMA Leech hardware
    std::vector<PciDeviceInfo> ScanHardwareDevices();

    // Check for LeechCore / shadow memory interfaces
    bool CheckLeechCoreArtifacts();

    // Inspects OS / hardware IOMMU (VT-d / AMD-Vi / Kernel DMA Protection) status
    IommuStatusInfo CheckIommuStatus();

    // Computes multi-signal hardware confidence classification
    HardwareConfidenceLevel EvaluateHardwareConfidence(
        const PciDeviceInfo& dev,
        bool has_leechcore_artifact,
        bool has_bus_jitter_anomaly
    ) const;

    HardwareConfidenceLevel EvaluateHardwareConfidence(
        const DmaProfile& jitter_profile,
        const std::vector<PciDeviceInfo>& devices,
        bool leechcore_present,
        const IommuStatusInfo& iommu_status
    ) const;

    static const char* ConfidenceLevelToString(HardwareConfidenceLevel level);

    // Runs a full DMA audit
    std::vector<core::DetectionEvent> PerformAudit();

    // Direct configuration of jitter threshold multiplier
    void SetAnomalyThreshold(double multiplier) { anomaly_multiplier_ = multiplier; }

private:
    DmaDetector();
    ~DmaDetector();

    std::vector<uint8_t> probe_buffer_;
    double baseline_mean_cycles_{0.0};
    double baseline_variance_{0.0};
    double anomaly_multiplier_{3.2};
    bool calibrated_{false};
    std::mutex mutex_;
    uint64_t MeasureBufferTraversal();
};

} // namespace noescape::dma
