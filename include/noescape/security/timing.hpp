#pragma once

#include <chrono>
#include <optional>
#include <cstdint>
#include <mutex>
#include "noescape/core/types.hpp"

namespace noescape::security {

class TimingIntegrity {
public:
    static TimingIntegrity& Instance();

    // Calibrates baseline hardware cycles per millisecond
    bool Calibrate(uint32_t calibrationMs = 50);

    // Checks current delta ratio against baseline
    std::optional<core::DetectionEvent> CheckSpeedhack();

    // Directly evaluates a clock ratio delta for test verification of tightened thresholds
    std::optional<core::DetectionEvent> EvaluateRatioForTesting(double ratio, double elapsedMs = 50.0);

    double GetCyclesPerMs() const { std::lock_guard<std::mutex> l(mutex_); return cycles_per_ms_; }
    bool IsCalibrated() const { std::lock_guard<std::mutex> l(mutex_); return calibrated_; }

private:
    TimingIntegrity() = default;

    uint64_t ReadHardwareTsc() const;

    mutable std::mutex mutex_;
    bool CalibrateLocked(uint32_t calibrationMs);
    std::optional<core::DetectionEvent> EvaluateRatioInternal(double ratio, double elapsedMs);
    bool calibrated_{false};
    double cycles_per_ms_{0.0};
    uint64_t last_tsc_{0};
    std::chrono::steady_clock::time_point last_os_time_;
    uint32_t consecutive_anomalies_{0};
};

} // namespace noescape::security
