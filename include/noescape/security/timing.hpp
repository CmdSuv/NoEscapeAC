#pragma once

#include <chrono>
#include <optional>
#include <cstdint>
#include "noescape/core/types.hpp"

namespace noescape::security {

class TimingIntegrity {
public:
    static TimingIntegrity& Instance();

    // Calibrates baseline hardware cycles per millisecond
    bool Calibrate(uint32_t calibrationMs = 50);

    // Checks current delta ratio against baseline
    std::optional<core::DetectionEvent> CheckSpeedhack();

    double GetCyclesPerMs() const { return cycles_per_ms_; }
    bool IsCalibrated() const { return calibrated_; }

private:
    TimingIntegrity() = default;

    uint64_t ReadHardwareTsc() const;

    bool calibrated_{false};
    double cycles_per_ms_{0.0};
    uint64_t last_tsc_{0};
    std::chrono::steady_clock::time_point last_os_time_;
    uint32_t consecutive_anomalies_{0};
};

} // namespace noescape::security
