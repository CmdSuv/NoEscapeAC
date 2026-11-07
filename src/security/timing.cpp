#include "noescape/security/timing.hpp"
#include <thread>
#include <cmath>

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

namespace noescape::security {

TimingIntegrity& TimingIntegrity::Instance() {
    static TimingIntegrity* instance = new TimingIntegrity();
    return *instance;
}

uint64_t TimingIntegrity::ReadHardwareTsc() const {
#if defined(_MSC_VER) || defined(__x86_64__) || defined(__i386__)
    return __rdtsc();
#else
    // Fallback on ARM/other: use high-resolution hardware steady clock
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
#endif
}

bool TimingIntegrity::Calibrate(uint32_t calibrationMs) {
    std::lock_guard<std::mutex> lock(mutex_);
    return CalibrateLocked(calibrationMs);
}

bool TimingIntegrity::CalibrateLocked(uint32_t calibrationMs) {
    auto startOs = std::chrono::steady_clock::now();
    uint64_t startTsc = ReadHardwareTsc();

    std::this_thread::sleep_for(std::chrono::milliseconds(calibrationMs));

    auto endOs = std::chrono::steady_clock::now();
    uint64_t endTsc = ReadHardwareTsc();

    double elapsedMs = std::chrono::duration<double, std::milli>(endOs - startOs).count();
    if (elapsedMs <= 0.0 || endTsc <= startTsc) {
        return false;
    }

    cycles_per_ms_ = static_cast<double>(endTsc - startTsc) / elapsedMs;
    last_tsc_ = endTsc;
    last_os_time_ = endOs;
    calibrated_ = true;
    consecutive_anomalies_ = 0;
    return true;
}

std::optional<core::DetectionEvent> TimingIntegrity::CheckSpeedhack() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!calibrated_) {
        if (!CalibrateLocked(50)) return std::nullopt;
    }

    auto nowOs = std::chrono::steady_clock::now();
    uint64_t nowTsc = ReadHardwareTsc();

    double elapsedMs = std::chrono::duration<double, std::milli>(nowOs - last_os_time_).count();
    // Only verify if at least 15ms have elapsed to minimize quantization error
    if (elapsedMs < 15.0) {
        return std::nullopt;
    }

    // Check for negative delta / backwards time travel
    if (nowTsc < last_tsc_) {
        // Per-core TSC skew, VM migration and suspend/resume can all do this: re-baseline and
        // report as a moderate signal instead of an instant ban.
        last_tsc_ = nowTsc;
        last_os_time_ = nowOs;
        core::DetectionEvent ev;
        ev.type = core::DetectionType::SPEEDHACK_TIMING_DISCREPANCY;
        ev.severity = core::Severity::HIGH;
        ev.component = "TimingIntegrity::TSC";
        ev.details = "Hardware TSC jumped backwards (possible Anti-Tick / Rewind exploit)";
        ev.timestamp = static_cast<uint64_t>(time(nullptr));
        ev.threat_score = 40;
        return ev;
    }

    uint64_t deltaTsc = nowTsc - last_tsc_;
    double expectedCycles = cycles_per_ms_ * elapsedMs;
    double ratio = static_cast<double>(deltaTsc) / (expectedCycles > 0 ? expectedCycles : 1.0);

    last_tsc_ = nowTsc;
    last_os_time_ = nowOs;

    // A ratio significantly < 0.60 means OS time is ticking much faster than CPU cycles (Speedhack acceleration)
    // A ratio significantly > 1.60 means OS time was dilated / slowed down (Bullet-time or speedhack slowdown)
    if (ratio < 0.60 || ratio > 1.60) {
        consecutive_anomalies_++;
        // Require 2 consecutive anomalies to eliminate scheduling hiccups / context switch spikes
        if (consecutive_anomalies_ >= 2) {
            core::DetectionEvent ev;
            ev.type = core::DetectionType::SPEEDHACK_TIMING_DISCREPANCY;
            ev.severity = core::Severity::CRITICAL;
            ev.component = "TimingIntegrity::ClockRatio";
            ev.details = "Clock frequency deviation: ratio=" + std::to_string(ratio) +
                         " (elapsed_ms=" + std::to_string(elapsedMs) + ")";
            ev.timestamp = static_cast<uint64_t>(time(nullptr));
            ev.threat_score = 75;
            return ev;
        }
    } else {
        if (consecutive_anomalies_ > 0) consecutive_anomalies_--;
    }

    return std::nullopt;
}

} // namespace noescape::security
