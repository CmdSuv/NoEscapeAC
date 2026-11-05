#pragma once

#include <vector>
#include <deque>
#include <optional>
#include <cstdint>
#include "noescape/core/types.hpp"

namespace noescape::kinematics {

struct AngleSample {
    float pitch{0.0f};      // Pitch in degrees [-89, 89]
    float yaw{0.0f};        // Yaw in degrees [-180, 180] or [0, 360]
    uint64_t timestamp_ms{0};
};

struct KinematicMetrics {
    float angular_velocity{0.0f};     // deg/s
    float angular_acceleration{0.0f}; // deg/s^2
    float angular_jerk{0.0f};         // deg/s^3
    float linearity_error{0.0f};      // Orthogonal deviation variance
    float velocity_variance{0.0f};    // Variance of velocity over window
};

class AimAnalyzer {
public:
    AimAnalyzer(size_t history_capacity = 64);

    // Records a new view angle observation
    std::optional<core::DetectionEvent> PushSample(float pitch, float yaw, uint64_t timestamp_ms);
    std::optional<core::DetectionEvent> PushSample(const AngleSample& sample);

    // Clears historical buffer (e.g. on teleport or round reset)
    void Reset();

    // Direct access to computed metrics of the current trajectory window
    KinematicMetrics ComputeCurrentMetrics() const;

    // Threshold setters for customization
    void SetSnapAngleThreshold(float deg) { snap_angle_threshold_ = deg; }
    void SetLinearityThreshold(float err) { linearity_threshold_ = err; }
    void SetMinSamplesForAnalysis(size_t n) { min_samples_ = n; }

private:
    std::deque<AngleSample> history_;
    size_t history_capacity_{64};
    size_t min_samples_{8};

    float snap_angle_threshold_{20.0f}; // Degrees in single tick
    float linearity_threshold_{0.005f}; // Max orthogonal variance for perfect line

    float NormalizeAngleDelta(float delta) const;
    float CalculateAngleDistance(const AngleSample& a, const AngleSample& b) const;

    std::optional<core::DetectionEvent> CheckInstantSnap();
    std::optional<core::DetectionEvent> CheckPerfectLinearity();
    std::optional<core::DetectionEvent> CheckArtificialSmoothing();
};

} // namespace noescape::kinematics
