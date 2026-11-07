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
    float polling_jitter_stddev_us{0.0f}; // Stddev of raw input intervals (us)
    float mean_reaction_time_ms{0.0f};    // Mean crosshair-to-fire delay (ms)
    uint32_t session_anomaly_count{0};    // Cumulative anomalies in current session
};

struct RawInputSample {
    uint64_t interval_us{0};
    int32_t dx{0};
    int32_t dy{0};
};

struct RecoilSample {
    float weapon_pitch{0.0f};
    float weapon_yaw{0.0f};
    float input_pitch{0.0f};
    float input_yaw{0.0f};
};

class AimAnalyzer {
public:
    AimAnalyzer(size_t history_capacity = 64);

    // Records a new view angle observation
    std::optional<core::DetectionEvent> PushSample(float pitch, float yaw, uint64_t timestamp_ms);
    std::optional<core::DetectionEvent> PushSample(const AngleSample& sample);

    // Raw mouse input timing & quantization telemetry (for synthetic input / HID macro detection)
    std::optional<core::DetectionEvent> RecordRawInputSample(uint64_t interval_us, int32_t dx, int32_t dy);

    // Triggerbot reaction-time telemetry (crosshair target acquisition -> weapon fire)
    void RecordCrosshairTargetAcquire(uint64_t timestamp_ms);
    std::optional<core::DetectionEvent> RecordWeaponFire(uint64_t timestamp_ms);

    // Recoil compensation telemetry (weapon kick vs player counter-pull per shot)
    std::optional<core::DetectionEvent> RecordRecoilCompensation(
        float weapon_recoil_pitch, float weapon_recoil_yaw,
        float player_input_pitch, float player_input_yaw);

    // Clears historical buffer (e.g. on teleport or round reset)
    void Reset();
    size_t GetHistorySize() const { return history_.size(); }
    uint32_t GetSessionAnomalyCount() const { return session_anomaly_count_; }

    // Direct access to computed metrics of the current trajectory window
    KinematicMetrics ComputeCurrentMetrics() const;

    // Threshold setters for customization
    void SetSnapAngleThreshold(float deg) { snap_angle_threshold_ = deg; }
    void SetLinearityThreshold(float err) { linearity_threshold_ = err; }
    void SetMinSamplesForAnalysis(size_t n) { min_samples_ = n; }

private:
    std::deque<AngleSample> history_;
    std::deque<RawInputSample> raw_input_history_;
    std::deque<uint64_t> reaction_delays_ms_;
    std::deque<RecoilSample> recoil_history_;
    std::optional<uint64_t> last_target_acquire_ms_;

    size_t history_capacity_{64};
    size_t min_samples_{8};
    uint32_t session_anomaly_count_{0};

    float snap_angle_threshold_{20.0f}; // Degrees in single tick
    float linearity_threshold_{0.005f}; // Max orthogonal variance for perfect line

    float NormalizeAngleDelta(float delta) const;
    float CalculateAngleDistance(const AngleSample& a, const AngleSample& b) const;

    std::optional<core::DetectionEvent> CheckInstantSnap();
    std::optional<core::DetectionEvent> CheckPerfectLinearity();
    std::optional<core::DetectionEvent> CheckArtificialSmoothing();
    std::optional<core::DetectionEvent> CheckSyntheticInputTiming();
    std::optional<core::DetectionEvent> CheckTriggerbotTiming();
    std::optional<core::DetectionEvent> CheckRecoilAutomation();
};

} // namespace noescape::kinematics
