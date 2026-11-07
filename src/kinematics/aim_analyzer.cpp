#include "noescape/kinematics/aim_analyzer.hpp"
#include <cmath>
#include <numeric>
#include <sstream>
#include <ctime>

namespace noescape::kinematics {

AimAnalyzer::AimAnalyzer(size_t history_capacity)
    : history_capacity_(history_capacity < 16 ? 16 : history_capacity) {}

void AimAnalyzer::Reset() {
    history_.clear();
    raw_input_history_.clear();
    reaction_delays_ms_.clear();
    recoil_history_.clear();
    last_target_acquire_ms_.reset();
    session_anomaly_count_ = 0;
}

float AimAnalyzer::NormalizeAngleDelta(float delta) const {
    if (!std::isfinite(delta)) return 0.0f;
    delta = std::fmod(delta, 360.0f);
    if (delta > 180.0f) delta -= 360.0f;
    if (delta < -180.0f) delta += 360.0f;
    return delta;
}

float AimAnalyzer::CalculateAngleDistance(const AngleSample& a, const AngleSample& b) const {
    float dp = b.pitch - a.pitch;
    float dy = NormalizeAngleDelta(b.yaw - a.yaw);
    return std::sqrt(dp * dp + dy * dy);
}

std::optional<core::DetectionEvent> AimAnalyzer::PushSample(float pitch, float yaw, uint64_t timestamp_ms) {
    return PushSample(AngleSample{pitch, yaw, timestamp_ms});
}

std::optional<core::DetectionEvent> AimAnalyzer::PushSample(const AngleSample& sample) {
    if (!std::isfinite(sample.pitch) || !std::isfinite(sample.yaw)) {
        return std::nullopt;
    }
    if (std::abs(sample.pitch) > 180.0f) {
        return std::nullopt;
    }

    AngleSample s = sample;
    if (!history_.empty()) {
        if (s.timestamp_ms < history_.back().timestamp_ms) {
            if (history_.back().timestamp_ms - s.timestamp_ms < 1000) {
                // Minor out-of-order sample: drop it
                return std::nullopt;
            }
            // Clock reset (level load / timer restart): start a fresh trajectory instead of
            // silently discarding every future sample.
            history_.clear();
        } else if (s.timestamp_ms - history_.back().timestamp_ms > 500) {
            // Long gap (pause, alt-tab, respawn, camera cut): trajectories must not span it
            history_.clear();
        }
    }
    if (!history_.empty()) {
        if (s.timestamp_ms == history_.back().timestamp_ms) {
            // High-polling rate sub-millisecond mouse event: assign micro-increment
            s.timestamp_ms = history_.back().timestamp_ms + 1;
        }
    }

    history_.push_back(s);
    if (history_.size() > history_capacity_) {
        history_.pop_front();
    }

    if (history_.size() < 3) {
        return std::nullopt;
    }

    auto recordAndPromote = [this](std::optional<core::DetectionEvent> ev) -> std::optional<core::DetectionEvent> {
        if (!ev) return std::nullopt;
        ++session_anomaly_count_;
        if (session_anomaly_count_ >= 5) {
            ev->confidence = core::ConfidenceLevel::HIGH;
        } else if (session_anomaly_count_ >= 3) {
            ev->confidence = core::ConfidenceLevel::MEDIUM;
        } else {
            ev->confidence = core::ConfidenceLevel::LOW;
        }
        return ev;
    };

    // Check 1: Instant Snap (Silent Aim / Instant Flick)
    auto snapEvent = CheckInstantSnap();
    if (snapEvent) return recordAndPromote(snapEvent);

    // Checks requiring a longer trajectory window
    if (history_.size() >= min_samples_) {
        // Check 2: Perfect Linearity
        auto linearEvent = CheckPerfectLinearity();
        if (linearEvent) return recordAndPromote(linearEvent);

        // Check 3: Artificial Smoothing
        auto smoothEvent = CheckArtificialSmoothing();
        if (smoothEvent) return recordAndPromote(smoothEvent);
    }

    return std::nullopt;
}

std::optional<core::DetectionEvent> AimAnalyzer::CheckInstantSnap() {
    size_t n = history_.size();
    if (n < 3) return std::nullopt;

    const auto& s0 = history_[n - 3];
    const auto& s1 = history_[n - 2];
    const auto& s2 = history_[n - 1];

    float dt1 = static_cast<float>(s1.timestamp_ms - s0.timestamp_ms) / 1000.0f;
    float dt2 = static_cast<float>(s2.timestamp_ms - s1.timestamp_ms) / 1000.0f;

    if (dt1 <= 0.0f || dt2 <= 0.0f) return std::nullopt;

    float dist1 = CalculateAngleDistance(s0, s1);
    float dist2 = CalculateAngleDistance(s1, s2);

    float velocity1 = dist1 / dt1; // deg/s
    float velocity2 = dist2 / dt2; // deg/s

    // Condition: Massive angular flick (e.g. >20 deg) in <= 35ms (1-2 ticks)
    // followed immediately by near-complete freeze (< 1.0 deg) or massive velocity deceleration (> 85%)
    // Ignore dead stops caused by game engine pitch clamping at +/-89 deg boundaries
    bool isPitchClamped = (std::abs(s1.pitch) >= 88.0f && std::abs(s2.pitch) >= 88.0f);
    if (isPitchClamped && std::abs(NormalizeAngleDelta(s1.yaw - s0.yaw)) < 5.0f) {
        return std::nullopt;
    }

    bool deadStop = (dist2 < 1.0f);
    bool massiveDecel = (velocity2 < velocity1 * 0.15f);
    if (dist1 >= snap_angle_threshold_ && dt1 <= 0.035f && (deadStop || massiveDecel) && velocity1 > 700.0f) {
        float jerk = (velocity2 - velocity1) / (dt2 > 0.0f ? dt2 : 0.01f);

        core::DetectionEvent ev;
        ev.type = core::DetectionType::KINEMATICS_AIMBOT_SNAP;
        ev.severity = core::Severity::HIGH; // a single frame-paced flick-and-stop is plausible for humans
        ev.component = "Kinematics::SnapDetector";

        std::ostringstream ss;
        ss << "Instantaneous non-human angular snap: delta=" << dist1 << " deg in "
           << (dt1 * 1000.0f) << " ms (velocity=" << velocity1 << " deg/s, dead stop delta="
           << dist2 << " deg, jerk=" << jerk << " deg/s^3)";
        ev.details = ss.str();
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 60;
        return ev;
    }

    return std::nullopt;
}

std::optional<core::DetectionEvent> AimAnalyzer::CheckPerfectLinearity() {
    size_t n = history_.size();
    if (n < min_samples_) return std::nullopt;

    const auto& start = history_[n - min_samples_];
    const auto& end = history_.back();

    float totalDist = CalculateAngleDistance(start, end);
    // Only analyze sustained movements of at least 10 degrees
    if (totalDist < 10.0f) return std::nullopt;

    // Vector from start to end in 2D angle space
    float vP = end.pitch - start.pitch;
    float vY = NormalizeAngleDelta(end.yaw - start.yaw);
    float lineLenSq = vP * vP + vY * vY;

    if (lineLenSq < 1.0f) return std::nullopt;

    // Pure horizontal/vertical sweeps (gamepad stick, low-sens mouse panning) are trivially "linear"
    // for humans; only diagonal trajectories carry signal.
    if (std::min(std::abs(vP), std::abs(vY)) < 1.0f) return std::nullopt;

    std::vector<float> perpDists;
    perpDists.reserve(min_samples_);

    float maxPerp = 0.0f;
    for (size_t i = n - min_samples_; i < n; ++i) {
        const auto& pt = history_[i];
        float wP = pt.pitch - start.pitch;
        float wY = NormalizeAngleDelta(pt.yaw - start.yaw);

        // Perpendicular distance = |v x w| / |v|
        float cross = std::abs(vP * wY - vY * wP);
        float dPerp = cross / std::sqrt(lineLenSq);

        perpDists.push_back(dPerp);
        if (dPerp > maxPerp) maxPerp = dPerp;
    }

    // Variance of perpendicular distances
    double meanPerp = std::accumulate(perpDists.begin(), perpDists.end(), 0.0) / perpDists.size();
    double varPerp = 0.0;
    for (float d : perpDists) {
        double diff = d - meanPerp;
        varPerp += diff * diff;
    }
    varPerp /= perpDists.size();

    // Robotic linear aimbot exhibits sub-millidegree variance across all trajectory points
    if (varPerp < linearity_threshold_ && maxPerp < 0.10f) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::KINEMATICS_PERFECT_LINEARITY;
        ev.severity = core::Severity::HIGH;
        ev.component = "Kinematics::LinearityAnalyzer";

        std::ostringstream ss;
        ss << "Unnatural robotic linearity detected: total_displacement=" << totalDist
           << " deg, orthogonal_variance=" << varPerp
           << ", max_deviation=" << maxPerp << " deg";
        ev.details = ss.str();
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 60;
        return ev;
    }

    return std::nullopt;
}

std::optional<core::DetectionEvent> AimAnalyzer::CheckArtificialSmoothing() {
    size_t n = history_.size();
    if (n < min_samples_) return std::nullopt;

    std::vector<float> velocities;
    velocities.reserve(min_samples_ - 1);

    float totalMovement = 0.0f;
    for (size_t i = n - min_samples_ + 1; i < n; ++i) {
        const auto& prev = history_[i - 1];
        const auto& curr = history_[i];

        float dt = static_cast<float>(curr.timestamp_ms - prev.timestamp_ms) / 1000.0f;
        if (dt <= 0.0f) continue;

        float dist = CalculateAngleDistance(prev, curr);
        totalMovement += dist;
        velocities.push_back(dist / dt);
    }

    if (velocities.size() < 6 || totalMovement < 8.0f) {
        return std::nullopt;
    }
    {
        const auto& st = history_[n - min_samples_];
        float nP = history_.back().pitch - st.pitch;
        float nY = NormalizeAngleDelta(history_.back().yaw - st.yaw);
        if (std::min(std::abs(nP), std::abs(nY)) < 1.0f) return std::nullopt; // axis-aligned sweep
    }

    double meanVel = std::accumulate(velocities.begin(), velocities.end(), 0.0) / velocities.size();
    if (meanVel < 30.0) return std::nullopt; // Skip stationary or micro-adjustments

    double varVel = 0.0;
    for (float v : velocities) {
        double diff = v - meanVel;
        varVel += diff * diff;
    }
    varVel /= velocities.size();

    // Relative variance (standard deviation divided by mean)
    double relStdDev = std::sqrt(varVel) / meanVel;

    // If angular velocity is unnaturally constant across an 8-degree sweep (< 2% variance)
    if (relStdDev < 0.02) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::KINEMATICS_ARTIFICIAL_SMOOTHING;
        ev.severity = core::Severity::HIGH;
        ev.component = "Kinematics::SmoothAimbotFilter";

        std::ostringstream ss;
        ss << "Artificial constant-velocity aim smoothing detected: mean_vel=" << meanVel
           << " deg/s, relative_stddev=" << (relStdDev * 100.0) << "% over "
           << totalMovement << " deg";
        ev.details = ss.str();
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 80;
        return ev;
    }

    return std::nullopt;
}

KinematicMetrics AimAnalyzer::ComputeCurrentMetrics() const {
    KinematicMetrics m;
    size_t n = history_.size();
    if (n < 2) return m;

    const auto& s0 = history_[n - 2];
    const auto& s1 = history_[n - 1];

    float dt = static_cast<float>(s1.timestamp_ms - s0.timestamp_ms) / 1000.0f;
    if (dt > 0.0f) {
        float dist = CalculateAngleDistance(s0, s1);
        m.angular_velocity = dist / dt;
    }

    if (n >= 3) {
        const auto& s_prev = history_[n - 3];
        float dt_prev = static_cast<float>(s0.timestamp_ms - s_prev.timestamp_ms) / 1000.0f;
        if (dt_prev > 0.0f && dt > 0.0f) {
            float v_prev = CalculateAngleDistance(s_prev, s0) / dt_prev;
            m.angular_acceleration = (m.angular_velocity - v_prev) / dt;

            if (n >= 4) {
                const auto& s_prev2 = history_[n - 4];
                float dt_prev2 = static_cast<float>(s_prev.timestamp_ms - s_prev2.timestamp_ms) / 1000.0f;
                if (dt_prev2 > 0.0f) {
                    float v_prev2 = CalculateAngleDistance(s_prev2, s_prev) / dt_prev2;
                    float a_prev = (v_prev - v_prev2) / dt_prev;
                    m.angular_jerk = (m.angular_acceleration - a_prev) / dt;
                }
            }
        }
    }

    // Linearity and velocity variance over the recent window
    size_t windowSize = std::min(n, min_samples_);
    if (windowSize >= 3) {
        const auto& start = history_[n - windowSize];
        const auto& end = history_.back();
        float vP = end.pitch - start.pitch;
        float vY = const_cast<AimAnalyzer*>(this)->NormalizeAngleDelta(end.yaw - start.yaw);
        float lineLenSq = vP * vP + vY * vY;

        if (lineLenSq >= 1.0f) {
            double varSum = 0.0;
            double meanPerp = 0.0;
            std::vector<float> perps;
            perps.reserve(windowSize);
            float sqrtLen = std::sqrt(lineLenSq);

            for (size_t i = n - windowSize; i < n; ++i) {
                const auto& pt = history_[i];
                float wP = pt.pitch - start.pitch;
                float wY = const_cast<AimAnalyzer*>(this)->NormalizeAngleDelta(pt.yaw - start.yaw);
                float cross = std::abs(vP * wY - vY * wP);
                float dPerp = cross / sqrtLen;
                perps.push_back(dPerp);
                meanPerp += dPerp;
            }
            meanPerp /= windowSize;
            for (float d : perps) {
                double diff = d - meanPerp;
                varSum += diff * diff;
            }
            m.linearity_error = static_cast<float>(varSum / windowSize);
        }

        // Velocity variance
        std::vector<float> vels;
        vels.reserve(windowSize - 1);
        double velSum = 0.0;
        for (size_t i = n - windowSize + 1; i < n; ++i) {
            float segDt = static_cast<float>(history_[i].timestamp_ms - history_[i - 1].timestamp_ms) / 1000.0f;
            if (segDt > 0.0f) {
                float segV = CalculateAngleDistance(history_[i - 1], history_[i]) / segDt;
                vels.push_back(segV);
                velSum += segV;
            }
        }
        if (!vels.empty()) {
            double meanV = velSum / vels.size();
            double velVar = 0.0;
            for (float v : vels) {
                double diff = v - meanV;
                velVar += diff * diff;
            }
            m.velocity_variance = static_cast<float>(velVar / vels.size());
        }
    }

    if (raw_input_history_.size() >= 2) {
        double meanUs = 0.0;
        for (const auto& r : raw_input_history_) {
            meanUs += static_cast<double>(r.interval_us);
        }
        meanUs /= raw_input_history_.size();
        double varUs = 0.0;
        for (const auto& r : raw_input_history_) {
            double diff = static_cast<double>(r.interval_us) - meanUs;
            varUs += diff * diff;
        }
        m.polling_jitter_stddev_us = static_cast<float>(std::sqrt(varUs / raw_input_history_.size()));
    }

    if (!reaction_delays_ms_.empty()) {
        double sumMs = std::accumulate(reaction_delays_ms_.begin(), reaction_delays_ms_.end(), 0.0);
        m.mean_reaction_time_ms = static_cast<float>(sumMs / reaction_delays_ms_.size());
    }

    m.session_anomaly_count = session_anomaly_count_;
    return m;
}

std::optional<core::DetectionEvent> AimAnalyzer::RecordRawInputSample(
    uint64_t interval_us, int32_t dx, int32_t dy) {
    if (interval_us == 0 || interval_us > 1000000) return std::nullopt;
    if (dx == 0 && dy == 0) return std::nullopt;

    raw_input_history_.push_back(RawInputSample{interval_us, dx, dy});
    if (raw_input_history_.size() > history_capacity_) {
        raw_input_history_.pop_front();
    }

    return CheckSyntheticInputTiming();
}

std::optional<core::DetectionEvent> AimAnalyzer::CheckSyntheticInputTiming() {
    constexpr size_t kMinRawSamples = 16;
    if (raw_input_history_.size() < kMinRawSamples) return std::nullopt;

    size_t n = raw_input_history_.size();
    double sumUs = 0.0;
    size_t identicalDeltaCount = 0;

    for (size_t i = n - kMinRawSamples; i < n; ++i) {
        sumUs += static_cast<double>(raw_input_history_[i].interval_us);
        if (i > n - kMinRawSamples) {
            if (raw_input_history_[i].dx == raw_input_history_[i - 1].dx &&
                raw_input_history_[i].dy == raw_input_history_[i - 1].dy) {
                ++identicalDeltaCount;
            }
        }
    }

    double meanUs = sumUs / kMinRawSamples;
    if (meanUs < 100.0) return std::nullopt;

    double varUs = 0.0;
    for (size_t i = n - kMinRawSamples; i < n; ++i) {
        double diff = static_cast<double>(raw_input_history_[i].interval_us) - meanUs;
        varUs += diff * diff;
    }
    double stddevUs = std::sqrt(varUs / kMinRawSamples);

    // Synthetic software timers / macro loops produce near-zero interval jitter (< 1.5 us)
    // combined with quantized identical step deltas across >= 85% of samples
    if (stddevUs < 1.5 && identicalDeltaCount >= (kMinRawSamples - 3)) {
        ++session_anomaly_count_;
        core::DetectionEvent ev;
        ev.type = core::DetectionType::KINEMATICS_SYNTHETIC_INPUT;
        ev.severity = core::Severity::MEDIUM;
        ev.component = "Kinematics::SyntheticInputDetector";
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 45;
        ev.confidence = core::ConfidenceLevel::MEDIUM;

        std::ostringstream ss;
        ss << "Synthetic quantized mouse input stream detected: interval_mean=" << meanUs
           << " us, jitter_stddev=" << stddevUs << " us, identical_step_ratio="
           << identicalDeltaCount << "/" << (kMinRawSamples - 1);
        ev.details = ss.str();
        return ev;
    }

    return std::nullopt;
}

void AimAnalyzer::RecordCrosshairTargetAcquire(uint64_t timestamp_ms) {
    last_target_acquire_ms_ = timestamp_ms;
}

std::optional<core::DetectionEvent> AimAnalyzer::RecordWeaponFire(uint64_t timestamp_ms) {
    if (!last_target_acquire_ms_.has_value()) return std::nullopt;
    uint64_t acquire_ms = *last_target_acquire_ms_;
    last_target_acquire_ms_.reset();

    if (timestamp_ms < acquire_ms) return std::nullopt;
    uint64_t delay_ms = timestamp_ms - acquire_ms;
    // Ignore pre-fires or engagements longer than 1.5 seconds after initial target acquisition
    if (delay_ms > 1500) return std::nullopt;

    reaction_delays_ms_.push_back(delay_ms);
    if (reaction_delays_ms_.size() > 32) {
        reaction_delays_ms_.pop_front();
    }

    return CheckTriggerbotTiming();
}

std::optional<core::DetectionEvent> AimAnalyzer::CheckTriggerbotTiming() {
    constexpr size_t kMinTriggerSamples = 6;
    if (reaction_delays_ms_.size() < kMinTriggerSamples) return std::nullopt;

    size_t n = reaction_delays_ms_.size();
    double sum = 0.0;
    for (size_t i = n - kMinTriggerSamples; i < n; ++i) {
        sum += static_cast<double>(reaction_delays_ms_[i]);
    }
    double meanMs = sum / kMinTriggerSamples;

    double var = 0.0;
    for (size_t i = n - kMinTriggerSamples; i < n; ++i) {
        double diff = static_cast<double>(reaction_delays_ms_[i]) - meanMs;
        var += diff * diff;
    }
    double stddevMs = std::sqrt(var / kMinTriggerSamples);

    // Human visual reaction times average 150-250ms with >= 12ms standard deviation.
    // Triggerbots either fire sub-45ms consistently or use a fixed sleep timer (e.g. 60ms +/- 2ms).
    if (meanMs < 45.0 || (meanMs < 95.0 && stddevMs < 3.0)) {
        ++session_anomaly_count_;
        core::DetectionEvent ev;
        ev.type = core::DetectionType::KINEMATICS_TRIGGERBOT;
        ev.severity = core::Severity::HIGH;
        ev.component = "Kinematics::TriggerbotAnalyzer";
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 55;
        ev.confidence = core::ConfidenceLevel::MEDIUM;

        std::ostringstream ss;
        ss << "Automated triggerbot reaction profile over " << kMinTriggerSamples
           << " engagements: mean_delay=" << meanMs << " ms, stddev=" << stddevMs << " ms";
        ev.details = ss.str();
        return ev;
    }

    return std::nullopt;
}

std::optional<core::DetectionEvent> AimAnalyzer::RecordRecoilCompensation(
    float weapon_recoil_pitch, float weapon_recoil_yaw,
    float player_input_pitch, float player_input_yaw) {
    if (!std::isfinite(weapon_recoil_pitch) || !std::isfinite(weapon_recoil_yaw) ||
        !std::isfinite(player_input_pitch) || !std::isfinite(player_input_yaw)) {
        return std::nullopt;
    }
    // Only record non-trivial weapon kick events
    float kickMag = std::sqrt(weapon_recoil_pitch * weapon_recoil_pitch +
                              weapon_recoil_yaw * weapon_recoil_yaw);
    if (kickMag < 0.25f) return std::nullopt;

    recoil_history_.push_back(RecoilSample{
        weapon_recoil_pitch, weapon_recoil_yaw,
        player_input_pitch, player_input_yaw
    });
    if (recoil_history_.size() > 32) {
        recoil_history_.pop_front();
    }

    return CheckRecoilAutomation();
}

std::optional<core::DetectionEvent> AimAnalyzer::CheckRecoilAutomation() {
    constexpr size_t kMinRecoilSamples = 10;
    if (recoil_history_.size() < kMinRecoilSamples) return std::nullopt;

    size_t n = recoil_history_.size();
    double totalResidualSq = 0.0;
    double totalKickSq = 0.0;

    for (size_t i = n - kMinRecoilSamples; i < n; ++i) {
        const auto& s = recoil_history_[i];
        // Ideal counter-recoil is player_input == -weapon_recoil
        double resPitch = static_cast<double>(s.weapon_pitch + s.input_pitch);
        double resYaw = static_cast<double>(s.weapon_yaw + s.input_yaw);
        totalResidualSq += (resPitch * resPitch + resYaw * resYaw);
        totalKickSq += (static_cast<double>(s.weapon_pitch) * s.weapon_pitch +
                        static_cast<double>(s.weapon_yaw) * s.weapon_yaw);
    }

    if (totalKickSq < 1.0) return std::nullopt;
    double meanResidualSq = totalResidualSq / kMinRecoilSamples;
    double cancellationRatio = 1.0 - std::sqrt(totalResidualSq / totalKickSq);

    // Automated recoil scripts cancel > 98.5% of both vertical and horizontal kick with near-zero residual error
    if (cancellationRatio > 0.985 && meanResidualSq < 0.002) {
        ++session_anomaly_count_;
        core::DetectionEvent ev;
        ev.type = core::DetectionType::KINEMATICS_RECOIL_AUTOMATION;
        ev.severity = core::Severity::MEDIUM;
        ev.component = "Kinematics::RecoilAnalyzer";
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 50;
        ev.confidence = core::ConfidenceLevel::MEDIUM;

        std::ostringstream ss;
        ss << "Deterministic recoil compensation script detected over " << kMinRecoilSamples
           << " shots: cancellation=" << (cancellationRatio * 100.0)
           << "%, mean_residual_sq=" << meanResidualSq;
        ev.details = ss.str();
        return ev;
    }

    return std::nullopt;
}

} // namespace noescape::kinematics
