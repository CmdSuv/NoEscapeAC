#include "noescape/server/server_integration.hpp"

#include <cmath>
#include <algorithm>
#include <sstream>
#include <ctime>

namespace noescape::server {

void ServerEspFilter::SetVisibilityAdapter(std::shared_ptr<IAuthoritativeVisibilityAdapter> adapter) {
    std::lock_guard<std::mutex> lock(mutex_);
    visibility_adapter_ = std::move(adapter);
}

std::shared_ptr<IAuthoritativeVisibilityAdapter> ServerEspFilter::GetVisibilityAdapter() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return visibility_adapter_;
}

void ServerEspFilter::AddOccluder(const OccluderBox& box) {
    std::lock_guard<std::mutex> lock(mutex_);
    OccluderBox normalized = box;
    if (normalized.min_x > normalized.max_x) std::swap(normalized.min_x, normalized.max_x);
    if (normalized.min_y > normalized.max_y) std::swap(normalized.min_y, normalized.max_y);
    if (normalized.min_z > normalized.max_z) std::swap(normalized.min_z, normalized.max_z);
    occluders_.push_back(normalized);
}

void ServerEspFilter::ClearOccluders() {
    std::lock_guard<std::mutex> lock(mutex_);
    occluders_.clear();
}

size_t ServerEspFilter::GetOccluderCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return occluders_.size();
}

bool ServerEspFilter::HasOcclusionData() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !occluders_.empty() || (visibility_adapter_ != nullptr);
}

bool ServerEspFilter::SegmentIntersectsAabb(
    float x0, float y0, float z0,
    float x1, float y1, float z1,
    const OccluderBox& box) {
    float dx = x1 - x0;
    float dy = y1 - y0;
    float dz = z1 - z0;

    float tmin = 0.0f;
    float tmax = 1.0f;

    auto clipAxis = [&](float start, float dir, float bmin, float bmax) -> bool {
        if (std::abs(dir) < 1e-6f) {
            return (start >= bmin && start <= bmax);
        }
        float invD = 1.0f / dir;
        float t0 = (bmin - start) * invD;
        float t1 = (bmax - start) * invD;
        if (t0 > t1) std::swap(t0, t1);
        tmin = std::max(tmin, t0);
        tmax = std::min(tmax, t1);
        return tmin <= tmax;
    };

    if (!clipAxis(x0, dx, box.min_x, box.max_x)) return false;
    if (!clipAxis(y0, dy, box.min_y, box.max_y)) return false;
    if (!clipAxis(z0, dz, box.min_z, box.max_z)) return false;

    return tmin <= tmax && tmax >= 0.0f && tmin <= 1.0f;
}

bool ServerEspFilter::IsLineOfSightOccluded(
    const ObserverState& observer,
    const TargetEntityState& target) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (occluders_.empty() && !visibility_adapter_) return false;

    // Test center-of-mass plus 4 lateral/vertical bounding offsets to prevent pop-in artifacts on corner peeks
    const float r = std::max(0.0f, target.bounding_radius);
    const float sampleOffsets[5][3] = {
        {0.0f, 0.0f, 0.0f},
        {r, 0.0f, 0.0f},
        {-r, 0.0f, 0.0f},
        {0.0f, r, 0.0f},
        {0.0f, -r, 0.0f}
    };

    for (const auto& offset : sampleOffsets) {
        float tx = target.x + offset[0];
        float ty = target.y + offset[1];
        float tz = target.z + offset[2];

        bool rayBlocked = false;
        if (visibility_adapter_) {
            rayBlocked = visibility_adapter_->LineOfSightBlocked(
                observer.x, observer.y, observer.z, tx, ty, tz, false);
        } else {
            for (const auto& box : occluders_) {
                if (SegmentIntersectsAabb(observer.x, observer.y, observer.z, tx, ty, tz, box)) {
                    rayBlocked = true;
                    break;
                }
            }
        }
        if (!rayBlocked) {
            // At least one point on the target's bounding volume has clear line-of-sight
            return false;
        }
    }

    return true;
}

ReplicationDecision ServerEspFilter::EvaluateEntityReplication(
    const ObserverState& observer,
    const TargetEntityState& target) const {
    ReplicationDecision decision;

    float dx = target.x - observer.x;
    float dy = target.y - observer.y;
    float dz = target.z - observer.z;
    float dist = std::sqrt(dx * dx + dy * dy + dz * dz);

    if (dist > max_replication_distance_) {
        decision.culled_by_distance = true;
        return decision;
    }

    if (!HasOcclusionData()) {
        decision.occlusion_unconfigured = true;
        decision.replicate_full_transform = true;
        return decision;
    }

    bool occluded = IsLineOfSightOccluded(observer, target);
    if (occluded) {
        // Target is behind a solid wall/occluder. Even in close proximity, full transform
        // must not be replicated to prevent Ring-3 wallhacks from reading player coordinates.
        decision.culled_by_occlusion = true;
        if (target.is_making_sound && dist <= target.sound_radius) {
            decision.replicate_acoustic_cue_only = true;
        }
        return decision;
    }

    // Target is within line of sight
    decision.replicate_full_transform = true;
    return decision;
}

std::optional<core::DetectionEvent> ServerEspFilter::ValidatePlayerMovement(
    uint32_t player_id,
    float prev_x, float prev_y, float prev_z, uint64_t prev_ts_ms,
    float curr_x, float curr_y, float curr_z, uint64_t curr_ts_ms,
    float max_allowed_speed) const {
    if (curr_ts_ms <= prev_ts_ms || max_allowed_speed <= 0.0f) {
        return std::nullopt;
    }
    if (!std::isfinite(prev_x) || !std::isfinite(prev_y) || !std::isfinite(prev_z) ||
        !std::isfinite(curr_x) || !std::isfinite(curr_y) || !std::isfinite(curr_z)) {
        return std::nullopt;
    }

    float dt = static_cast<float>(curr_ts_ms - prev_ts_ms) / 1000.0f;
    if (dt < 0.001f) return std::nullopt;

    float dx = curr_x - prev_x;
    float dy = curr_y - prev_y;
    float dz = curr_z - prev_z;
    float dist = std::sqrt(dx * dx + dy * dy + dz * dz);
    float speed = dist / dt;

    // Allow 15% network jitter tolerance margin over max_allowed_speed
    if (speed > max_allowed_speed * 1.15f) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::SERVER_ESP_VIOLATION;
        ev.severity = core::Severity::CRITICAL;
        ev.component = "ServerEspFilter::MovementValidator";
        ev.timestamp = core::DetectionEvent::NowMonotonicMs();
        ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
        ev.threat_score = 90;
        ev.confidence = core::ConfidenceLevel::INDEPENDENTLY_VERIFIED;
        ev.corroborating_sources = 2;

        std::ostringstream ss;
        ss << "Server-verified impossible movement speed for player #" << player_id
           << ": measured=" << speed << " u/s, max_allowed=" << max_allowed_speed
           << " u/s (displacement=" << dist << " over " << (dt * 1000.0f) << " ms)";
        ev.details = ss.str();
        return ev;
    }

    return std::nullopt;
}

std::optional<core::DetectionEvent> ServerEspFilter::ValidateTargetEngagement(
    const ObserverState& attacker,
    const TargetEntityState& target,
    uint32_t consecutive_occluded_engagements) const {
    if (!IsLineOfSightOccluded(attacker, target)) {
        return std::nullopt;
    }

    // Check if any blocking occluder is non-penetrable
    bool blockedBySolidWall = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (visibility_adapter_) {
            blockedBySolidWall = visibility_adapter_->LineOfSightBlocked(
                attacker.x, attacker.y, attacker.z, target.x, target.y, target.z, true);
        } else {
            for (const auto& box : occluders_) {
                if (!box.penetrable &&
                    SegmentIntersectsAabb(attacker.x, attacker.y, attacker.z,
                                          target.x, target.y, target.z, box)) {
                    blockedBySolidWall = true;
                    break;
                }
            }
        }
    }

    if (blockedBySolidWall && consecutive_occluded_engagements >= 3) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::SERVER_ESP_VIOLATION;
        ev.severity = core::Severity::HIGH;
        ev.component = "ServerEspFilter::OcclusionValidator";
        ev.timestamp = core::DetectionEvent::NowMonotonicMs();
        ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
        ev.threat_score = 85;
        ev.confidence = core::ConfidenceLevel::INDEPENDENTLY_VERIFIED;
        ev.corroborating_sources = 2;

        std::ostringstream ss;
        ss << "Server-verified occluded engagement anomaly: player #" << attacker.player_id
           << " engaged target #" << target.entity_id
           << " through solid non-penetrable occluder (" << consecutive_occluded_engagements
           << " consecutive occluded engagements)";
        ev.details = ss.str();
        return ev;
    }

    return std::nullopt;
}

} // namespace noescape::server
