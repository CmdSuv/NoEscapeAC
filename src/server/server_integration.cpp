#include "noescape/server/server_integration.hpp"

#include <cmath>
#include <algorithm>
#include <sstream>
#include <ctime>
#include <numeric>

#if (defined(__x86_64__) || defined(_M_X64))
#include <immintrin.h>
#endif

namespace noescape::server {

namespace {

#if (defined(__x86_64__) || defined(_M_X64)) && defined(__AVX2__)
inline bool Intersect8AabbsAvx2(
    float x0, float y0, float z0,
    float dx, float dy, float dz,
    const float* min_x, const float* max_x,
    const float* min_y, const float* max_y,
    const float* min_z, const float* max_z,
    int count
) {
    __m256 tmin = _mm256_set1_ps(0.0f);
    __m256 tmax = _mm256_set1_ps(1.0f);
    __m256 parallel_ok = _mm256_castsi256_ps(_mm256_set1_epi32(-1));

    auto clipAxisSimd = [&](float start, float dir, const float* bmin_ptr, const float* bmax_ptr) {
        __m256 bmin = _mm256_loadu_ps(bmin_ptr);
        __m256 bmax = _mm256_loadu_ps(bmax_ptr);
        if (std::abs(dir) < 1e-6f) {
            __m256 s = _mm256_set1_ps(start);
            __m256 ge = _mm256_cmp_ps(s, bmin, _CMP_GE_OQ);
            __m256 le = _mm256_cmp_ps(s, bmax, _CMP_LE_OQ);
            parallel_ok = _mm256_and_ps(parallel_ok, _mm256_and_ps(ge, le));
        } else {
            float invD = 1.0f / dir;
            __m256 invD_vec = _mm256_set1_ps(invD);
            __m256 s = _mm256_set1_ps(start);
            __m256 t0 = _mm256_mul_ps(_mm256_sub_ps(bmin, s), invD_vec);
            __m256 t1 = _mm256_mul_ps(_mm256_sub_ps(bmax, s), invD_vec);
            __m256 real_t0 = _mm256_min_ps(t0, t1);
            __m256 real_t1 = _mm256_max_ps(t0, t1);
            tmin = _mm256_max_ps(tmin, real_t0);
            tmax = _mm256_min_ps(tmax, real_t1);
        }
    };

    clipAxisSimd(x0, dx, min_x, max_x);
    clipAxisSimd(y0, dy, min_y, max_y);
    clipAxisSimd(z0, dz, min_z, max_z);

    __m256 valid = _mm256_and_ps(parallel_ok, _mm256_cmp_ps(tmin, tmax, _CMP_LE_OQ));
    __m256 condRange = _mm256_and_ps(_mm256_cmp_ps(tmax, _mm256_set1_ps(0.0f), _CMP_GE_OQ),
                                     _mm256_cmp_ps(tmin, _mm256_set1_ps(1.0f), _CMP_LE_OQ));
    valid = _mm256_and_ps(valid, condRange);

    int mask = _mm256_movemask_ps(valid);
    int validMask = (1 << count) - 1;
    return (mask & validMask) != 0;
}
#endif

} // namespace

void ServerEspFilter::SetVisibilityAdapter(std::shared_ptr<IAuthoritativeVisibilityAdapter> adapter) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    visibility_adapter_ = std::move(adapter);
}

std::shared_ptr<IAuthoritativeVisibilityAdapter> ServerEspFilter::GetVisibilityAdapter() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return visibility_adapter_;
}

void ServerEspFilter::AddOccluder(const OccluderBox& box) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    OccluderBox normalized = box;
    if (normalized.min_x > normalized.max_x) std::swap(normalized.min_x, normalized.max_x);
    if (normalized.min_y > normalized.max_y) std::swap(normalized.min_y, normalized.max_y);
    if (normalized.min_z > normalized.max_z) std::swap(normalized.min_z, normalized.max_z);
    occluders_.push_back(normalized);
    bvh_dirty_.store(true, std::memory_order_release);
}

void ServerEspFilter::ClearOccluders() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    std::lock_guard<std::mutex> buildLock(bvh_build_mutex_);
    occluders_.clear();
    bvh_nodes_.clear();
    bvh_box_indices_.clear();
    bvh_dirty_.store(false, std::memory_order_release);
}

size_t ServerEspFilter::GetOccluderCount() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return occluders_.size();
}

bool ServerEspFilter::HasOcclusionData() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return !occluders_.empty() || (visibility_adapter_ != nullptr);
}

float ServerEspFilter::ComputeBoxSurfaceArea(const OccluderBox& b) {
    float dx = std::max(0.0f, b.max_x - b.min_x);
    float dy = std::max(0.0f, b.max_y - b.min_y);
    float dz = std::max(0.0f, b.max_z - b.min_z);
    return 2.0f * (dx * dy + dy * dz + dz * dx);
}

OccluderBox ServerEspFilter::UnionBoxes(const OccluderBox& a, const OccluderBox& b) {
    return OccluderBox{
        std::min(a.min_x, b.min_x), std::min(a.min_y, b.min_y), std::min(a.min_z, b.min_z),
        std::max(a.max_x, b.max_x), std::max(a.max_y, b.max_y), std::max(a.max_z, b.max_z),
        a.penetrable && b.penetrable
    };
}

void ServerEspFilter::RebuildBvh() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    std::lock_guard<std::mutex> buildLock(bvh_build_mutex_);
    bvh_dirty_.store(true, std::memory_order_release);
    EnsureBvhBuilt();
}

void ServerEspFilter::EnsureBvhBuilt() const {
    if (!bvh_dirty_.load(std::memory_order_acquire) && !bvh_nodes_.empty()) return;
    std::lock_guard<std::mutex> buildLock(bvh_build_mutex_);
    if (!bvh_dirty_.load(std::memory_order_relaxed) && !bvh_nodes_.empty()) return;

    if (occluders_.empty()) {
        bvh_nodes_.clear();
        bvh_box_indices_.clear();
        bvh_dirty_.store(false, std::memory_order_release);
        return;
    }

    bvh_nodes_.clear();
    bvh_nodes_.reserve(occluders_.size() * 2);
    bvh_box_indices_.resize(occluders_.size());
    std::iota(bvh_box_indices_.begin(), bvh_box_indices_.end(), 0);

    SubdivideBvh(0, occluders_.size());
    bvh_dirty_.store(false, std::memory_order_release);
}

int32_t ServerEspFilter::SubdivideBvh(size_t first, size_t count) const {
    if (count == 0) return -1;

    int32_t nodeIdx = static_cast<int32_t>(bvh_nodes_.size());
    bvh_nodes_.emplace_back();

    // Compute bounding box for primitives [first, first + count)
    OccluderBox bbox = occluders_[bvh_box_indices_[first]];
    for (size_t i = 1; i < count; ++i) {
        bbox = UnionBoxes(bbox, occluders_[bvh_box_indices_[first + i]]);
    }
    bvh_nodes_[nodeIdx].bounds = bbox;

    // Leaf threshold: <= 4 primitives
    if (count <= 4) {
        bvh_nodes_[nodeIdx].left_child = -1;
        bvh_nodes_[nodeIdx].right_child = -1;
        bvh_nodes_[nodeIdx].first_box_idx = static_cast<int32_t>(first);
        bvh_nodes_[nodeIdx].box_count = static_cast<int32_t>(count);
        return nodeIdx;
    }

    // SAH: Surface Area Heuristic split evaluation
    float extentX = bbox.max_x - bbox.min_x;
    float extentY = bbox.max_y - bbox.min_y;
    float extentZ = bbox.max_z - bbox.min_z;

    int splitAxis = 0;
    if (extentY > extentX && extentY > extentZ) splitAxis = 1;
    else if (extentZ > extentX && extentZ > extentY) splitAxis = 2;

    auto getCentroid = [this](size_t idx, int axis) -> float {
        const auto& b = occluders_[idx];
        if (axis == 0) return 0.5f * (b.min_x + b.max_x);
        if (axis == 1) return 0.5f * (b.min_y + b.max_y);
        return 0.5f * (b.min_z + b.max_z);
    };

    size_t mid = first + count / 2;
    std::nth_element(
        bvh_box_indices_.begin() + first,
        bvh_box_indices_.begin() + mid,
        bvh_box_indices_.begin() + first + count,
        [&](size_t a, size_t b) {
            return getCentroid(a, splitAxis) < getCentroid(b, splitAxis);
        }
    );

    size_t leftCount = mid - first;
    size_t rightCount = count - leftCount;

    int32_t leftChild = SubdivideBvh(first, leftCount);
    int32_t rightChild = SubdivideBvh(mid, rightCount);

    bvh_nodes_[nodeIdx].left_child = leftChild;
    bvh_nodes_[nodeIdx].right_child = rightChild;
    bvh_nodes_[nodeIdx].first_box_idx = -1;
    bvh_nodes_[nodeIdx].box_count = 0;

    return nodeIdx;
}

bool ServerEspFilter::RayIntersectsBvh(float x0, float y0, float z0, float x1, float y1, float z1) const {
    if (occluders_.empty()) return false;
    EnsureBvhBuilt();
    if (bvh_nodes_.empty()) return false;

#if (defined(__x86_64__) || defined(_M_X64)) && defined(__AVX2__)
    float dx = x1 - x0;
    float dy = y1 - y0;
    float dz = z1 - z0;
#endif

    int32_t stack[64];
    int stackPtr = 0;
    stack[stackPtr++] = 0; // Root node

    while (stackPtr > 0) {
        int32_t nodeIdx = stack[--stackPtr];
        const auto& node = bvh_nodes_[nodeIdx];

        if (!SegmentIntersectsAabb(x0, y0, z0, x1, y1, z1, node.bounds)) {
            continue;
        }

        if (node.IsLeaf()) {
            int32_t first = node.first_box_idx;
            int32_t count = node.box_count;

#if (defined(__x86_64__) || defined(_M_X64)) && defined(__AVX2__)
            alignas(32) float min_x[8]{}, max_x[8]{};
            alignas(32) float min_y[8]{}, max_y[8]{};
            alignas(32) float min_z[8]{}, max_z[8]{};

            int batch = std::min(count, 8);
            for (int i = 0; i < batch; ++i) {
                const auto& b = occluders_[bvh_box_indices_[first + i]];
                min_x[i] = b.min_x; max_x[i] = b.max_x;
                min_y[i] = b.min_y; max_y[i] = b.max_y;
                min_z[i] = b.min_z; max_z[i] = b.max_z;
            }
            if (Intersect8AabbsAvx2(x0, y0, z0, dx, dy, dz, min_x, max_x, min_y, max_y, min_z, max_z, batch)) {
                return true;
            }
            for (int i = 8; i < count; ++i) {
                const auto& b = occluders_[bvh_box_indices_[first + i]];
                if (SegmentIntersectsAabb(x0, y0, z0, x1, y1, z1, b)) return true;
            }
#else
            for (int i = 0; i < count; ++i) {
                const auto& b = occluders_[bvh_box_indices_[first + i]];
                if (SegmentIntersectsAabb(x0, y0, z0, x1, y1, z1, b)) {
                    return true;
                }
            }
#endif
        } else {
            if (node.left_child != -1 && stackPtr < 63) stack[stackPtr++] = node.left_child;
            if (node.right_child != -1 && stackPtr < 63) stack[stackPtr++] = node.right_child;
        }
    }

    return false;
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
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (occluders_.empty() && !visibility_adapter_) return false;

    // Test center-of-mass plus 6 lateral and vertical bounding offsets ({0,0,0}, {+/-r,0,0}, {0,+/-r,0}, {0,0,+/-r})
    // to prevent pop-in artifacts on corner peeks and false occlusion of crouching/head-peeking players behind half-walls.
    const float r = std::max(0.0f, target.bounding_radius);
    const float sampleOffsets[7][3] = {
        {0.0f, 0.0f, 0.0f},
        {r, 0.0f, 0.0f},
        {-r, 0.0f, 0.0f},
        {0.0f, r, 0.0f},
        {0.0f, -r, 0.0f},
        {0.0f, 0.0f, r},
        {0.0f, 0.0f, -r}
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
            rayBlocked = RayIntersectsBvh(observer.x, observer.y, observer.z, tx, ty, tz);
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

    // FOV Frustum Culling:
    float effectiveFov = (observer.fov_deg > 0.0f && std::isfinite(observer.fov_deg))
        ? std::min(observer.fov_deg, 360.0f)
        : 110.0f;
    float halfFov = effectiveFov * 0.5f;
    constexpr float kFovMarginDeg = 15.0f; // Peripheral / aspect ratio buffer
    float r = std::max(0.0f, target.bounding_radius);

    // If target bounding sphere intersects or contains observer viewpoint (dist <= r),
    // target is in direct physical contact / knife proximity and cannot be culled by FOV.
    if (dist > r && dist > 0.001f && effectiveFov < 360.0f) {
        constexpr float kDegToRad = 3.14159265358979323846f / 180.0f;
        constexpr float kRadToDeg = 180.0f / 3.14159265358979323846f;
        float pitch = std::isfinite(observer.pitch_deg) ? observer.pitch_deg : 0.0f;
        float yaw = std::isfinite(observer.yaw_deg) ? observer.yaw_deg : 0.0f;
        float cp = std::cos(pitch * kDegToRad);
        float sp = std::sin(pitch * kDegToRad);
        float cyw = std::cos(yaw * kDegToRad);
        float syw = std::sin(yaw * kDegToRad);
        float fx = cp * cyw;
        float fy = cp * syw;
        float fz = sp;

        float angularRadius = (r > 0.0f) ? (std::asin(std::clamp(r / dist, 0.0f, 1.0f)) * kRadToDeg) : 0.0f;
        float maxAngle = halfFov + kFovMarginDeg + angularRadius;

        float dirX = dx / dist;
        float dirY = dy / dist;
        float dirZ = dz / dist;
        float dot = fx * dirX + fy * dirY + fz * dirZ;
        dot = std::clamp(dot, -1.0f, 1.0f);
        float angleDeg = std::acos(dot) * kRadToDeg;

        if (angleDeg > maxAngle) {
            decision.culled_by_fov = true;
            if (target.is_making_sound && dist <= target.sound_radius) {
                decision.replicate_acoustic_cue_only = true;
            }
            return decision;
        }
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
        std::shared_lock<std::shared_mutex> lock(mutex_);
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
