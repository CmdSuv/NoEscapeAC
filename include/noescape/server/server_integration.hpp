#pragma once

#include <cstdint>
#include <vector>
#include <optional>
#include <mutex>
#include "noescape/core/types.hpp"

namespace noescape::server {

struct OccluderBox {
    float min_x{0.0f}, min_y{0.0f}, min_z{0.0f};
    float max_x{0.0f}, max_y{0.0f}, max_z{0.0f};
    bool penetrable{false};
};

struct ObserverState {
    uint32_t player_id{0};
    float x{0.0f}, y{0.0f}, z{0.0f};
    float pitch_deg{0.0f};
    float yaw_deg{0.0f};
    float fov_deg{110.0f};
};

struct TargetEntityState {
    uint32_t entity_id{0};
    float x{0.0f}, y{0.0f}, z{0.0f};
    float bounding_radius{0.6f};
    bool is_making_sound{false};
    float sound_radius{18.0f};
};

struct ReplicationDecision {
    bool replicate_full_transform{false};
    bool replicate_acoustic_cue_only{false};
    bool culled_by_occlusion{false};
    bool culled_by_distance{false};
};

// Server-side ESP/Radar countermeasure & authoritative gameplay validation engine.
// Prevents wallhacks and external/DMA ESP by withholding occluded entity coordinates
// from the client network stream until line-of-sight or acoustic proximity is established.
class ServerEspFilter {
public:
    ServerEspFilter() = default;

    void AddOccluder(const OccluderBox& box);
    void ClearOccluders();
    size_t GetOccluderCount() const;

    void SetMaxReplicationDistance(float dist) { max_replication_distance_ = dist; }
    void SetCloseProximityRadius(float radius) { close_proximity_radius_ = radius; }

    // 3D Slab-method segment-AABB intersection check
    static bool SegmentIntersectsAabb(
        float x0, float y0, float z0,
        float x1, float y1, float z1,
        const OccluderBox& box);

    // Checks if line-of-sight between observer and target (including bounding offsets for corner peeks) is occluded
    bool IsLineOfSightOccluded(const ObserverState& observer, const TargetEntityState& target) const;

    // Determines whether the game server should transmit `target` to `observer`'s client
    ReplicationDecision EvaluateEntityReplication(
        const ObserverState& observer,
        const TargetEntityState& target) const;

    // Server-authoritative speedhack / teleport check
    std::optional<core::DetectionEvent> ValidatePlayerMovement(
        uint32_t player_id,
        float prev_x, float prev_y, float prev_z, uint64_t prev_ts_ms,
        float curr_x, float curr_y, float curr_z, uint64_t curr_ts_ms,
        float max_allowed_speed) const;

    // Server-authoritative wallbang / occluded target tracking validation
    std::optional<core::DetectionEvent> ValidateTargetEngagement(
        const ObserverState& attacker,
        const TargetEntityState& target,
        uint32_t consecutive_occluded_engagements) const;

private:
    mutable std::mutex mutex_;
    std::vector<OccluderBox> occluders_;
    float max_replication_distance_{150.0f};
    float close_proximity_radius_{6.0f};
};

} // namespace noescape::server
