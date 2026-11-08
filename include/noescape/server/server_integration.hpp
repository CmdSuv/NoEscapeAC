#pragma once

#include <cstdint>
#include <vector>
#include <optional>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <memory>
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
    bool occlusion_unconfigured{false}; // Explicitly flagged when no occluder boxes or adapter are configured
};

// Abstract adapter contract for integrating game engine authoritative collision & visibility systems
// (e.g. Unreal Engine UWorld::LineTraceSingleByChannel, PhysX scene queries, Unity Physics.Raycast).
class IAuthoritativeVisibilityAdapter {
public:
    virtual ~IAuthoritativeVisibilityAdapter() = default;

    // Returns true if ray from (x0, y0, z0) to (x1, y1, z1) is occluded by authoritative world geometry.
    // If check_penetrable is true, returns true only if occluded by non-penetrable geometry.
    virtual bool LineOfSightBlocked(
        float x0, float y0, float z0,
        float x1, float y1, float z1,
        bool check_penetrable = false) const = 0;
};

struct BvhNode {
    OccluderBox bounds;
    int32_t left_child{-1};
    int32_t right_child{-1};
    int32_t first_box_idx{-1};
    int32_t box_count{0};

    bool IsLeaf() const { return left_child == -1 && right_child == -1; }
};

// Server-side ESP/Radar countermeasure & authoritative gameplay validation helper.
// NOTE: ServerEspFilter is a server-side helper library and does not automatically attach to
// your game server's networking loop. It must be explicitly driven in the game server's
// replication / packet dispatch tick and hooked into authoritative engine physics via
// IAuthoritativeVisibilityAdapter or static OccluderBox registration.
class ServerEspFilter {
public:
    ServerEspFilter() = default;

    void SetVisibilityAdapter(std::shared_ptr<IAuthoritativeVisibilityAdapter> adapter);
    std::shared_ptr<IAuthoritativeVisibilityAdapter> GetVisibilityAdapter() const;

    void AddOccluder(const OccluderBox& box);
    void ClearOccluders();
    size_t GetOccluderCount() const;
    bool HasOcclusionData() const;

    // Explicitly rebuilds the Surface Area Heuristic (SAH) BVH acceleration structure
    void RebuildBvh();

    // Queries BVH ray-occlusion (accelerated by AVX2 8-way parallel slab intersection)
    bool RayIntersectsBvh(float x0, float y0, float z0, float x1, float y1, float z1) const;

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
    mutable std::shared_mutex mutex_;
    std::vector<OccluderBox> occluders_;
    mutable std::vector<BvhNode> bvh_nodes_;
    mutable std::vector<size_t> bvh_box_indices_;
    mutable std::atomic<bool> bvh_dirty_{false};
    mutable std::mutex bvh_build_mutex_;
    std::shared_ptr<IAuthoritativeVisibilityAdapter> visibility_adapter_;
    float max_replication_distance_{150.0f};
    float close_proximity_radius_{6.0f};

    void EnsureBvhBuilt() const;
    int32_t SubdivideBvh(size_t first, size_t count) const;
    static float ComputeBoxSurfaceArea(const OccluderBox& b);
    static OccluderBox UnionBoxes(const OccluderBox& a, const OccluderBox& b);
};

} // namespace noescape::server
