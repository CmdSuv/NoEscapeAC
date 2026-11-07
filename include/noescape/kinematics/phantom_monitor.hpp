#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <vector>
#include "noescape/core/types.hpp"

namespace noescape::kinematics {

enum class DecoyMode {
    LOCAL_ANALYTICAL = 0,  // Standalone SDK coordinate evaluation
    SERVER_INTEGRATED = 1  // Embedded in game's replicated entity list behind solid occluders
};

struct PhantomEntity {
    uint32_t id{0};
    float x{0}, y{0}, z{0};
    bool collision_enabled{false}; // Must be false so decoys never block bullets/movement
    bool audible{false};           // Must be false so legitimate players never hear audio cues
    bool occluded_placement{true}; // Placed behind walls/occluders out of legitimate line of sight
};

// Decoy-entity tripwire. The game registers invisible, never-rendered, non-collidable, silent
// decoy entities. Memory-reading ESP/aimbots that iterate the game's entity table will draw or
// lock onto them. Note: In LOCAL_ANALYTICAL mode, phantoms exist only inside PhantomMonitor's
// internal vector; to catch external/DMA cheats reading the game's real entity array, the host
// game must mirror PhantomEntities into its replicated entity table (SERVER_INTEGRATED mode).
class PhantomMonitor {
public:
    PhantomMonitor() = default;

    void SetDecoyMode(DecoyMode mode) { mode_ = mode; }
    DecoyMode GetDecoyMode() const { return mode_; }

    void AddPhantom(uint32_t id, float x, float y, float z, bool occluded = true);
    void UpdatePhantom(uint32_t id, float x, float y, float z);
    void Clear();
    void Reset();
    size_t Count() const;
    std::vector<PhantomEntity> GetPhantoms() const;
    uint32_t GetTotalLockDetections() const { return total_detections_; }

    // Generates `count` phantoms at random positions around `center` (reproducible via seed).
    void GenerateAround(float cx, float cy, float cz, float radius, size_t count, uint64_t seed);

    void SetToleranceDegrees(float deg) { tolerance_deg_ = deg; }
    void SetRequiredConsecutiveSamples(size_t n) { required_samples_ = n; }

    // Feed camera position and view angles (degrees, game convention: yaw about +Z, pitch up positive).
    std::optional<core::DetectionEvent> PushView(float cam_x, float cam_y, float cam_z,
                                                 float pitch_deg, float yaw_deg, uint64_t timestamp_ms);

private:
    mutable std::mutex mutex_;
    std::vector<PhantomEntity> phantoms_;
    DecoyMode mode_{DecoyMode::LOCAL_ANALYTICAL};
    float tolerance_deg_{0.75f};
    size_t required_samples_{12};
    uint32_t tracked_id_{0};
    size_t streak_{0};
    uint32_t total_detections_{0};
};

} // namespace noescape::kinematics
