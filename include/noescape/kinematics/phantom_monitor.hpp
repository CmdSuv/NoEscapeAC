#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <vector>
#include "noescape/core/types.hpp"

namespace noescape::kinematics {

struct PhantomEntity {
    uint32_t id{0};
    float x{0}, y{0}, z{0};
};

// Decoy-entity tripwire. The game registers invisible, never-rendered, never-networked
// "players". Memory-reading ESP/aimbots that trust entity tables will draw or aim at them.
// Legitimate players have no way to know where a phantom is, so sustained, precise aim at one
// is strong evidence. Works regardless of how the cheat reads memory (kernel, DMA, external).
class PhantomMonitor {
public:
    PhantomMonitor() = default;

    void AddPhantom(uint32_t id, float x, float y, float z);
    void UpdatePhantom(uint32_t id, float x, float y, float z);
    void Clear();
    size_t Count() const;

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
    float tolerance_deg_{0.75f};
    size_t required_samples_{12};
    uint32_t tracked_id_{0};
    size_t streak_{0};
};

} // namespace noescape::kinematics
