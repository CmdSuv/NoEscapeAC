#include "noescape/kinematics/phantom_monitor.hpp"

#include <cmath>
#include <ctime>
#include <random>
#include <sstream>

namespace noescape::kinematics {

namespace {
constexpr float kDegToRad = 3.14159265358979323846f / 180.0f;
constexpr float kRadToDeg = 180.0f / 3.14159265358979323846f;
}

void PhantomMonitor::AddPhantom(uint32_t id, float x, float y, float z) {
    std::lock_guard<std::mutex> lock(mutex_);
    phantoms_.push_back({id, x, y, z});
}

void PhantomMonitor::UpdatePhantom(uint32_t id, float x, float y, float z) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& p : phantoms_) {
        if (p.id == id) { p.x = x; p.y = y; p.z = z; return; }
    }
}

void PhantomMonitor::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    phantoms_.clear();
    tracked_id_ = 0;
    streak_ = 0;
}

size_t PhantomMonitor::Count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return phantoms_.size();
}

void PhantomMonitor::GenerateAround(float cx, float cy, float cz, float radius, size_t count, uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::uniform_real_distribution<float> ang(0.0f, 2.0f * 3.14159265f);
    std::uniform_real_distribution<float> rad(radius * 0.3f, radius);
    std::uniform_real_distribution<float> dz(-1.0f, 3.0f);
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t nextId = 0xF000u + static_cast<uint32_t>(phantoms_.size());
    for (size_t i = 0; i < count; ++i) {
        float a = ang(rng), r = rad(rng);
        phantoms_.push_back({nextId++, cx + r * std::cos(a), cy + r * std::sin(a), cz + dz(rng)});
    }
}

std::optional<core::DetectionEvent> PhantomMonitor::PushView(float cx, float cy, float cz,
                                                             float pitch_deg, float yaw_deg,
                                                             uint64_t /*timestamp_ms*/) {
    if (!std::isfinite(cx) || !std::isfinite(cy) || !std::isfinite(cz) ||
        !std::isfinite(pitch_deg) || !std::isfinite(yaw_deg)) {
        return std::nullopt;
    }

    const float cp = std::cos(pitch_deg * kDegToRad), sp = std::sin(pitch_deg * kDegToRad);
    const float cyw = std::cos(yaw_deg * kDegToRad), syw = std::sin(yaw_deg * kDegToRad);
    const float fx = cp * cyw, fy = cp * syw, fz = sp; // unit forward vector

    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t best = 0;
    float bestAngle = 1e9f;
    for (const auto& p : phantoms_) {
        float dx = p.x - cx, dy = p.y - cy, dz = p.z - cz;
        float len = std::sqrt(dx * dx + dy * dy + dz * dz);
        if (len < 1.0f) continue; // too close for a meaningful angle
        float dot = (fx * dx + fy * dy + fz * dz) / len;
        dot = std::fmax(-1.0f, std::fmin(1.0f, dot));
        float angle = std::acos(dot) * kRadToDeg;
        if (angle < bestAngle) { bestAngle = angle; best = p.id; }
    }

    if (best == 0 || bestAngle > tolerance_deg_) {
        streak_ = 0;
        tracked_id_ = 0;
        return std::nullopt;
    }

    if (best != tracked_id_) { tracked_id_ = best; streak_ = 0; }
    if (++streak_ < required_samples_) return std::nullopt;

    streak_ = 0; // rearm: one event per sustained lock
    core::DetectionEvent ev;
    ev.type = core::DetectionType::PHANTOM_ENTITY_TARGETED;
    ev.severity = core::Severity::HIGH;
    ev.component = "Kinematics::PhantomMonitor";
    std::ostringstream ss;
    ss << "Crosshair held on invisible decoy entity #" << best << " within " << bestAngle
       << " deg for " << required_samples_ << " consecutive samples (entity table is being read)";
    ev.details = ss.str();
    ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
    ev.threat_score = 60;
    return ev;
}

} // namespace noescape::kinematics
