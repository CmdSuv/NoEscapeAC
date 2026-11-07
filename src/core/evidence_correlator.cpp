#include "noescape/core/evidence_correlator.hpp"
#include "noescape/network/crypto_util.hpp"
#include <chrono>
#include <algorithm>

namespace noescape::core {

namespace {
uint64_t NowEpochMs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}
} // namespace

bool EvidenceCorrelator::IsWeakSingleHeuristic(const DetectionEvent& event) {
    // Weak single signals that must never trigger an automatic permanent HWID ban on their own:
    // 1. DMA bus latency jitter alone
    if (event.type == DetectionType::DMA_LATENCY_JITTER_ANOMALY) {
        return true;
    }
    // 2. Process name match alone (without open memory handle or injection command line)
    if (event.type == DetectionType::SUSPICIOUS_PROCESS_DETECTED &&
        event.component.find("ProcessName") != std::string::npos) {
        return true;
    }
    // 3. Generic window title / non-verified overlay overlap alone
    if (event.type == DetectionType::OVERLAY_HIJACK_DETECTED &&
        event.severity <= Severity::HIGH &&
        event.details.find("UNBACKED") == std::string::npos) {
        return true;
    }
    // 4. Single timing discrepancy sample or RDTSC timing anomaly
    if (event.type == DetectionType::SPEEDHACK_TIMING_DISCREPANCY &&
        event.occurrence_count <= 1 &&
        event.severity < Severity::CRITICAL) {
        return true;
    }
    if (event.component.find("TimingAnomaly") != std::string::npos) {
        return true;
    }
    // 5. Generic PCIe VID/PID or OS posture warning without memory/code corroboration
    if (event.type == DetectionType::DMA_PCIE_LEECH_DEVICE &&
        event.severity <= Severity::HIGH &&
        event.component.find("LeechCore") == std::string::npos) {
        return true;
    }
    if (event.type == DetectionType::ENVIRONMENT_TAMPERING &&
        event.component.find("KernelIntegrity") != std::string::npos) {
        return true;
    }
    return false;
}

ConfidenceLevel EvidenceCorrelator::InferBaseConfidence(const DetectionEvent& event) {
    if (event.server_verified) {
        return ConfidenceLevel::INDEPENDENTLY_VERIFIED;
    }
    if (event.confidence != ConfidenceLevel::OBSERVATION) {
        return event.confidence;
    }
    if (IsWeakSingleHeuristic(event)) {
        return (event.severity <= Severity::MEDIUM)
            ? ConfidenceLevel::OBSERVATION
            : ConfidenceLevel::SUSPICION;
    }
    switch (event.severity) {
        case Severity::INFO:
        case Severity::LOW:
            return ConfidenceLevel::OBSERVATION;
        case Severity::MEDIUM:
            return ConfidenceLevel::SUSPICION;
        case Severity::HIGH:
            return ConfidenceLevel::CORROBORATED_ANOMALY;
        case Severity::CRITICAL:
        case Severity::FATAL_BAN:
            return ConfidenceLevel::HIGH_CONFIDENCE_VIOLATION;
        default:
            return ConfidenceLevel::OBSERVATION;
    }
}

CorrelationDecision EvidenceCorrelator::Evaluate(
    const DetectionEvent& raw_event,
    uint32_t current_total_score,
    uint32_t ban_threshold,
    bool strict_corroboration_mode
) {
    std::lock_guard<std::mutex> lock(mutex_);

    CorrelationDecision decision{};
    DetectionEvent ev = raw_event;

    uint64_t now = (ev.timestamp != 0) ? ev.timestamp : NowEpochMs();
    ev.timestamp = now;
    if (ev.event_id == 0) {
        ev.event_id = next_event_id_++;
    }
    if (ev.category == DetectionCategory::UNKNOWN) {
        ev.category = DetectionEvent::CategoryFromType(ev.type);
    }
    if (ev.evidence_source.empty()) {
        ev.evidence_source = ev.component.empty() ? "AntiCheatEngine" : ev.component;
    }

    std::string key = std::to_string(static_cast<uint32_t>(ev.type)) + "|" + ev.component + "|" + ev.details;
    ev.evidence_hash = network::CryptoUtil::Sha256(key);

    auto it = aggregated_by_key_.find(key);
    if (it == aggregated_by_key_.end()) {
        ev.first_seen_timestamp = now;
        ev.last_seen_timestamp = now;
        if (ev.occurrence_count == 0) ev.occurrence_count = 1;
    } else {
        ev.first_seen_timestamp = it->second.first_seen_timestamp;
        ev.last_seen_timestamp = now;
        ev.occurrence_count = it->second.occurrence_count + 1;
    }

    // Collect related event IDs from other independent categories
    uint32_t catKey = static_cast<uint32_t>(ev.category);
    for (const auto& [otherCat, ids] : category_to_event_ids_) {
        if (otherCat != catKey && !ids.empty()) {
            ev.related_event_ids.push_back(ids.back());
        }
    }
    category_to_event_ids_[catKey].push_back(ev.event_id);

    size_t independentCategories = category_to_event_ids_.size();
    bool weakSingle = IsWeakSingleHeuristic(ev);
    ConfidenceLevel baseConf = InferBaseConfidence(ev);

    // Promote confidence when multiple independent categories or repeated observations corroborate
    ConfidenceLevel promotedConf = baseConf;
    if (ev.server_verified) {
        promotedConf = ConfidenceLevel::INDEPENDENTLY_VERIFIED;
    } else if (independentCategories >= 2 && promotedConf < ConfidenceLevel::CORROBORATED_ANOMALY) {
        promotedConf = ConfidenceLevel::CORROBORATED_ANOMALY;
    } else if (independentCategories >= 2 && baseConf >= ConfidenceLevel::CORROBORATED_ANOMALY) {
        promotedConf = ConfidenceLevel::HIGH_CONFIDENCE_VIOLATION;
    } else if (ev.occurrence_count >= 3 && promotedConf == ConfidenceLevel::SUSPICION && !weakSingle) {
        promotedConf = ConfidenceLevel::CORROBORATED_ANOMALY;
    }

    ev.confidence = promotedConf;
    ev.corroborating_sources = static_cast<uint32_t>(independentCategories);
    aggregated_by_key_[key] = ev;

    decision.enriched_event = ev;
    decision.effective_score_delta = ev.threat_score;
    decision.overall_confidence = promotedConf;
    decision.independent_category_count = independentCategories;
    decision.is_weak_single_signal = weakSingle;

    // Match restriction eligibility (e.g., OS security posture or uncorroborated suspicious hardware)
    uint32_t projectedScore = current_total_score + ev.threat_score;
    decision.eligible_for_match_restriction =
        (ev.type == DetectionType::ENVIRONMENT_TAMPERING) ||
        (ev.type == DetectionType::DMA_PCIE_LEECH_DEVICE) ||
        (projectedScore >= (ban_threshold / 2) && ban_threshold > 0);

    // Session reject eligibility (active debugger attach, preload tampering, integrity violation)
    decision.eligible_for_session_reject =
        (ev.severity >= Severity::CRITICAL) ||
        (ev.type == DetectionType::ANTI_DEBUG_TRACER) ||
        (ev.type == DetectionType::SELF_INTEGRITY_VIOLATION) ||
        (projectedScore >= ban_threshold && ban_threshold > 0);

    // Permanent ban eligibility
    bool scoreReached = (ban_threshold > 0 && projectedScore >= ban_threshold);
    bool fatalSeverity = (ev.severity == Severity::FATAL_BAN);

    if (strict_corroboration_mode && weakSingle && independentCategories < 2 && !ev.server_verified) {
        // Under strict multi-signal corroboration, a single weak heuristic alone
        // can never trigger a permanent HWID ban without an independent second signal.
        decision.eligible_for_permanent_ban = false;
        if (ban_threshold > 0 && projectedScore >= ban_threshold) {
            decision.effective_score_delta = (current_total_score + 1 < ban_threshold)
                ? (ban_threshold - 1 - current_total_score)
                : 0;
        }
    } else {
        decision.eligible_for_permanent_ban = scoreReached || fatalSeverity;
    }

    return decision;
}

void EvidenceCorrelator::MarkServerVerified(uint64_t event_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [k, ev] : aggregated_by_key_) {
        if (ev.event_id == event_id) {
            ev.server_verified = true;
            ev.confidence = ConfidenceLevel::INDEPENDENTLY_VERIFIED;
        }
    }
}

size_t EvidenceCorrelator::GetActiveCategoryCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return category_to_event_ids_.size();
}

std::vector<DetectionEvent> EvidenceCorrelator::GetAggregatedEvidence() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DetectionEvent> out;
    out.reserve(aggregated_by_key_.size());
    for (const auto& [k, ev] : aggregated_by_key_) {
        out.push_back(ev);
    }
    std::sort(out.begin(), out.end(), [](const DetectionEvent& a, const DetectionEvent& b) {
        return a.event_id < b.event_id;
    });
    return out;
}

void EvidenceCorrelator::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    next_event_id_ = 1;
    aggregated_by_key_.clear();
    category_to_event_ids_.clear();
}

} // namespace noescape::core
