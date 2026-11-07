#include "noescape/core/evidence_correlator.hpp"
#include "noescape/network/crypto_util.hpp"
#include <chrono>
#include <algorithm>
#include <sstream>

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

EvidenceCorrelator::EvidenceCorrelator() {
    session_id_ = "session_" + network::CryptoUtil::GenerateRandomHex(8);
    match_id_ = "match_initial";
}

void EvidenceCorrelator::SetSessionId(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_id_ != session_id) {
        // Enforce strict session isolation: retire previous session records
        aggregated_by_key_.clear();
        category_timeline_.clear();
        session_id_ = session_id;
    }
}

std::string EvidenceCorrelator::GetSessionId() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return session_id_;
}

void EvidenceCorrelator::SetMatchId(const std::string& match_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (match_id_ != match_id) {
        // Enforce strict match isolation: retire prior match records
        aggregated_by_key_.clear();
        category_timeline_.clear();
        match_id_ = match_id;
    }
}

std::string EvidenceCorrelator::GetMatchId() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return match_id_;
}

void EvidenceCorrelator::SetTimeWindowMs(uint64_t window_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    time_window_ms_ = (window_ms > 0) ? window_ms : 60000;
}

uint64_t EvidenceCorrelator::GetTimeWindowMs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return time_window_ms_;
}

void EvidenceCorrelator::SetMaxStoredEvents(size_t max_events) {
    std::lock_guard<std::mutex> lock(mutex_);
    max_stored_events_ = (max_events >= 16) ? max_events : 16;
    EvictToCapacityLocked();
}

size_t EvidenceCorrelator::GetMaxStoredEvents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return max_stored_events_;
}

std::string EvidenceCorrelator::DeriveRootCauseId(const DetectionEvent& event) {
    // Group identical underlying causes: memory address spans, thread IDs, or process PIDs
    size_t hexPos = event.details.find("0x");
    if (hexPos != std::string::npos) {
        size_t endHex = event.details.find_first_of(" \t\r\n)]", hexPos);
        std::string addrStr = (endHex == std::string::npos)
            ? event.details.substr(hexPos)
            : event.details.substr(hexPos, endHex - hexPos);
        return event.component + "|" + addrStr;
    }
    size_t pidPos = event.details.find("PID ");
    if (pidPos != std::string::npos) {
        size_t endPid = event.details.find_first_of(" \t\r\n)]", pidPos + 4);
        std::string pidStr = (endPid == std::string::npos)
            ? event.details.substr(pidPos)
            : event.details.substr(pidPos, endPid - pidPos);
        return event.component + "|" + pidStr;
    }
    return event.component + "|" + std::to_string(static_cast<uint32_t>(event.type));
}

bool EvidenceCorrelator::IsWeakSingleHeuristic(const DetectionEvent& event) {
    // 1. DMA bus latency jitter alone
    if (event.type == DetectionType::DMA_LATENCY_JITTER_ANOMALY) {
        return true;
    }
    // 2. Process name match alone (without handle or code injection evidence)
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
    // 4. Single timing discrepancy sample or RDTSC anomaly
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
    // 6. Watchdog scheduling delay / heartbeat timing jitter alone
    if (event.type == DetectionType::HEARTBEAT_TAMPERING &&
        event.component.find("Watchdog") != std::string::npos) {
        return true;
    }
    // 7. Process environment audit / dynamic linker environment variables alone
    if (event.type == DetectionType::ENVIRONMENT_TAMPERING &&
        event.component.find("EnvironmentAudit") != std::string::npos) {
        return true;
    }
    // 8. Filesystem artifact or vulnerable OEM driver alone
    if (event.type == DetectionType::FORENSICS_ARTIFACT_DETECTED) {
        if (event.component.find("Filesystem") != std::string::npos ||
            event.details.find("Vulnerable OEM") != std::string::npos) {
            return true;
        }
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

void EvidenceCorrelator::PruneExpired(uint64_t now_ms) {
    uint64_t cutoff = (now_ms > time_window_ms_) ? (now_ms - time_window_ms_) : 0;

    // Prune category timeline entries older than sliding temporal window
    for (auto it = category_timeline_.begin(); it != category_timeline_.end(); ) {
        auto& entries = it->second;
        entries.erase(
            std::remove_if(entries.begin(), entries.end(),
                           [cutoff](const CategoryTimelineEntry& e) { return e.timestamp < cutoff; }),
            entries.end()
        );
        if (entries.empty()) {
            it = category_timeline_.erase(it);
        } else {
            ++it;
        }
    }

    // Mark expired status on aggregated evidence records older than sliding temporal window
    for (auto& [k, ev] : aggregated_by_key_) {
        if (ev.last_seen_timestamp < cutoff && ev.evidence_state != EvidenceState::EXPIRED) {
            ev.evidence_state = EvidenceState::EXPIRED;
        }
    }
}

size_t EvidenceCorrelator::GetActiveCategoryCount(uint64_t now_ms) const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t now = (now_ms != 0) ? now_ms : NowEpochMs();
    uint64_t cutoff = (now > time_window_ms_) ? (now - time_window_ms_) : 0;

    size_t activeCount = 0;
    for (const auto& [cat, entries] : category_timeline_) {
        bool hasActive = false;
        for (const auto& e : entries) {
            if (e.timestamp >= cutoff) {
                hasActive = true;
                break;
            }
        }
        if (hasActive) {
            ++activeCount;
        }
    }
    return activeCount;
}

void EvidenceCorrelator::EvictToCapacityLocked() {
    if (aggregated_by_key_.size() <= max_stored_events_) return;

    // First pass: evict EXPIRED records
    for (auto it = aggregated_by_key_.begin(); it != aggregated_by_key_.end() && aggregated_by_key_.size() > max_stored_events_; ) {
        if (it->second.evidence_state == EvidenceState::EXPIRED) {
            it = aggregated_by_key_.erase(it);
        } else {
            ++it;
        }
    }

    // Second pass: evict oldest records if still above capacity
    if (aggregated_by_key_.size() > max_stored_events_) {
        std::vector<std::pair<std::string, uint64_t>> candidates;
        candidates.reserve(aggregated_by_key_.size());
        for (const auto& [k, ev] : aggregated_by_key_) {
            candidates.emplace_back(k, ev.last_seen_timestamp);
        }
        std::sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
            return a.second < b.second;
        });
        size_t toRemove = aggregated_by_key_.size() - max_stored_events_;
        for (size_t i = 0; i < toRemove && i < candidates.size(); ++i) {
            aggregated_by_key_.erase(candidates[i].first);
        }
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
    ev.session_id = session_id_;
    ev.match_id = match_id_;
    ev.root_cause_id = DeriveRootCauseId(ev);
    ev.expiration_timestamp = now + time_window_ms_;

    // Prune stale records based on sliding temporal window
    PruneExpired(now);

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
        ev.related_event_ids = it->second.related_event_ids;
    }

    // Update or append to category timeline with deduplication and bounded capacity
    uint32_t catKey = static_cast<uint32_t>(ev.category);
    auto& catEntries = category_timeline_[catKey];
    bool foundRootCause = false;
    for (auto& entry : catEntries) {
        if (entry.root_cause_id == ev.root_cause_id) {
            entry.timestamp = now;
            entry.event_id = ev.event_id;
            foundRootCause = true;
            break;
        }
    }
    if (!foundRootCause) {
        catEntries.push_back(CategoryTimelineEntry{ev.event_id, now, ev.root_cause_id});
        if (catEntries.size() > 32) {
            catEntries.erase(catEntries.begin());
        }
    }

    // Compute independent active categories with distinct root causes
    std::unordered_set<uint32_t> distinctCategories;
    std::unordered_set<std::string> distinctRootCauses;
    uint64_t cutoff = (now > time_window_ms_) ? (now - time_window_ms_) : 0;

    for (const auto& [otherCat, entries] : category_timeline_) {
        for (const auto& entry : entries) {
            if (entry.timestamp >= cutoff) {
                distinctCategories.insert(otherCat);
                distinctRootCauses.insert(entry.root_cause_id);
                if (ev.related_event_ids.size() < 16 && otherCat != catKey &&
                    std::find(ev.related_event_ids.begin(), ev.related_event_ids.end(), entry.event_id) == ev.related_event_ids.end()) {
                    ev.related_event_ids.push_back(entry.event_id);
                }
            }
        }
    }

    size_t independentCategories = distinctCategories.size();
    bool weakSingle = IsWeakSingleHeuristic(ev);
    ConfidenceLevel baseConf = InferBaseConfidence(ev);

    // Promote confidence across independent families
    ConfidenceLevel promotedConf = baseConf;
    EvidenceState state = EvidenceState::OBSERVED;

    if (ev.server_verified) {
        promotedConf = ConfidenceLevel::INDEPENDENTLY_VERIFIED;
        state = EvidenceState::SERVER_VERIFIED;
    } else if (independentCategories >= 2 && distinctRootCauses.size() >= 2) {
        promotedConf = (baseConf >= ConfidenceLevel::CORROBORATED_ANOMALY)
            ? ConfidenceLevel::HIGH_CONFIDENCE_VIOLATION
            : ConfidenceLevel::CORROBORATED_ANOMALY;
        state = (promotedConf == ConfidenceLevel::HIGH_CONFIDENCE_VIOLATION)
            ? EvidenceState::HIGH_CONFIDENCE
            : EvidenceState::CORROBORATED;
    } else if (ev.occurrence_count >= 3 && !weakSingle) {
        promotedConf = ConfidenceLevel::CORROBORATED_ANOMALY;
        state = EvidenceState::CORROBORATED;
    } else if (weakSingle || baseConf == ConfidenceLevel::SUSPICION) {
        state = EvidenceState::SUSPICIOUS;
    }

    ev.confidence = promotedConf;
    ev.evidence_state = state;
    ev.corroborating_sources = static_cast<uint32_t>(independentCategories);
    aggregated_by_key_[key] = ev;
    EvictToCapacityLocked();

    decision.enriched_event = ev;
    decision.effective_score_delta = ev.threat_score;
    decision.overall_confidence = promotedConf;
    decision.evidence_state = state;
    decision.independent_category_count = independentCategories;
    decision.is_weak_single_signal = weakSingle;

    uint32_t projectedScore = current_total_score + ev.threat_score;
    decision.eligible_for_match_restriction =
        (ev.type == DetectionType::ENVIRONMENT_TAMPERING) ||
        (ev.type == DetectionType::DMA_PCIE_LEECH_DEVICE) ||
        (projectedScore >= (ban_threshold / 2) && ban_threshold > 0);

    decision.eligible_for_session_reject =
        (ev.severity >= Severity::CRITICAL) ||
        (ev.type == DetectionType::ANTI_DEBUG_TRACER) ||
        (ev.type == DetectionType::SELF_INTEGRITY_VIOLATION) ||
        (projectedScore >= ban_threshold && ban_threshold > 0);

    bool scoreReached = (ban_threshold > 0 && projectedScore >= ban_threshold);
    bool fatalSeverity = (ev.severity == Severity::FATAL_BAN);

    if (strict_corroboration_mode) {
        // Under strict multi-signal corroboration mode (Production / Shadow Production):
        // 1. Permanent bans REQUIRE multi-signal corroboration: at least 2 independent detection
        //    categories with distinct root causes, OR authoritative server verification.
        // 2. An event's severity alone (even FATAL_BAN or CRITICAL) does NOT establish evidence independence.
        // 3. A single client-side heuristic or condition cannot trigger a permanent ban without corroboration.
        bool hasMultiSignalCorroboration = (independentCategories >= 2 && distinctRootCauses.size() >= 2);
        if (ev.server_verified || hasMultiSignalCorroboration) {
            decision.eligible_for_permanent_ban = scoreReached || fatalSeverity;
        } else {
            decision.eligible_for_permanent_ban = false;
            // Cap score just below threshold so uncorroborated single signals cannot accumulate to an irreversible ban
            if (ban_threshold > 0 && projectedScore >= ban_threshold) {
                decision.effective_score_delta = (current_total_score + 1 < ban_threshold)
                    ? (ban_threshold - 1 - current_total_score)
                    : 0;
            }
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
            ev.evidence_state = EvidenceState::SERVER_VERIFIED;
        }
    }
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
    category_timeline_.clear();
    session_id_ = "session_" + network::CryptoUtil::GenerateRandomHex(8);
}

} // namespace noescape::core
