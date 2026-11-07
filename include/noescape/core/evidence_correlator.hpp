#pragma once

#include "noescape/core/types.hpp"
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>

namespace noescape::core {

struct CorrelationDecision {
    DetectionEvent enriched_event;
    uint32_t effective_score_delta{0};
    ConfidenceLevel overall_confidence{ConfidenceLevel::OBSERVATION};
    EvidenceState evidence_state{EvidenceState::OBSERVED};
    size_t independent_category_count{0};
    bool is_weak_single_signal{false};
    bool eligible_for_permanent_ban{false};
    bool eligible_for_match_restriction{false};
    bool eligible_for_session_reject{false};
};

class EvidenceCorrelator {
public:
    EvidenceCorrelator();

    // Enriches an incoming DetectionEvent, correlates it against prior signals across
    // independent detection families within the active temporal window, and determines enforcement eligibility.
    CorrelationDecision Evaluate(
        const DetectionEvent& raw_event,
        uint32_t current_total_score,
        uint32_t ban_threshold,
        bool strict_corroboration_mode = false
    );

    // Marks an event as independently verified by server attestation / server validation.
    void MarkServerVerified(uint64_t event_id);

    // Session and Match isolation
    void SetSessionId(const std::string& session_id);
    std::string GetSessionId() const;
    void SetMatchId(const std::string& match_id);
    std::string GetMatchId() const;

    // Time window & bounded storage configuration
    void SetTimeWindowMs(uint64_t window_ms);
    uint64_t GetTimeWindowMs() const;
    void SetMaxStoredEvents(size_t max_events);
    size_t GetMaxStoredEvents() const;

    // Returns the number of distinct independent detection categories active within the temporal window.
    size_t GetActiveCategoryCount(uint64_t now_ms = 0) const;

    // Prunes expired events and enforces bounded capacity.
    void PruneExpired(uint64_t now_ms);

    // Returns all aggregated evidence records with occurrence counts and states.
    std::vector<DetectionEvent> GetAggregatedEvidence() const;

    // Resets correlator state (e.g. on session boundary or engine re-init).
    void Reset();

    // Classifies whether an event represents a single weak heuristic that must not
    // trigger an automatic permanent ban without independent corroboration.
    static bool IsWeakSingleHeuristic(const DetectionEvent& event);

    // Infers intrinsic confidence level of a standalone event before cross-category promotion.
    static ConfidenceLevel InferBaseConfidence(const DetectionEvent& event);

    // Derives stable root-cause grouping identifier to prevent duplicate signals from inflating corroboration.
    static std::string DeriveRootCauseId(const DetectionEvent& event);

private:
    mutable std::mutex mutex_;
    uint64_t next_event_id_{1};
    std::string session_id_{"session_default"};
    std::string match_id_{"match_default"};
    uint64_t time_window_ms_{60000}; // 60-second sliding window
    size_t max_stored_events_{512};   // Strict bounded capacity

    struct CategoryTimelineEntry {
        uint64_t event_id{0};
        uint64_t timestamp{0};
        std::string root_cause_id;
    };

    std::unordered_map<std::string, DetectionEvent> aggregated_by_key_;
    std::unordered_map<uint32_t, std::vector<CategoryTimelineEntry>> category_timeline_;

    void EvictToCapacityLocked();
};

} // namespace noescape::core
