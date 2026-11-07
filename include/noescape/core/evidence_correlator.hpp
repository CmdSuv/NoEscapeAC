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
    size_t independent_category_count{0};
    bool is_weak_single_signal{false};
    bool eligible_for_permanent_ban{false};
    bool eligible_for_match_restriction{false};
    bool eligible_for_session_reject{false};
};

class EvidenceCorrelator {
public:
    EvidenceCorrelator() = default;

    // Enriches an incoming DetectionEvent, correlates it against prior signals across
    // independent detection families, and determines safe enforcement eligibility.
    CorrelationDecision Evaluate(
        const DetectionEvent& raw_event,
        uint32_t current_total_score,
        uint32_t ban_threshold,
        bool strict_corroboration_mode = false
    );

    // Marks all events matching a category or ID as independently verified by the server.
    void MarkServerVerified(uint64_t event_id);

    // Returns the number of distinct detection categories observed so far.
    size_t GetActiveCategoryCount() const;

    // Returns all deduplicated/aggregated evidence records with occurrence counts.
    std::vector<DetectionEvent> GetAggregatedEvidence() const;

    // Resets state (used on engine shutdown / re-init).
    void Reset();

    // Classifies whether an event represents a single weak heuristic that must not
    // trigger an automatic permanent ban without corroboration.
    static bool IsWeakSingleHeuristic(const DetectionEvent& event);

    // Infers intrinsic confidence level of a standalone event before cross-category promotion.
    static ConfidenceLevel InferBaseConfidence(const DetectionEvent& event);

private:
    mutable std::mutex mutex_;
    uint64_t next_event_id_{1};
    std::unordered_map<std::string, DetectionEvent> aggregated_by_key_;
    std::unordered_map<uint32_t, std::vector<uint64_t>> category_to_event_ids_;
};

} // namespace noescape::core
