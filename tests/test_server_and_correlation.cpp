#include "tests/test_framework.hpp"
#include "noescape/core/evidence_correlator.hpp"
#include "noescape/server/server_integration.hpp"
#include <cmath>
#include <thread>

using namespace noescape::core;
using namespace noescape::server;

TEST(Correlation, WeakSingleHeuristicsClassifiedCorrectly) {
    DetectionEvent dma_jitter;
    dma_jitter.type = DetectionType::DMA_LATENCY_JITTER_ANOMALY;
    dma_jitter.severity = Severity::LOW;
    ASSERT_TRUE(EvidenceCorrelator::IsWeakSingleHeuristic(dma_jitter));

    DetectionEvent proc_name;
    proc_name.type = DetectionType::SUSPICIOUS_PROCESS_DETECTED;
    proc_name.component = "ProcessNameScanner";
    proc_name.severity = Severity::MEDIUM;
    ASSERT_TRUE(EvidenceCorrelator::IsWeakSingleHeuristic(proc_name));

    DetectionEvent unbacked_code;
    unbacked_code.type = DetectionType::UNBACKED_EXECUTABLE_MEMORY;
    unbacked_code.severity = Severity::FATAL_BAN;
    ASSERT_FALSE(EvidenceCorrelator::IsWeakSingleHeuristic(unbacked_code));

    DetectionEvent inline_hook;
    inline_hook.type = DetectionType::INLINE_HOOK_DETECTED;
    inline_hook.severity = Severity::HIGH;
    ASSERT_FALSE(EvidenceCorrelator::IsWeakSingleHeuristic(inline_hook));
}

TEST(Correlation, MultiSourceCorroborationAndBanEligibility) {
    EvidenceCorrelator correlator;

    // 1. First event: weak DMA bus latency jitter
    DetectionEvent ev1;
    ev1.type = DetectionType::DMA_LATENCY_JITTER_ANOMALY;
    ev1.component = "DmaDetector::MemoryBusJitter";
    ev1.severity = Severity::LOW;
    ev1.threat_score = 30;

    auto dec1 = correlator.Evaluate(ev1, 30, 100, /*strict_corroboration_mode=*/true);
    ASSERT_TRUE(dec1.is_weak_single_signal);
    ASSERT_FALSE(dec1.eligible_for_permanent_ban);
    ASSERT_EQ(correlator.GetActiveCategoryCount(), 1);

    // 2. Second event from the same category: does not add independent category count
    DetectionEvent ev2 = ev1;
    auto dec2 = correlator.Evaluate(ev2, 60, 100, /*strict_corroboration_mode=*/true);
    ASSERT_EQ(correlator.GetActiveCategoryCount(), 1);

    // 3. Third event: strong independent category (memory tampering)
    DetectionEvent ev3;
    ev3.type = DetectionType::INLINE_HOOK_DETECTED;
    ev3.component = "Unhooker::Kernel32";
    ev3.severity = Severity::FATAL_BAN;
    ev3.threat_score = 50;

    auto dec3 = correlator.Evaluate(ev3, 110, 100, /*strict_corroboration_mode=*/true);
    ASSERT_FALSE(dec3.is_weak_single_signal);
    ASSERT_TRUE(dec3.eligible_for_permanent_ban);
    ASSERT_GE(correlator.GetActiveCategoryCount(), 2);

    auto aggregated = correlator.GetAggregatedEvidence();
    ASSERT_GE(aggregated.size(), 2);
}

TEST(Correlation, ServerVerificationPromotion) {
    EvidenceCorrelator correlator;

    DetectionEvent ev;
    ev.type = DetectionType::KINEMATICS_AIMBOT_SNAP;
    ev.component = "Kinematics::AimAnalyzer";
    ev.threat_score = 40;

    auto dec = correlator.Evaluate(ev, 40, 100, false);
    ASSERT_FALSE(dec.enriched_event.server_verified);

    correlator.MarkServerVerified(dec.enriched_event.event_id);
    auto all_ev = correlator.GetAggregatedEvidence();
    ASSERT_FALSE(all_ev.empty());
    ASSERT_TRUE(all_ev.front().server_verified);
    ASSERT_EQ(all_ev.front().confidence, ConfidenceLevel::INDEPENDENTLY_VERIFIED);
}

TEST(ServerIntegration, RayAabbIntersectionSlabMethod) {
    OccluderBox box{
        -10.0f, 10.0f, -5.0f,
         10.0f, 12.0f,  5.0f,
        false
    };

    // Direct ray through the box (from 0, 0, 0 to 0, 20, 0)
    bool hit = ServerEspFilter::SegmentIntersectsAabb(
        0.0f, 0.0f, 0.0f,
        0.0f, 20.0f, 0.0f,
        box
    );
    ASSERT_TRUE(hit);

    // Ray that completely misses (from 0, 0, 0 to 50, 0, 0)
    bool miss = ServerEspFilter::SegmentIntersectsAabb(
        0.0f, 0.0f, 0.0f,
        50.0f, 0.0f, 0.0f,
        box
    );
    ASSERT_FALSE(miss);

    // Ray that stops short of the box (from 0, 0, 0 to 0, 5, 0)
    bool short_ray = ServerEspFilter::SegmentIntersectsAabb(
        0.0f, 0.0f, 0.0f,
        0.0f, 5.0f, 0.0f,
        box
    );
    ASSERT_FALSE(short_ray);
}

TEST(ServerIntegration, AuthoritativeEspCullingAndReplication) {
    ServerEspFilter filter;

    // Add a solid wall at y = 20
    OccluderBox wall{-50.0f, 19.5f, -10.0f, 50.0f, 20.5f, 10.0f, false};
    filter.AddOccluder(wall);
    ASSERT_EQ(filter.GetOccluderCount(), 1);

    ObserverState observer;
    observer.player_id = 1;
    observer.x = 0.0f; observer.y = 0.0f; observer.z = 1.0f;

    // Target behind the wall at y = 40, silent
    TargetEntityState target_occluded;
    target_occluded.entity_id = 100;
    target_occluded.x = 0.0f; target_occluded.y = 40.0f; target_occluded.z = 1.0f;
    target_occluded.is_making_sound = false;

    auto rep1 = filter.EvaluateEntityReplication(observer, target_occluded);
    // Entity should be occluded and NOT replicated to client
    ASSERT_FALSE(rep1.replicate_full_transform);
    ASSERT_TRUE(rep1.culled_by_occlusion);

    // If target makes footsteps / gunshots within sound radius, replicate acoustic cue only
    target_occluded.is_making_sound = true;
    target_occluded.sound_radius = 50.0f;
    auto rep2 = filter.EvaluateEntityReplication(observer, target_occluded);
    ASSERT_FALSE(rep2.replicate_full_transform);
    ASSERT_TRUE(rep2.replicate_acoustic_cue_only);

    // If target is in clear line-of-sight in front of wall at y = 10
    TargetEntityState target_visible;
    target_visible.entity_id = 101;
    target_visible.x = 0.0f; target_visible.y = 10.0f; target_visible.z = 1.0f;
    auto rep3 = filter.EvaluateEntityReplication(observer, target_visible);
    ASSERT_TRUE(rep3.replicate_full_transform);
    ASSERT_FALSE(rep3.culled_by_occlusion);
}

TEST(ServerIntegration, MovementAndEngagementValidation) {
    ServerEspFilter filter;

    // Legal move: 5 meters in 1000 ms (speed = 5 m/s, max allowed = 10 m/s)
    auto ev_legal = filter.ValidatePlayerMovement(
        42,
        0.0f, 0.0f, 0.0f, 1000,
        5.0f, 0.0f, 0.0f, 2000,
        10.0f
    );
    ASSERT_FALSE(ev_legal.has_value());

    // Teleport / speedhack move: 500 meters in 20 ms
    auto ev_speedhack = filter.ValidatePlayerMovement(
        42,
        0.0f, 0.0f, 0.0f, 1000,
        500.0f, 0.0f, 0.0f, 1020,
        10.0f
    );
    ASSERT_TRUE(ev_speedhack.has_value());
    ASSERT_EQ(ev_speedhack->type, DetectionType::SERVER_ESP_VIOLATION);
    ASSERT_EQ(ev_speedhack->severity, Severity::CRITICAL);
}

TEST(ServerIntegration, BvhRayIntersectionMultiBox) {
    ServerEspFilter filter;

    // Create an array of 16 distinct occluder boxes (triggering BVH building and AVX2 8-way slabs)
    for (int i = 0; i < 16; ++i) {
        float x = static_cast<float>(i * 10);
        OccluderBox b{
            x - 2.0f, 10.0f, -2.0f,
            x + 2.0f, 12.0f,  2.0f,
            false
        };
        filter.AddOccluder(b);
    }
    ASSERT_EQ(filter.GetOccluderCount(), 16);

    ObserverState obs;
    obs.player_id = 1;
    obs.x = 40.0f; obs.y = 0.0f; obs.z = 0.0f;

    TargetEntityState target_box5;
    target_box5.entity_id = 10;
    target_box5.x = 40.0f; target_box5.y = 20.0f; target_box5.z = 0.0f;

    // Ray shooting through the 5th box at x = 40 (from 40, 0, 0 to 40, 20, 0)
    bool hit_box5 = filter.IsLineOfSightOccluded(obs, target_box5);
    ASSERT_TRUE(hit_box5);

    // Ray passing cleanly through the corridor between box 0 and box 1 at x = 5 (from 5, 0, 0 to 5, 20, 0)
    obs.x = 5.0f;
    TargetEntityState target_corridor;
    target_corridor.entity_id = 11;
    target_corridor.x = 5.0f; target_corridor.y = 20.0f; target_corridor.z = 0.0f;
    bool miss_corridor = filter.IsLineOfSightOccluded(obs, target_corridor);
    ASSERT_FALSE(miss_corridor);

    // Ray above all boxes at z = 10 (from 40, 0, 10 to 40, 20, 10)
    obs.x = 40.0f; obs.z = 10.0f;
    TargetEntityState target_height;
    target_height.entity_id = 12;
    target_height.x = 40.0f; target_height.y = 20.0f; target_height.z = 10.0f;
    bool miss_height = filter.IsLineOfSightOccluded(obs, target_height);
    ASSERT_FALSE(miss_height);
}

TEST(ServerIntegration, ConcurrentMultiThreadedBvhQueries) {
    ServerEspFilter filter;
    for (int i = 0; i < 32; ++i) {
        float x = static_cast<float>(i * 5);
        filter.AddOccluder(OccluderBox{x - 1.0f, 10.0f, -1.0f, x + 1.0f, 12.0f, 1.0f, false});
    }

    constexpr int kNumThreads = 8;
    constexpr int kQueriesPerThread = 150;
    std::vector<std::thread> workers;
    std::atomic<int> occludedHits{0};
    std::atomic<int> corridorMisses{0};

    for (int t = 0; t < kNumThreads; ++t) {
        workers.emplace_back([&filter, &occludedHits, &corridorMisses]() {
            for (int q = 0; q < kQueriesPerThread; ++q) {
                // Query 1: hit box at x = 20
                ObserverState obsHit{1, 20.0f, 0.0f, 0.0f};
                TargetEntityState tgtHit{10, 20.0f, 20.0f, 0.0f};
                if (filter.IsLineOfSightOccluded(obsHit, tgtHit)) {
                    occludedHits.fetch_add(1, std::memory_order_relaxed);
                }

                // Query 2: corridor at x = 2.5
                ObserverState obsMiss{2, 2.5f, 0.0f, 0.0f};
                TargetEntityState tgtMiss{11, 2.5f, 20.0f, 0.0f};
                if (!filter.IsLineOfSightOccluded(obsMiss, tgtMiss)) {
                    corridorMisses.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& w : workers) {
        w.join();
    }

    ASSERT_EQ(occludedHits.load(), kNumThreads * kQueriesPerThread);
    ASSERT_EQ(corridorMisses.load(), kNumThreads * kQueriesPerThread);
}


