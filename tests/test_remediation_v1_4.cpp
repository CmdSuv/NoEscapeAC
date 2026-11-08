#include "tests/test_framework.hpp"
#include "noescape/core/types.hpp"
#include "noescape/core/evidence_correlator.hpp"
#include "noescape/core/engine.hpp"
#include "noescape/server/server_integration.hpp"
#include "noescape/kinematics/aim_analyzer.hpp"
#include "noescape/kinematics/phantom_monitor.hpp"
#include "noescape/dma/dma_detector.hpp"
#include "noescape/overlay/overlay_detector.hpp"
#include "noescape/network/crypto_util.hpp"
#include "noescape/network/ed25519.hpp"
#include "noescape/network/panel_client.hpp"
#include "noescape/security/anti_debug.hpp"
#include "noescape/security/integrity.hpp"
#include "noescape/security/timing.hpp"
#include "noescape/memory/memory_scanner.hpp"
#include "noescape/memory/canary_monitor.hpp"
#include "noescape/memory/unhooker.hpp"
#include "noescape/forensics/process_analyzer.hpp"
#include "noescape/forensics/artifact_analyzer.hpp"
#include "noescape_sdk.h"

#include <vector>
#include <string>
#include <unordered_set>
#include <cstring>
#include <cstdlib>
#include <thread>
#include <atomic>

using namespace noescape;
using namespace noescape::core;
using namespace noescape::server;
using namespace noescape::kinematics;
using namespace noescape::network;

// ============================================================================
// P0-1: Timestamp Normalization & Sliding Time Window
// ============================================================================

TEST(RemediationV1_4, TimestampMonotonicAndUtcMsSanity) {
    uint64_t mono = DetectionEvent::NowMonotonicMs();
    uint64_t utc = DetectionEvent::NowUtcMs();

    ASSERT_GT(mono, 0u);
    ASSERT_GT(utc, 1700000000000ULL); // At least year 2023 in milliseconds

    // Default constructed DetectionEvent must automatically populate valid timestamps
    DetectionEvent evDefault;
    ASSERT_GE(evDefault.timestamp, mono);
    ASSERT_GE(evDefault.timestamp_utc_ms, utc);
    ASSERT_GE(evDefault.first_seen_timestamp, mono);
    ASSERT_GE(evDefault.last_seen_timestamp, mono);

    DetectionEvent ev;
    ev.timestamp = DetectionEvent::NowMonotonicMs();
    ev.timestamp_utc_ms = DetectionEvent::NowUtcMs();

    ASSERT_GE(ev.timestamp, mono);
    ASSERT_GE(ev.timestamp_utc_ms, utc);
}

TEST(RemediationV1_4, SixtySecondWindowStrict60000MsAcrossSubsystems) {
    // 13 Subsystems that produce DetectionEvents
    struct SubsystemDescriptor {
        const char* name;
        DetectionType type;
        Severity severity;
        const char* component;
        uint32_t threat_score;
    };

    const std::vector<SubsystemDescriptor> subsystems = {
        {"AntiDebug", DetectionType::ANTI_DEBUG_TRACER, Severity::CRITICAL, "AntiDebug", 100},
        {"IntegrityChecker", DetectionType::SELF_INTEGRITY_VIOLATION, Severity::CRITICAL, "IntegrityChecker", 100},
        {"TimingIntegrity", DetectionType::SPEEDHACK_TIMING_DISCREPANCY, Severity::HIGH, "TimingIntegrity", 60},
        {"MemoryScanner", DetectionType::UNBACKED_EXECUTABLE_MEMORY, Severity::HIGH, "MemoryScanner", 65},
        {"CanaryMonitor", DetectionType::CANARY_TAMPERED, Severity::CRITICAL, "CanaryMonitor", 90},
        {"Unhooker", DetectionType::INLINE_HOOK_DETECTED, Severity::HIGH, "Unhooker", 70},
        {"ProcessAnalyzer", DetectionType::SUSPICIOUS_PROCESS_DETECTED, Severity::MEDIUM, "ProcessAnalyzer", 40},
        {"ArtifactAnalyzer", DetectionType::FORENSICS_ARTIFACT_DETECTED, Severity::MEDIUM, "ArtifactAnalyzer", 30},
        {"DmaDetector", DetectionType::DMA_PCIE_LEECH_DEVICE, Severity::CRITICAL, "DmaDetector", 95},
        {"PhantomMonitor", DetectionType::PHANTOM_ENTITY_TARGETED, Severity::HIGH, "PhantomMonitor", 60},
        {"AimAnalyzer", DetectionType::KINEMATICS_AIMBOT_SNAP, Severity::HIGH, "AimAnalyzer", 70},
        {"OverlayDetector", DetectionType::OVERLAY_HIJACK_DETECTED, Severity::HIGH, "OverlayDetector", 50},
        {"ServerEspFilter", DetectionType::SERVER_ESP_VIOLATION, Severity::CRITICAL, "ServerEspFilter", 90}
    };

    uint64_t base_time = 10000000; // Simulated monotonic ms

    for (const auto& sub : subsystems) {
        EvidenceCorrelator correlator;
        correlator.SetTimeWindowMs(60000); // 60-second window

        DetectionEvent ev;
        ev.type = sub.type;
        ev.severity = sub.severity;
        ev.component = sub.component;
        ev.details = std::string(sub.name) + " sliding window test observation";
        ev.timestamp = base_time;
        ev.timestamp_utc_ms = GetUtcTimeMs();
        ev.threat_score = sub.threat_score;

        ASSERT_GT(ev.timestamp, 0u);
        ASSERT_GT(ev.timestamp_utc_ms, 1700000000000ULL);

        correlator.Evaluate(ev, 0, 100);

        // At base_time + 59,900 ms (59.9s): event is within the 60-second window -> ACTIVE (1 category)
        ASSERT_EQ(correlator.GetActiveCategoryCount(base_time + 59900), 1u);

        // At base_time + 60,000 ms: exactly on the boundary
        ASSERT_EQ(correlator.GetActiveCategoryCount(base_time + 60000), 1u);

        // At base_time + 60,001 ms (60.001s): event has strictly expired -> INACTIVE (0 categories)
        ASSERT_EQ(correlator.GetActiveCategoryCount(base_time + 60001), 0u);

        // At base_time + 60,100 ms: strictly expired
        ASSERT_EQ(correlator.GetActiveCategoryCount(base_time + 60100), 0u);

        // PruneExpired at base_time + 60,100 ms must mark the record EXPIRED
        correlator.PruneExpired(base_time + 60100);
        auto evidence = correlator.GetAggregatedEvidence();
        ASSERT_FALSE(evidence.empty());
        for (const auto& record : evidence) {
            if (record.type == sub.type) {
                ASSERT_EQ(static_cast<int>(record.evidence_state), static_cast<int>(EvidenceState::EXPIRED));
            }
        }
    }
}

TEST(RemediationV1_4, ServerEspFilterTimestampsAreMonotonicAndUtcMs) {
    ServerEspFilter filter;
    // Movement validator: 1000 units in 0.05s = 20,000 u/s (exceeds max 250 u/s)
    auto ev = filter.ValidatePlayerMovement(1, 0.0f, 0.0f, 0.0f, 1000,
                                           1000.0f, 0.0f, 0.0f, 1050,
                                           250.0f);
    ASSERT_TRUE(ev.has_value());
    ASSERT_GT(ev->timestamp, 0u);
    ASSERT_GT(ev->timestamp_utc_ms, 1700000000000ULL);
}

// ============================================================================
// P0-2: Enforcement and Corroboration Bypass Prevention
// ============================================================================

TEST(RemediationV1_4, SingleCriticalClientHeuristicCannotBypassCorroboration) {
    EvidenceCorrelator correlator;
    correlator.SetTimeWindowMs(60000);

    // Single client-side CRITICAL heuristic event
    DetectionEvent ev;
    ev.type = DetectionType::UNBACKED_EXECUTABLE_MEMORY;
    ev.severity = Severity::CRITICAL;
    ev.component = "MemoryScanner::UnbackedPages";
    ev.details = "Suspicious anonymous executable memory allocation";
    ev.timestamp = DetectionEvent::NowMonotonicMs();
    ev.timestamp_utc_ms = DetectionEvent::NowUtcMs();
    ev.threat_score = 100; // Above ban threshold 100

    auto decision = correlator.Evaluate(ev, 0, 100, true /* strict_corroboration_mode */);

    // Under strict corroboration policy, single client-side heuristic MUST NOT trigger ban eligibility
    ASSERT_FALSE(decision.eligible_for_permanent_ban);
    ASSERT_FALSE(decision.eligible_for_session_reject);
    ASSERT_FALSE(decision.eligible_for_shadow);
    ASSERT_FALSE(decision.eligible_for_match_restriction);
    ASSERT_TRUE(decision.eligible_for_report_only);
    // Score delta must be capped so score cannot reach 100
    ASSERT_EQ(decision.effective_score_delta, 99u);

    // A second signal of the SAME heuristic sub-type must NOT satisfy multi-signal corroboration
    DetectionEvent ev_same_type;
    ev_same_type.type = DetectionType::UNBACKED_EXECUTABLE_MEMORY;
    ev_same_type.severity = Severity::CRITICAL;
    ev_same_type.component = "MemoryScanner::UnbackedPages";
    ev_same_type.details = "Suspicious anonymous executable memory allocation #2";
    ev_same_type.timestamp = DetectionEvent::NowMonotonicMs();
    ev_same_type.timestamp_utc_ms = DetectionEvent::NowUtcMs();
    ev_same_type.threat_score = 100;

    auto decision_same = correlator.Evaluate(ev_same_type, 99, 100, true /* strict */);
    ASSERT_FALSE(decision_same.eligible_for_permanent_ban);
    ASSERT_FALSE(decision_same.eligible_for_session_reject);

    // Now supply a truly independent detection category (DMA hardware)
    DetectionEvent ev2;
    ev2.type = DetectionType::DMA_PCIE_LEECH_DEVICE;
    ev2.severity = Severity::HIGH;
    ev2.component = "DmaDetector::PciScan";
    ev2.details = "LeechCore DMA device detected on bus";
    ev2.timestamp = DetectionEvent::NowMonotonicMs();
    ev2.timestamp_utc_ms = DetectionEvent::NowUtcMs();
    ev2.threat_score = 80;

    auto decision2 = correlator.Evaluate(ev2, 99, 100, true /* strict_corroboration_mode */);

    // Now corroborated across multiple distinct categories
    ASSERT_GE(decision2.independent_category_count, 2u);
    ASSERT_TRUE(decision2.eligible_for_permanent_ban);
    ASSERT_TRUE(decision2.eligible_for_session_reject);
}

TEST(RemediationV1_4, EngineCentralizedEnforcementModeRespectsDecisions) {
    // 1. REPORT_ONLY mode: Never enforces local actions even with corroborated ban eligibility
    {
        EngineConfig cfg = EngineConfig::DevelopmentProfile();
        cfg.enforcementMode = EnforcementMode::REPORT_ONLY;
        AntiCheatEngine engine(cfg);

        DetectionEvent ev1{DetectionType::UNBACKED_EXECUTABLE_MEMORY, Severity::CRITICAL, "MemScan", "det1", 1000, 100};
        DetectionEvent ev2{DetectionType::DMA_PCIE_LEECH_DEVICE, Severity::CRITICAL, "DmaScan", "det2", 1005, 100};
        engine.ProcessDetection(ev1);
        engine.ProcessDetection(ev2);

        ASSERT_FALSE(engine.IsBanned());
        ASSERT_FALSE(engine.IsShadowFlagged());
        ASSERT_FALSE(engine.IsMatchRestricted());
        ASSERT_FALSE(engine.IsSessionRejected());
    }

    // 2. SHADOW mode: Sets only shadow ban
    {
        EngineConfig cfg = EngineConfig::ShadowProductionProfile();
        cfg.enforcementMode = EnforcementMode::SHADOW;
        cfg.requireMultiSignalCorroboration = false;
        AntiCheatEngine engine(cfg);

        DetectionEvent ev{DetectionType::UNBACKED_EXECUTABLE_MEMORY, Severity::CRITICAL, "MemScan", "det", 1000, 100};
        engine.ProcessDetection(ev);

        ASSERT_FALSE(engine.IsBanned());
        ASSERT_TRUE(engine.IsShadowFlagged());
        ASSERT_FALSE(engine.IsMatchRestricted());
        ASSERT_FALSE(engine.IsSessionRejected());
    }

    // 3. MATCH_RESTRICTION mode: Sets only match restriction
    {
        EngineConfig cfg;
        cfg.enforcementMode = EnforcementMode::MATCH_RESTRICTION;
        cfg.requireMultiSignalCorroboration = false;
        AntiCheatEngine engine(cfg);

        DetectionEvent ev{DetectionType::UNBACKED_EXECUTABLE_MEMORY, Severity::CRITICAL, "MemScan", "det", 1000, 100};
        engine.ProcessDetection(ev);

        ASSERT_FALSE(engine.IsBanned());
        ASSERT_FALSE(engine.IsShadowFlagged());
        ASSERT_TRUE(engine.IsMatchRestricted());
        ASSERT_FALSE(engine.IsSessionRejected());
    }

    // 4. SERVER_SESSION_REJECT mode: Sets session rejection
    {
        EngineConfig cfg;
        cfg.enforcementMode = EnforcementMode::SERVER_SESSION_REJECT;
        cfg.requireMultiSignalCorroboration = false;
        AntiCheatEngine engine(cfg);

        DetectionEvent ev{DetectionType::UNBACKED_EXECUTABLE_MEMORY, Severity::CRITICAL, "MemScan", "det", 1000, 100};
        engine.ProcessDetection(ev);

        ASSERT_FALSE(engine.IsBanned());
        ASSERT_FALSE(engine.IsShadowFlagged());
        ASSERT_FALSE(engine.IsMatchRestricted());
        ASSERT_TRUE(engine.IsSessionRejected());
    }

    // 5. ENFORCE mode: Full enforcement triggering ban, match restriction, session reject
    {
        EngineConfig cfg;
        cfg.enforcementMode = EnforcementMode::ENFORCE;
        cfg.enforceBanOnViolation = true;
        cfg.banScoreThreshold = 100;
        cfg.requireMultiSignalCorroboration = false;
        AntiCheatEngine engine(cfg);

        DetectionEvent ev{DetectionType::UNBACKED_EXECUTABLE_MEMORY, Severity::CRITICAL, "MemScan", "det", 1000, 100};
        engine.ProcessDetection(ev);

        ASSERT_TRUE(engine.IsBanned());
        ASSERT_TRUE(engine.IsMatchRestricted());
        ASSERT_TRUE(engine.IsSessionRejected());
    }

    // 6. Test SDK Public Query APIs
    {
        NoEscapeConfig cfg = NoEscape_GetProfileConfig(NOESCAPE_PROFILE_TESTING);
        cfg.enforcement_mode = static_cast<int>(EnforcementMode::ENFORCE);
        ASSERT_EQ(NoEscape_Init(&cfg), 0);

        ASSERT_FALSE(NoEscape_IsBanned());
        ASSERT_FALSE(NoEscape_IsShadowFlagged());
        ASSERT_FALSE(NoEscape_IsMatchRestricted());
        ASSERT_FALSE(NoEscape_IsSessionRejected());

        ASSERT_FALSE(noescape::sdk::Client::IsBanned());
        ASSERT_FALSE(noescape::sdk::Client::IsShadowFlagged());
        ASSERT_FALSE(noescape::sdk::Client::IsMatchRestricted());
        ASSERT_FALSE(noescape::sdk::Client::IsSessionRejected());

        NoEscape_Shutdown();
    }
}

// ============================================================================
// P0-3: Ed25519 Canonical Scalar Validation & Strict Point Encoding
// ============================================================================

TEST(RemediationV1_4, Ed25519CanonicalScalarAndMalformedSignaturesRejected) {
    auto kp = CryptoUtil::GenerateAsymmetricKeyPair();
    std::string msg = "CanonicalTestPayload";
    std::string sigHex = CryptoUtil::SignAsymmetric(kp.private_key_hex, msg);
    ASSERT_EQ(sigHex.length(), 128);

    auto pubBytes = CryptoUtil::FromHex(kp.public_key_hex);
    auto sigBytes = CryptoUtil::FromHex(sigHex);
    ASSERT_EQ(pubBytes.size(), 32);
    ASSERT_EQ(sigBytes.size(), 64);

    // Verify original signature is valid on both Verify (audited/provider) and VerifySoftware (pure C++)
    ASSERT_TRUE(ed25519::Verify(pubBytes.data(),
                                reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                sigBytes.data()));
    ASSERT_TRUE(ed25519::VerifySoftware(pubBytes.data(),
                                        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                        sigBytes.data()));

    // The order L in little-endian format (32 bytes):
    const uint8_t L_order[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };

    // 1. Signature with S exactly equal to L: MUST FAIL on both providers
    std::vector<uint8_t> sigWithL = sigBytes;
    std::memcpy(sigWithL.data() + 32, L_order, 32);
    ASSERT_FALSE(ed25519::Verify(pubBytes.data(),
                                 reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                 sigWithL.data()));
    ASSERT_FALSE(ed25519::VerifySoftware(pubBytes.data(),
                                         reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                         sigWithL.data()));

    // 2. Signature with S = L + 1: MUST FAIL on both providers
    std::vector<uint8_t> sigWithLPlus1 = sigWithL;
    sigWithLPlus1[32] = 0xee; // 0xed + 1
    ASSERT_FALSE(ed25519::Verify(pubBytes.data(),
                                 reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                 sigWithLPlus1.data()));
    ASSERT_FALSE(ed25519::VerifySoftware(pubBytes.data(),
                                         reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                         sigWithLPlus1.data()));

    // 3. Signature with S = 2^255 - 1: MUST FAIL on both providers
    std::vector<uint8_t> sigMax = sigBytes;
    for (size_t i = 32; i < 63; ++i) sigMax[i] = 0xFF;
    sigMax[63] = 0x7F;
    ASSERT_FALSE(ed25519::Verify(pubBytes.data(),
                                 reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                 sigMax.data()));
    ASSERT_FALSE(ed25519::VerifySoftware(pubBytes.data(),
                                         reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                         sigMax.data()));
}

TEST(RemediationV1_4, Ed25519RejectsNonCanonicalPointEncodingsAndNegativeZero) {
    auto kp = CryptoUtil::GenerateAsymmetricKeyPair();
    std::string msg = "PointEncodingTest";
    std::string sigHex = CryptoUtil::SignAsymmetric(kp.private_key_hex, msg);
    auto pubBytes = CryptoUtil::FromHex(kp.public_key_hex);
    auto sigBytes = CryptoUtil::FromHex(sigHex);

    // 1. Non-canonical public key with y >= 2^255 - 19 (y = 2^255 - 18)
    std::vector<uint8_t> nonCanonicalPub = pubBytes;
    for (size_t i = 0; i < 31; ++i) nonCanonicalPub[i] = 0xFF;
    nonCanonicalPub[0] = 0xEE; // >= 0xED
    nonCanonicalPub[31] = 0x7F;
    ASSERT_FALSE(ed25519::Verify(nonCanonicalPub.data(),
                                 reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                 sigBytes.data()));
    ASSERT_FALSE(ed25519::VerifySoftware(nonCanonicalPub.data(),
                                         reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                         sigBytes.data()));

    // 2. Non-canonical signature commitment R with y >= 2^255 - 19
    std::vector<uint8_t> nonCanonicalR = sigBytes;
    for (size_t i = 0; i < 31; ++i) nonCanonicalR[i] = 0xFF;
    nonCanonicalR[0] = 0xEE;
    nonCanonicalR[31] = 0x7F;
    ASSERT_FALSE(ed25519::Verify(pubBytes.data(),
                                 reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                 nonCanonicalR.data()));
    ASSERT_FALSE(ed25519::VerifySoftware(pubBytes.data(),
                                         reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                         nonCanonicalR.data()));

    // 3. RFC 8032 Section 5.1.3 Negative Zero Test: x = 0 with sign bit = 1 on public key
    // Point (0, 1): y = 1 encoded with top bit (sign) = 1 -> byte[0] = 0x01, byte[31] = 0x80
    std::vector<uint8_t> negZeroPub(32, 0);
    negZeroPub[0] = 0x01;
    negZeroPub[31] = 0x80;
    ASSERT_FALSE(ed25519::Verify(negZeroPub.data(),
                                 reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                 sigBytes.data()));
    ASSERT_FALSE(ed25519::VerifySoftware(negZeroPub.data(),
                                         reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                         sigBytes.data()));

    // 4. Negative zero on commitment R
    std::vector<uint8_t> negZeroR = sigBytes;
    std::memcpy(negZeroR.data(), negZeroPub.data(), 32);
    ASSERT_FALSE(ed25519::Verify(pubBytes.data(),
                                 reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                 negZeroR.data()));
    ASSERT_FALSE(ed25519::VerifySoftware(pubBytes.data(),
                                         reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                                         negZeroR.data()));
}

TEST(RemediationV1_4, Ed25519KnownAnswerTestVectorsBothProviders) {
    // RFC 8032 Section 7.1 Test Vector 1 (Empty message)
    std::string pub1Hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    std::string msg1 = "";
    std::string sig1Hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    auto pub1 = CryptoUtil::FromHex(pub1Hex);
    auto sig1 = CryptoUtil::FromHex(sig1Hex);
    ASSERT_TRUE(ed25519::Verify(pub1.data(), reinterpret_cast<const uint8_t*>(msg1.data()), msg1.size(), sig1.data()));
    ASSERT_TRUE(ed25519::VerifySoftware(pub1.data(), reinterpret_cast<const uint8_t*>(msg1.data()), msg1.size(), sig1.data()));

    // RFC 8032 Section 7.1 Test Vector 2 (1-byte message: 0x72)
    std::string pub2Hex = "dee9b74d69fac31bbbf8e3cc317ab5e1d6e8fda98ed31bb52c23881ce4198dcd";
    std::string msg2 = "\x72";
    std::string sig2Hex = "55278ef4887a7bd31043dcab71a8c9a2c83531be997024e12955e34989202d0b415cfaedfba299f7c2cc677bd57602cd113820ead58101f48a0dd09372a27703";

    auto pub2 = CryptoUtil::FromHex(pub2Hex);
    auto sig2 = CryptoUtil::FromHex(sig2Hex);
    ASSERT_TRUE(ed25519::Verify(pub2.data(), reinterpret_cast<const uint8_t*>(msg2.data()), msg2.size(), sig2.data()));
    ASSERT_TRUE(ed25519::VerifySoftware(pub2.data(), reinterpret_cast<const uint8_t*>(msg2.data()), msg2.size(), sig2.data()));

    // RFC 8032 Section 7.1 Test Vector 3 (2-byte message: 0xaf 0x82)
    std::string pub3Hex = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
    std::string msg3 = "\xaf\x82";
    std::string sig3Hex = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

    auto pub3 = CryptoUtil::FromHex(pub3Hex);
    auto sig3 = CryptoUtil::FromHex(sig3Hex);
    ASSERT_TRUE(ed25519::Verify(pub3.data(), reinterpret_cast<const uint8_t*>(msg3.data()), msg3.size(), sig3.data()));
    ASSERT_TRUE(ed25519::VerifySoftware(pub3.data(), reinterpret_cast<const uint8_t*>(msg3.data()), msg3.size(), sig3.data()));
}

// ============================================================================
// P1-1: Match / Session Lifecycle SDK Isolation
// ============================================================================

TEST(RemediationV1_4, MatchLifecyclePreventsEvidenceBleedAcrossMatches) {
    EngineConfig cfg = EngineConfig::ProductionProfile();
    cfg.enforcementMode = EnforcementMode::ENFORCE;
    cfg.enforceBanOnViolation = true;
    cfg.banScoreThreshold = 100;
    cfg.requireMultiSignalCorroboration = true;
    AntiCheatEngine engine(cfg);

    // 1. Begin Match 1
    engine.BeginMatch("match_season1_game001");

    // Ingest suspicious event in Category A (Memory) in Match 1
    DetectionEvent ev1;
    ev1.type = DetectionType::UNBACKED_EXECUTABLE_MEMORY;
    ev1.severity = Severity::CRITICAL;
    ev1.component = "MemoryScanner";
    ev1.details = "Match 1 memory finding";
    ev1.threat_score = 40;
    engine.ProcessDetection(ev1);

    ASSERT_EQ(engine.GetThreatScore(), 40u);
    ASSERT_EQ(engine.GetEvidenceCorrelator().GetActiveCategoryCount(), 1u);
    ASSERT_FALSE(engine.IsBanned());

    // 2. End Match 1
    engine.EndMatch();
    ASSERT_EQ(engine.GetThreatScore(), 0u);

    // 3. Begin Match 2 with same or different match ID
    engine.BeginMatch("match_season1_game001"); // Restart same ID to test strict reset

    // Prior match evidence MUST be completely cleared
    ASSERT_EQ(engine.GetThreatScore(), 0u);
    ASSERT_EQ(engine.GetEvidenceCorrelator().GetActiveCategoryCount(), 0u);
    ASSERT_TRUE(engine.GetEvidenceCorrelator().GetAggregatedEvidence().empty());

    // Ingest event in Category B (DMA) in Match 2
    DetectionEvent ev2;
    ev2.type = DetectionType::DMA_PCIE_LEECH_DEVICE;
    ev2.severity = Severity::CRITICAL;
    ev2.component = "DmaDetector";
    ev2.details = "Match 2 DMA finding";
    ev2.threat_score = 40;
    engine.ProcessDetection(ev2);

    // Active category count must be 1, NOT 2 (evidence from Match 1 did not bleed into Match 2)
    ASSERT_EQ(engine.GetEvidenceCorrelator().GetActiveCategoryCount(), 1u);
    ASSERT_EQ(engine.GetThreatScore(), 40u);
    ASSERT_FALSE(engine.IsBanned());
    ASSERT_FALSE(engine.IsSessionRejected());
}

// ============================================================================
// P1-2: Bounded Engine State and Retention Limits
// ============================================================================

TEST(RemediationV1_4, EngineStateRemainsStrictlyBoundedUnderHighEventLoad) {
    EngineConfig cfg = EngineConfig::TestingProfile();
    AntiCheatEngine engine(cfg);
    engine.SetMaxHistoryCapacity(64); // Tight cap of 64 events

    // Feed 500 unique events
    for (uint32_t i = 0; i < 500; ++i) {
        DetectionEvent ev;
        ev.type = DetectionType::ENVIRONMENT_TAMPERING;
        ev.severity = Severity::LOW;
        ev.component = "StressProducer";
        ev.details = "Unique observation #" + std::to_string(i);
        ev.timestamp = 100000 + i;
        ev.timestamp_utc_ms = 1700000000000ULL + i;
        ev.threat_score = 1;
        engine.ProcessDetection(ev);
    }

    // Engine history must be strictly bounded to 64
    auto history = engine.GetDetectionHistory();
    ASSERT_LE(history.size(), 64u);
    ASSERT_EQ(history.back().details, "Unique observation #499");

    // Scored keys tracking must be strictly bounded to max_history_capacity * 2 (128)
    ASSERT_LE(engine.GetScoredKeysCount(), 128u);

    // PruneHistory cleans up aged events
    engine.PruneHistory(100);
}

// ============================================================================
// P1-3: Production SDK Configuration Validation
// ============================================================================

TEST(RemediationV1_4, ProductionProfileHasNoHardcodedSecretsAndValidatesExplicitBackend) {
    NoEscapeConfig prodCfg = NoEscape_GetProfileConfig(NOESCAPE_PROFILE_PRODUCTION);

    // Must NOT have hardcoded secret key or localhost panel URL
    ASSERT_EQ(prodCfg.panel_url, nullptr);
    ASSERT_EQ(prodCfg.secret_key, nullptr);
    ASSERT_EQ(prodCfg.server_public_key, nullptr);

    // ValidateConfig must fail on unconfigured production config
    char errBuf[256]{};
    int rc = NoEscape_ValidateConfig(&prodCfg, errBuf, sizeof(errBuf));
    ASSERT_NE(rc, 0);
    ASSERT_TRUE(std::strstr(errBuf, "panel_url") != nullptr);

    // Provide panel URL but missing secret key
    prodCfg.panel_url = "https://ac.gamebackend.internal/api/ac";
    rc = NoEscape_ValidateConfig(&prodCfg, errBuf, sizeof(errBuf));
    ASSERT_NE(rc, 0);
    ASSERT_TRUE(std::strstr(errBuf, "secret_key") != nullptr);

    // Provide secret key but missing server public key
    prodCfg.secret_key = "DedicatedDeploymentSecretToken!99";
    rc = NoEscape_ValidateConfig(&prodCfg, errBuf, sizeof(errBuf));
    ASSERT_NE(rc, 0);
    ASSERT_TRUE(std::strstr(errBuf, "server_public_key") != nullptr);

    // Provide valid 64-hex server public key -> now valid!
    prodCfg.server_public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    rc = NoEscape_ValidateConfig(&prodCfg, errBuf, sizeof(errBuf));
    ASSERT_EQ(rc, 0);
}

// ============================================================================
// P1-4: Server Integration Visibility Adapter & Occlusion Transparency
// ============================================================================

class MockEngineVisibilityAdapter : public IAuthoritativeVisibilityAdapter {
public:
    bool occlude_all{false};
    mutable int raycast_count{0};

    bool LineOfSightBlocked(float, float, float, float, float, float, bool) const override {
        ++raycast_count;
        return occlude_all;
    }
};

TEST(RemediationV1_4, ServerEspFilterAuthoritativeVisibilityAdapter) {
    ServerEspFilter filter;
    ObserverState obs{1, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 90.0f};
    TargetEntityState target{2, 10.0f, 0.0f, 0.0f, 0.5f, false, 0.0f};

    // 1. Unconfigured occlusion: HasOcclusionData() is false, decision flags occlusion_unconfigured
    ASSERT_FALSE(filter.HasOcclusionData());
    auto decUnconfigured = filter.EvaluateEntityReplication(obs, target);
    ASSERT_TRUE(decUnconfigured.occlusion_unconfigured);
    ASSERT_TRUE(decUnconfigured.replicate_full_transform);

    // 2. Attach authoritative engine visibility adapter
    auto adapter = std::make_shared<MockEngineVisibilityAdapter>();
    adapter->occlude_all = true;
    filter.SetVisibilityAdapter(adapter);

    ASSERT_TRUE(filter.HasOcclusionData());
    auto decOccluded = filter.EvaluateEntityReplication(obs, target);
    ASSERT_FALSE(decOccluded.occlusion_unconfigured);
    ASSERT_TRUE(decOccluded.culled_by_occlusion);
    ASSERT_FALSE(decOccluded.replicate_full_transform);
    ASSERT_GT(adapter->raycast_count, 0);
}

// ============================================================================
// P1-5: Cryptographic CSPRNG Nonce Quality and Error Propagation
// ============================================================================

TEST(RemediationV1_4, CryptoUtilAndPanelClientUseOsCsprngWithoutCollision) {
    uint8_t randomBuf[32]{};
    ASSERT_TRUE(CryptoUtil::GenerateRandomBytes(randomBuf, sizeof(randomBuf)));

    // Ensure not all zero
    bool allZero = true;
    for (uint8_t b : randomBuf) {
        if (b != 0) { allZero = false; break; }
    }
    ASSERT_FALSE(allZero);

    // 1,000 nonces: must be 32 hex chars and have zero collisions
    std::unordered_set<std::string> seenNonces;
    for (int i = 0; i < 1000; ++i) {
        std::string nonce = PanelClient::RandomNonce();
        ASSERT_EQ(nonce.length(), 32u);
        ASSERT_TRUE(seenNonces.insert(nonce).second);
    }
}

// ============================================================================
// Concurrency & High-Contention Stress Test
// ============================================================================

TEST(RemediationV1_4, ConcurrencyMatchLifecycleAndContinuousDetections) {
    EngineConfig cfg = EngineConfig::TestingProfile();
    AntiCheatEngine engine(cfg);

    std::atomic<bool> stop_flag{false};
    std::vector<std::thread> workers;

    // 4 threads rapidly injecting detection events
    for (int t = 0; t < 4; ++t) {
        workers.emplace_back([&engine, &stop_flag, t]() {
            uint32_t counter = 0;
            while (!stop_flag.load(std::memory_order_relaxed)) {
                DetectionEvent ev;
                ev.type = DetectionType::ENVIRONMENT_TAMPERING;
                ev.severity = Severity::LOW;
                ev.component = "WorkerThread_" + std::to_string(t);
                ev.details = "Contention test #" + std::to_string(counter++);
                ev.threat_score = 1;
                engine.ProcessDetection(ev);
            }
        });
    }

    // 1 thread continuously cycling matches
    workers.emplace_back([&engine, &stop_flag]() {
        int matchNum = 0;
        while (!stop_flag.load(std::memory_order_relaxed)) {
            engine.BeginMatch("concurrent_match_" + std::to_string(matchNum++));
            std::this_thread::yield();
            engine.EndMatch();
        }
    });

    // Run contention for 150 milliseconds
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    stop_flag.store(true, std::memory_order_release);

    for (auto& w : workers) {
        if (w.joinable()) w.join();
    }

    // Verify engine state remains intact and bounded
    ASSERT_LE(engine.GetDetectionHistory().size(), engine.GetMaxHistoryCapacity());
}
