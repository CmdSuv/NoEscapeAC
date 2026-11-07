#include "tests/test_framework.hpp"
#include "noescape/core/blackbox.hpp"
#include "noescape/core/engine.hpp"
#include <filesystem>
#include <fstream>

using namespace noescape::core;

TEST(Blackbox, BacktraceCapture) {
    auto frames = BlackboxDumper::CaptureBacktrace(16);
    ASSERT_GT(frames.size(), 0);
}

TEST(Blackbox, InputTrailCircularBuffer) {
    auto& dumper = BlackboxDumper::Instance();
    dumper.ClearInputTrail();
    ASSERT_EQ(dumper.GetInputTrailCount(), 0);

    for (int i = 0; i < 70; ++i) {
        dumper.RecordInputSample(static_cast<float>(i), static_cast<float>(i * 2), 1000 + i * 16);
    }

    // Capacity is 64; 70 pushes should cap at 64
    ASSERT_EQ(dumper.GetInputTrailCount(), 64);

    dumper.ClearInputTrail();
}

TEST(Blackbox, SnapshotCaptureAndSerializationRoundTrip) {
    auto& dumper = BlackboxDumper::Instance();
    dumper.ClearInputTrail();

    // Fill in a few input samples
    for (int i = 0; i < 5; ++i) {
        dumper.RecordInputSample(1.5f * i, 2.5f * i, 10000 + i * 16);
    }

    std::string key = "TestSuperSecretKey123!@#";
    auto snap = dumper.CaptureSnapshot("Kinematics::AimbotDetector", "Instant 90-degree Snap Detected", 85, 14);

    ASSERT_EQ(snap.violating_component, "Kinematics::AimbotDetector");
    ASSERT_EQ(snap.violation_reason, "Instant 90-degree Snap Detected");
    ASSERT_EQ(snap.threat_score, 85);
    ASSERT_EQ(snap.violation_type, 14);
    ASSERT_FALSE(snap.hwid.empty());
    ASSERT_EQ(snap.recent_input_trail.size(), 5);
    ASSERT_GT(snap.backtrace_addrs.size(), 0);

    // Serialize and encrypt
    auto encrypted = dumper.SerializeAndEncrypt(snap, key);
    ASSERT_GT(encrypted.size(), 90);
    // Magic check
    ASSERT_EQ(encrypted[0], 'N');
    ASSERT_EQ(encrypted[1], 'E');
    ASSERT_EQ(encrypted[2], 'B');
    ASSERT_EQ(encrypted[3], 'B');

    // Decrypt and deserialize
    BlackboxRecord decrypted{};
    bool success = dumper.DecryptAndDeserialize(encrypted, key, decrypted);
    ASSERT_TRUE(success);

    ASSERT_EQ(decrypted.timestamp, snap.timestamp);
    ASSERT_EQ(decrypted.threat_score, snap.threat_score);
    ASSERT_EQ(decrypted.violation_type, snap.violation_type);
    ASSERT_EQ(decrypted.hwid, snap.hwid);
    ASSERT_EQ(decrypted.violating_component, snap.violating_component);
    ASSERT_EQ(decrypted.violation_reason, snap.violation_reason);
    ASSERT_EQ(decrypted.backtrace_addrs.size(), snap.backtrace_addrs.size());
    ASSERT_EQ(decrypted.recent_input_trail.size(), snap.recent_input_trail.size());

    for (size_t i = 0; i < snap.recent_input_trail.size(); ++i) {
        ASSERT_NEAR(decrypted.recent_input_trail[i].pitch, snap.recent_input_trail[i].pitch, 0.0001f);
        ASSERT_NEAR(decrypted.recent_input_trail[i].yaw, snap.recent_input_trail[i].yaw, 0.0001f);
        ASSERT_EQ(decrypted.recent_input_trail[i].timestamp_ms, snap.recent_input_trail[i].timestamp_ms);
    }
}

TEST(Blackbox, TamperResistanceCiphertextMutation) {
    auto& dumper = BlackboxDumper::Instance();
    std::string key = "TamperResistanceKey_v1";

    auto snap = dumper.CaptureSnapshot("Unhooker::Integrity", "Kernel inline hook detected", 95, 8);
    auto encrypted = dumper.SerializeAndEncrypt(snap, key);

    // Mutate a byte in the ciphertext body
    size_t targetByte = 30; // Within IV/ciphertext region
    ASSERT_LT(targetByte, encrypted.size());
    encrypted[targetByte] ^= 0x55;

    BlackboxRecord outRecord{};
    bool success = dumper.DecryptAndDeserialize(encrypted, key, outRecord);
    // HMAC check MUST fail on any single-bit mutation
    ASSERT_FALSE(success);
}

TEST(Blackbox, TamperResistanceWrongKey) {
    auto& dumper = BlackboxDumper::Instance();
    std::string correctKey = "CorrectKey999";
    std::string wrongKey = "AttackerForgedKey";

    auto snap = dumper.CaptureSnapshot("ProcessAnalyzer", "CheatEngine detected", 100, 11);
    auto encrypted = dumper.SerializeAndEncrypt(snap, correctKey);

    BlackboxRecord outRecord{};
    bool success = dumper.DecryptAndDeserialize(encrypted, wrongKey, outRecord);
    ASSERT_FALSE(success);
}

TEST(Blackbox, FileDumpSaving) {
    auto& dumper = BlackboxDumper::Instance();
    std::string key = "DumpFileTestKey";
    auto snap = dumper.CaptureSnapshot("OverlayDetector", "Fake Window Detected", 75, 18);
    auto encrypted = dumper.SerializeAndEncrypt(snap, key);

    std::string testPath = "/tmp/test_blackbox_output.dmp";
    ASSERT_TRUE(dumper.SaveDumpToFile(testPath, encrypted));

    ASSERT_TRUE(std::filesystem::exists(testPath));
    ASSERT_GT(std::filesystem::file_size(testPath), 90);

    // Read back and decrypt
    std::ifstream ifs(testPath, std::ios::binary);
    std::vector<uint8_t> readBytes((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();

    BlackboxRecord readRecord{};
    ASSERT_TRUE(dumper.DecryptAndDeserialize(readBytes, key, readRecord));
    ASSERT_EQ(readRecord.violating_component, "OverlayDetector");

    std::filesystem::remove(testPath);
}

TEST(Blackbox, TriggerBanDiagnosticCaptureIntegrity) {
    EngineConfig cfg = EngineConfig::TestingProfile();
    cfg.enableHeartbeat = false;
    cfg.banScoreThreshold = 50;
    cfg.enforceBanOnViolation = true;
    cfg.enableBlackboxDump = true;
    cfg.blackboxDumpDirectory = "/tmp";
    cfg.secretKey = "BlackboxIntegrityKey!@#";

    AntiCheatEngine engine(cfg);
    ASSERT_TRUE(engine.Initialize());

    // Trigger a specific detection
    DetectionEvent ev;
    ev.type = DetectionType::OVERLAY_HIJACK_DETECTED;
    ev.severity = Severity::FATAL_BAN;
    ev.threat_score = 100;
    ev.component = "OverlayDetector::WindowScanner";
    ev.details = "ESP Overlay detected";
    engine.ProcessDetection(ev);

    ASSERT_TRUE(engine.IsBanned());
    const auto& payload = engine.GetLastBlackboxPayload();
    ASSERT_GT(payload.size(), 90);

    BlackboxRecord rec{};
    ASSERT_TRUE(BlackboxDumper::Instance().DecryptAndDeserialize(payload, cfg.secretKey, rec));
    ASSERT_EQ(rec.violating_component, "OverlayDetector::WindowScanner");
    ASSERT_EQ(rec.violation_reason, "ESP Overlay detected");
    ASSERT_EQ(rec.violation_type, static_cast<uint32_t>(DetectionType::OVERLAY_HIJACK_DETECTED));
    ASSERT_EQ(rec.threat_score, 100);
}
