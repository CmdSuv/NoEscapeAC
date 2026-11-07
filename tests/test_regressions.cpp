// Regression tests for the issues found in the full code audit.
#include "tests/test_framework.hpp"
#include "noescape_sdk.h"
#include "noescape/core/engine.hpp"
#include "noescape/core/blackbox.hpp"
#include "noescape/core/envutil.hpp"
#include "noescape/kinematics/aim_analyzer.hpp"
#include "noescape/memory/memory_scanner.hpp"
#include "noescape/overlay/overlay_detector.hpp"
#include "noescape/network/crypto_util.hpp"
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <thread>

using namespace noescape;

TEST(Regression, BlackboxCipherLenOverflowRejected) {
    std::vector<uint8_t> pk(200, 0);
    pk[0] = 'N'; pk[1] = 'E'; pk[2] = 'B'; pk[3] = 'B'; pk[4] = 1;
    uint32_t cl = 0xFFFFFFC0u; // cipherLen + 64 wraps to 0 in 32-bit arithmetic
    for (int i = 0; i < 4; ++i) pk[22 + i] = static_cast<uint8_t>((cl >> (8 * i)) & 0xFF);
    core::BlackboxRecord r;
    ASSERT_FALSE(core::BlackboxDumper::Instance().DecryptAndDeserialize(pk, "k", r));
}

TEST(Regression, ConstantTimeEquals) {
    ASSERT_TRUE(network::CryptoUtil::ConstantTimeEquals("abc", "abc"));
    ASSERT_FALSE(network::CryptoUtil::ConstantTimeEquals("abc", "abd"));
    ASSERT_FALSE(network::CryptoUtil::ConstantTimeEquals("abc", "abcd"));
}

TEST(Regression, NameMatchingIsNotSubstring) {
    ASSERT_TRUE(core::NameMatchesEntry("gdb", "gdb"));
    ASSERT_TRUE(core::NameMatchesEntry("gdb-multiarch", "gdb"));
    ASSERT_FALSE(core::NameMatchesEntry("gdbus", "gdb"));
    ASSERT_FALSE(core::NameMatchesEntry("validator", "ida"));
    ASSERT_FALSE(core::NameMatchesEntry("tidal", "ida"));
}

TEST(Regression, AxisAlignedPanIsNotLinearityCheat) {
    kinematics::AimAnalyzer a(64);
    int hits = 0;
    for (int i = 0; i < 60; ++i) {
        if (a.PushSample(0.0f, i * 2.0f, 1000 + i * 8)) ++hits; // gamepad full-stick yaw pan
    }
    ASSERT_EQ(hits, 0);
}

TEST(Regression, DiagonalRoboticSweepStillDetected) {
    kinematics::AimAnalyzer a(64);
    int hits = 0;
    for (int i = 0; i < 40; ++i) {
        if (a.PushSample(i * 1.0f, i * 2.0f, 1000 + i * 8)) ++hits;
    }
    ASSERT_GT(hits, 0);
}

TEST(Regression, FrameFlickIsNoLongerInstantBan) {
    kinematics::AimAnalyzer a(64);
    a.PushSample(0, 0, 1000);
    a.PushSample(0, 0.3f, 1016);
    auto ev = a.PushSample(0, 25.3f, 1032);
    auto ev2 = a.PushSample(0, 25.4f, 1048);
    auto e = ev ? ev : ev2;
    if (e) ASSERT_NE(static_cast<int>(e->severity), static_cast<int>(core::Severity::FATAL_BAN));
}

TEST(Regression, ClockResetDoesNotDisableAnalysis) {
    kinematics::AimAnalyzer a(64);
    a.PushSample(0, 0, 5'000'000);
    a.PushSample(0, 1, 5'000'010);
    a.PushSample(0, 2, 100); // timer restarted
    ASSERT_EQ(static_cast<int>(a.GetHistorySize()), 1);
}

TEST(Regression, SdkRejectsNonFiniteInput) {
    NoEscapeConfig cfg = NoEscape_GetDefaultConfig();
    cfg.show_ban_ui = false;
    cfg.enable_dma_detection = false;
    ASSERT_EQ(NoEscape_Init(&cfg), 0);
    // Previously: infinite loop (1e30) / permanently poisoned accumulator (NaN)
    NoEscape_PushMouseEvent(1e30f, 0.0f, 100);
    NoEscape_PushMouseEvent(NAN, NAN, 110);
    NoEscape_PushMouseEvent(INFINITY, 0.0f, 120);
    NoEscape_ResetInput();
    NoEscape_Shutdown();
}

TEST(Regression, SdkZeroThresholdKeepsDefault) {
    NoEscapeConfig cfg{};
    cfg.panel_url = "http://127.0.0.1:1/api";
    cfg.secret_key = "k";
    cfg.ban_threshold = 0;
    ASSERT_EQ(NoEscape_Init(&cfg), 0);
    ASSERT_FALSE(NoEscape_IsBanned());
    NoEscape_Shutdown();
}

TEST(Regression, AuditCycleWorksWithoutStart) {
    core::EngineConfig cfg;
    cfg.enableDmaDetection = false;
    cfg.enableSpeedhackDetection = false;
    cfg.enforceBanOnViolation = false;
    cfg.enableHeartbeat = false;
    core::AntiCheatEngine engine(cfg);
    ASSERT_TRUE(engine.Initialize());
    // A persistent finding injected via ProcessDetection must score only once
    core::DetectionEvent ev;
    ev.type = core::DetectionType::SUSPICIOUS_PROCESS_DETECTED;
    ev.severity = core::Severity::HIGH;
    ev.component = "Test";
    ev.details = "Blacklisted process: PID 1";
    ev.threat_score = 80;
    for (int i = 0; i < 20; ++i) engine.ProcessDetection(ev);
    ASSERT_EQ(engine.GetThreatScore(), 80u);
    // Synchronous audit must execute (previously returned immediately unless Start() was called)
    engine.AuditCycle();
    ASSERT_GT(engine.GetLastAuditHeartbeatMs(), 0u);
}

TEST(Regression, PersistentFindingDoesNotSnowballIntoBan) {
    core::EngineConfig cfg;
    cfg.enforceBanOnViolation = true;
    cfg.banScoreThreshold = 100;
    cfg.showBanUi = false;
    cfg.terminateProcessOnBan = false;
    cfg.enableHeartbeat = false;
    // NOESCAPE_TEST_MODE=1 is set by test_main (no ban UI / process termination)
    core::AntiCheatEngine engine(cfg);
    core::DetectionEvent ev;
    ev.type = core::DetectionType::ANTI_DEBUG_TOOL;
    ev.severity = core::Severity::HIGH;
    ev.component = "AntiDebug::ProcessScanner";
    ev.details = "tool running: gdb";
    ev.threat_score = 60;
    for (int i = 0; i < 50; ++i) engine.ProcessDetection(ev);
    ASSERT_FALSE(engine.IsBanned());
    ASSERT_EQ(engine.GetThreatScore(), 60u);
}

TEST(Regression, MemoryCacheIsReferenceCounted) {
    auto& ms = memory::MemoryScanner::Instance();
    ms.RefreshCache();
    ms.RefreshCache();
    ms.ClearCache();
    ASSERT_TRUE(ms.IsCacheValid()); // second concurrent audit still holds its snapshot
    ms.ClearCache();
    ASSERT_FALSE(ms.IsCacheValid());
}

TEST(Regression, ScannerHasNoStringSignatureInstantBan) {
    for (const auto& sig : memory::MemoryScanner::GetDefaultCheatSignatures()) {
        if (sig.GetTargetRule() == memory::MemoryTargetRule::ANY_ANONYMOUS) {
            ASSERT_NE(static_cast<int>(sig.GetSeverity()), static_cast<int>(core::Severity::FATAL_BAN));
            ASSERT_LT(sig.GetThreatScore(), 100u);
        }
    }
}

#if !defined(_WIN32)
#include "noescape/memory/unhooker.hpp"
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

namespace {
bool PokeText(uintptr_t addr, const void* data, size_t len) {
    int fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = pwrite(fd, data, len, static_cast<off_t>(addr)) == static_cast<ssize_t>(len);
    close(fd);
    return ok;
}
} // namespace

TEST(Regression, UnhookerDetectsAndRestoresRealLibcDetour) {
    void* libc = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD);
    if (!libc) return;
    auto target = reinterpret_cast<uintptr_t>(dlsym(libc, "process_vm_writev"));
    if (!target) return;

    uint8_t original[16];
    std::memcpy(original, reinterpret_cast<const void*>(target), sizeof(original));

    // Detour into an anonymous stub (injected-cheat style), placed within rel32 range
    void* stub = mmap(reinterpret_cast<void*>((target & ~0xFFFull) - (64ull << 20)), 4096,
                      PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_TRUE(stub != MAP_FAILED);
    int64_t rel = static_cast<int64_t>(reinterpret_cast<uintptr_t>(stub)) - static_cast<int64_t>(target + 5);
    if (rel > INT32_MAX || rel < INT32_MIN) { munmap(stub, 4096); return; }
    uint8_t jmp[5] = {0xE9};
    int32_t r32 = static_cast<int32_t>(rel);
    std::memcpy(jmp + 1, &r32, 4);
    ASSERT_TRUE(PokeText(target, jmp, sizeof(jmp)));

    bool found = false;
    for (const auto& ev : memory::Unhooker::Instance().AuditSystemHooks()) {
        if (ev.details.find("'process_vm_writev'") != std::string::npos) {
            found = true;
            ASSERT_EQ(static_cast<int>(ev.severity), static_cast<int>(core::Severity::CRITICAL));
            ASSERT_TRUE(ev.details.find("RESTORED") != std::string::npos);
        }
    }
    bool restored = std::memcmp(reinterpret_cast<const void*>(target), original, sizeof(original)) == 0;
    if (!restored) PokeText(target, original, sizeof(original)); // never leave libc patched
    munmap(stub, 4096);
    ASSERT_TRUE(found);
    ASSERT_TRUE(restored);
}

TEST(Regression, UnhookerCleanProcessHasNoConfirmedHooks) {
    for (const auto& ev : memory::Unhooker::Instance().AuditSystemHooks()) {
        // Sanitizer interceptors are interposers, never inline patches of libc itself
        ASSERT_NE(static_cast<int>(ev.severity), static_cast<int>(core::Severity::CRITICAL));
    }
}
#endif

#if !defined(_WIN32)
#include "noescape/network/panel_client.hpp"
#include <fstream>
#include <sstream>

TEST(Regression, PanelUrlParsingRejectsInjectionAndBadPorts) {
    using PC = network::PanelClient;
    ASSERT_TRUE(PC::ParseUrl("https://panel.example.com/api").secure);
    ASSERT_EQ(PC::ParseUrl("https://panel.example.com/api").port, 443);
    ASSERT_EQ(PC::ParseUrl("http://[::1]:8443/x").host, std::string("::1"));
    ASSERT_EQ(PC::ParseUrl("http://[::1]:8443/x").port, 8443);
    ASSERT_FALSE(PC::ParseUrl("http://h:99999/").valid);
    ASSERT_FALSE(PC::ParseUrl("http://h:12ab/").valid);
    ASSERT_FALSE(PC::ParseUrl("http://h/a\r\nX-Evil: 1").valid);
    ASSERT_FALSE(PC::ParseUrl("ftp://h/").valid);
}

TEST(Regression, PanelTlsWithPinnedKeyAgainstReferenceServer) {
    if (!network::PanelClient::TlsSupported()) return;
    if (std::system("python3 --version >/dev/null 2>&1 && openssl version >/dev/null 2>&1") != 0) return;
    const std::string dir = "/tmp/noescape_tls_test";
    std::string gen = "mkdir -p " + dir + " && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes "
                      "-keyout " + dir + "/k.pem -out " + dir + "/c.pem -days 2 -subj /CN=localhost >/dev/null 2>&1 && "
                      "openssl x509 -in " + dir + "/c.pem -pubkey -noout | openssl pkey -pubin -outform der | "
                      "sha256sum | cut -d' ' -f1 > " + dir + "/pin";
    ASSERT_EQ(std::system(gen.c_str()), 0);
    std::ifstream pf(dir + "/pin");
    std::string pin;
    pf >> pin;
    ASSERT_EQ(pin.size(), 64u);

    const char* secret = "TlsSecret";
    std::string start = "NOESCAPE_REF_TLS_CERT=" + dir + "/c.pem NOESCAPE_REF_TLS_KEY=" + dir + "/k.pem python3 " +
                        std::string(NOESCAPE_SOURCE_DIR) + "/tools/reference_server.py 18432 " + secret +
                        " >/dev/null 2>&1 &";
    ASSERT_EQ(std::system(start.c_str()), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(800));

    network::PanelClient pinned("https://127.0.0.1:18432/api/ac", secret, pin);
    auto okRes = pinned.QueryBanStatus();
    bool heartbeatOk = pinned.SendHeartbeat(5, "HEALTHY");

    std::string wrongPin(64, 'a');
    network::PanelClient mitm("https://127.0.0.1:18432/api/ac", secret, wrongPin);
    auto mitmRes = mitm.QueryBanStatus();

    // No pin: WebPKI validation must reject the self-signed certificate
    network::PanelClient unpinned("https://127.0.0.1:18432/api/ac", secret);
    auto unpinnedRes = unpinned.QueryBanStatus();

    (void)!std::system("pkill -f 'reference_server.py 18432' >/dev/null 2>&1");

    ASSERT_EQ(static_cast<int>(okRes.status), static_cast<int>(network::BanCheckStatus::CLEAN));
    ASSERT_TRUE(heartbeatOk);
    ASSERT_EQ(static_cast<int>(mitmRes.status), static_cast<int>(network::BanCheckStatus::SIGNATURE_INVALID));
    ASSERT_EQ(static_cast<int>(unpinnedRes.status), static_cast<int>(network::BanCheckStatus::NETWORK_ERROR));
}
#endif

TEST(Regression, SignatureTextNeverContainsAnotherSignature) {
    // Names/descriptions live in heap copies (and freed residue) that the scanner reads: if one
    // contained a byte pattern the anti-cheat would detect itself.
    auto sigs = memory::MemoryScanner::GetDefaultCheatSignatures();
    for (const auto& pat : sigs) {
        std::string bytes;
        bool literal = true;
        for (const auto& b : pat.GetBytes()) {
            if (b.is_wildcard) { literal = false; break; }
            bytes.push_back(static_cast<char>(b.value));
        }
        if (!literal || bytes.empty()) continue;
        for (const auto& other : sigs) {
            ASSERT_TRUE(other.GetName().find(bytes) == std::string::npos);
            ASSERT_TRUE(other.GetDescription().find(bytes) == std::string::npos);
        }
    }
}

TEST(Regression, EngineCanBeRestartedAfterStop) {
    core::EngineConfig cfg;
    cfg.enableHeartbeat = false;
    cfg.enableDmaDetection = false;
    cfg.enforceBanOnViolation = false;
    core::AntiCheatEngine engine(cfg);
    ASSERT_TRUE(engine.Initialize());
    for (int i = 0; i < 3; ++i) {
        engine.Start();
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        ASSERT_GT(engine.GetLastAuditHeartbeatMs(), 0u);
        engine.Stop();
    }
}

#if !defined(_WIN32)
#include "noescape/security/integrity.hpp"
#include <limits.h>

namespace {
std::string HttpGetLocal(int port, const std::string& path) {
    std::string cmd = "python3 -c \"import urllib.request,sys;print(urllib.request.urlopen('http://127.0.0.1:" +
                      std::to_string(port) + path + "',timeout=3).read().decode())\" 2>/dev/null";
    std::string out;
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return out;
    char buf[256];
    while (fgets(buf, sizeof(buf), p)) out += buf;
    pclose(p);
    return out;
}
} // namespace

TEST(Regression, ServerSideAttestationAndSessionVerdict) {
    if (std::system("python3 --version >/dev/null 2>&1") != 0) return;
    char self[PATH_MAX]{};
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    ASSERT_TRUE(n > 0);

    const char* secret = "AttestSecret";
    std::string start = std::string("NOESCAPE_REF_IMAGE=") + self + " NOESCAPE_REF_SESSION_TTL=3 python3 " +
                        NOESCAPE_SOURCE_DIR + "/tools/reference_server.py 18433 " + secret + " >/dev/null 2>&1 &";
    ASSERT_EQ(std::system(start.c_str()), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));

    network::PanelClient client("http://127.0.0.1:18433/api/ac", secret);
    const std::string verdictPath = "/api/ac/session?hwid=" + client.GetHwid();
    auto& integrity = security::IntegrityChecker::Instance();
    ASSERT_TRUE(integrity.Initialize());

    // 0) before any heartbeat the player has no session
    bool noSession = HttpGetLocal(18433, verdictPath).find("\"valid\":false") != std::string::npos;

    // 1) honest client: heartbeat -> challenge -> correct answer -> valid session
    auto hb = client.Heartbeat(0, "HEALTHY");
    bool gotChallenge = hb.ok && hb.challenge.present && !hb.challenge.forged;
    std::string answer;
    bool answered = gotChallenge &&
        integrity.Attest(secret, hb.challenge.id, hb.challenge.nonce, hb.challenge.offset, hb.challenge.length, answer) &&
        client.SendAttestation(hb.challenge, answer);
    bool validAfterHonest = HttpGetLocal(18433, verdictPath).find("\"valid\":true") != std::string::npos;

    // 2) client whose code was patched cannot reproduce the reference bytes: wrong answer
    auto hb2 = client.Heartbeat(0, "HEALTHY");
    bool tamperedAccepted = true;
    if (hb2.ok && hb2.challenge.present && !hb2.challenge.forged) {
        std::string bogus(64, '0');
        tamperedAccepted = client.SendAttestation(hb2.challenge, bogus);
    }
    bool invalidAfterTamper = HttpGetLocal(18433, verdictPath).find("\"valid\":false") != std::string::npos;

    // 3) wrong secret: server's challenge signature is rejected by the client as forged
    network::PanelClient wrongSecret("http://127.0.0.1:18433/api/ac", "NotTheSecret");
    auto hb3 = wrongSecret.Heartbeat(0, "HEALTHY");

    (void)!std::system("pkill -f 'reference_server.py 18433' >/dev/null 2>&1");

    ASSERT_TRUE(noSession);
    ASSERT_TRUE(gotChallenge);
    ASSERT_TRUE(answered);
    ASSERT_TRUE(validAfterHonest);
    ASSERT_FALSE(tamperedAccepted);
    ASSERT_TRUE(invalidAfterTamper);
    ASSERT_FALSE(hb3.ok);
}

TEST(Regression, AttestationRangeIsBoundsChecked) {
    auto& integrity = security::IntegrityChecker::Instance();
    ASSERT_TRUE(integrity.Initialize());
    std::string out;
    ASSERT_FALSE(integrity.Attest("k", "id", "n", 0, 0, out));
    ASSERT_FALSE(integrity.Attest("k", "id", "n", integrity.TextSize(), 16, out));
    ASSERT_FALSE(integrity.Attest("k", "id", "n", 1, UINT64_MAX, out));
    ASSERT_FALSE(integrity.Attest("k", "id", "n", UINT64_MAX, 16, out));
    ASSERT_TRUE(integrity.Attest("k", "id", "n", 0, 64, out));
    ASSERT_EQ(out.size(), 64u);
}
#endif

TEST(Regression, AuditLoopDetectsDeadWatchdog) {
    core::EngineConfig cfg;
    cfg.enableHeartbeat = false;
    cfg.enableDmaDetection = false;
    cfg.enableMemoryScan = false;
    cfg.enableForensics = false;
    cfg.enableOverlayDetection = false;
    cfg.terminateProcessOnBan = false;
    cfg.showBanUi = false;
    cfg.enforceBanOnViolation = true;
    core::AntiCheatEngine engine(cfg);
    ASSERT_TRUE(engine.Initialize());
    engine.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    ASSERT_FALSE(engine.IsBanned());           // healthy: mutual supervision stays quiet

    // Attacker suspends/kills only the watchdog thread; the audit loop must notice by itself
    engine.FreezeWatchdogForTesting(true);
    engine.SetWatchdogHeartbeatForTesting(engine.GetWatchdogHeartbeatMs() - 5000);
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    bool banned = engine.IsBanned();
    bool reported = false;
    for (const auto& ev : engine.GetDetectionHistory())
        if (ev.component == "AntiCheatEngine::WatchdogSupervisor") reported = true;
    engine.FreezeWatchdogForTesting(false);
    engine.Stop();
    ASSERT_TRUE(reported);
    ASSERT_TRUE(banned);
}

TEST(Regression, HealthyEngineNeverSelfReportsWatchdogFailure) {
    core::EngineConfig cfg;
    cfg.enableHeartbeat = false;
    cfg.enableDmaDetection = false;
    cfg.enableMemoryScan = false;
    cfg.enableForensics = false;
    cfg.enableOverlayDetection = false;
    cfg.enforceBanOnViolation = false;
    core::AntiCheatEngine engine(cfg);
    ASSERT_TRUE(engine.Initialize());
    engine.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    engine.Stop();
    for (const auto& ev : engine.GetDetectionHistory())
        ASSERT_TRUE(ev.component.find("Watchdog") == std::string::npos);
}

#if !defined(_WIN32)
#include <sys/prctl.h>
#include "noescape/memory/canary_monitor.hpp"

TEST(Regression, UnhookerCleanProcessZeroEventsAndWorksWhenNonDumpable) {
    // 1. Clean process must emit zero inline hook events (including vDSO IFUNC routines)
    auto cleanEvents = memory::Unhooker::Instance().AuditSystemHooks();
    ASSERT_EQ(cleanEvents.size(), 0u);

    // 2. Even while PR_SET_DUMPABLE == 0, Unhooker::RestoreHook must succeed via WriteViaProcMem
    void* libc = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD);
    if (!libc) return;
    auto target = reinterpret_cast<uintptr_t>(dlsym(libc, "process_vm_writev"));
    if (!target) return;

    uint8_t original[16];
    std::memcpy(original, reinterpret_cast<const void*>(target), sizeof(original));

    void* stub = mmap(reinterpret_cast<void*>((target & ~0xFFFull) - (64ull << 20)), 4096,
                      PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_TRUE(stub != MAP_FAILED);
    int64_t rel = static_cast<int64_t>(reinterpret_cast<uintptr_t>(stub)) - static_cast<int64_t>(target + 5);
    if (rel > INT32_MAX || rel < INT32_MIN) { munmap(stub, 4096); return; }
    uint8_t jmp[5] = {0xE9};
    int32_t r32 = static_cast<int32_t>(rel);
    std::memcpy(jmp + 1, &r32, 4);
    ASSERT_TRUE(PokeText(target, jmp, sizeof(jmp)));

    // Simulate active anti-debug state (PR_SET_DUMPABLE = 0)
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    ASSERT_EQ(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0), 0);

    bool found = false;
    for (const auto& ev : memory::Unhooker::Instance().AuditSystemHooks()) {
        if (ev.details.find("'process_vm_writev'") != std::string::npos) {
            found = true;
            ASSERT_TRUE(ev.details.find("RESTORED") != std::string::npos);
        }
    }
    // Dumpable flag must remain 0 after WriteViaProcMem
    ASSERT_EQ(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0), 0);
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);

    bool restored = std::memcmp(reinterpret_cast<const void*>(target), original, sizeof(original)) == 0;
    if (!restored) PokeText(target, original, sizeof(original));
    munmap(stub, 4096);
    ASSERT_TRUE(found);
    ASSERT_TRUE(restored);
}

TEST(Regression, CanaryInitializesWhileProcessNonDumpable) {
    auto& c = memory::CanaryMonitor::Instance();
    c.Shutdown();
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    bool ok = c.Initialize(2);
    ASSERT_EQ(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0), 0);
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    ASSERT_TRUE(ok);
    ASSERT_EQ(c.Check().size(), 0u);
}
#endif

TEST(Regression, GroupedSimdBucketScannerMatchesSharedPrefixPatterns) {
    std::vector<uint8_t> buf(4096, 0x90);
    // Three distinct patterns sharing the same first byte (0x48) at offset 0
    memory::Pattern p1("48 8B 05 ? ? ? ? 48 85 C0", "Shared48_A");
    memory::Pattern p2("48 89 5C 24 ? 57 48 83 EC 20", "Shared48_B");
    memory::Pattern p3("48 B8 ? ? ? ? ? ? ? ? FF E0", "Shared48_C");
    // And one pattern with a leading wildcard (first non-wildcard at offset 1)
    memory::Pattern p4("? 48 8D 0D ? ? ? ? E8", "Offset1_48");

    const uint8_t s1[] = {0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44, 0x48, 0x85, 0xC0};
    const uint8_t s2[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20};
    const uint8_t s3[] = {0x48, 0xB8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xFF, 0xE0};
    const uint8_t s4[] = {0xCC, 0x48, 0x8D, 0x0D, 0xAA, 0xBB, 0xCC, 0xDD, 0xE8};

    std::memcpy(buf.data() + 31, s1, sizeof(s1));   // crosses 32-byte AVX2 boundary
    std::memcpy(buf.data() + 512, s2, sizeof(s2));
    std::memcpy(buf.data() + 4080, s3, sizeof(s3)); // in scalar tail of buffer
    std::memcpy(buf.data() + 2048, s4, sizeof(s4));

    std::vector<memory::Pattern> batch = {p1, p2, p3, p4};
    auto hits = memory::PatternScanner::ScanBatch(buf.data(), buf.size(), batch, 0x10000);
    ASSERT_EQ(hits.size(), 4u);

    bool gotA = false, gotB = false, gotC = false, gotD = false;
    for (const auto& h : hits) {
        if (h.pattern_name == "Shared48_A" && h.address == 0x10000 + 31) gotA = true;
        if (h.pattern_name == "Shared48_B" && h.address == 0x10000 + 512) gotB = true;
        if (h.pattern_name == "Shared48_C" && h.address == 0x10000 + 4080) gotC = true;
        if (h.pattern_name == "Offset1_48" && h.address == 0x10000 + 2048) gotD = true;
    }
    ASSERT_TRUE(gotA && gotB && gotC && gotD);
}

TEST(Regression, SdkCppClientWrappersPhantomAndSettings) {
    noescape::sdk::Client::SetHostUsesJit(true);
    noescape::sdk::Client::SetPanelPin("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    NoEscapeConfig cfg = NoEscape_GetDefaultConfig();
    cfg.enable_heartbeat = false;
    cfg.enable_anti_debug = false;
    cfg.enable_integrity_scan = false;
    cfg.enable_speedhack_detection = false;
    cfg.enable_memory_scan = false;
    cfg.enable_unhooker = false;
    cfg.enable_forensics = false;
    cfg.enable_dma_detection = false;
    cfg.enable_overlay_detection = false;
    cfg.enable_kinematics = true;
    cfg.enforce_ban = false;

    ASSERT_TRUE(noescape::sdk::Client::Init(&cfg));
    noescape::sdk::Client::AddPhantom(42, 10.0f, 0.0f, 0.0f);
    noescape::sdk::Client::UpdatePhantom(42, 20.0f, 0.0f, 0.0f);
    for (int i = 0; i < 12; ++i) {
        noescape::sdk::Client::PushView(0.0f, 0.0f, 0.0f, 0.0f, 0.1f, static_cast<uint64_t>(100 + i));
    }
    ASSERT_GT(noescape::sdk::Client::GetThreatScore(), 0u);
    noescape::sdk::Client::Shutdown();
    noescape::sdk::Client::SetHostUsesJit(false);
    noescape::sdk::Client::SetPanelPin("");
}

TEST(Regression, EngineAuditCycleWorksAfterStartAndStop) {
    core::EngineConfig cfg;
    cfg.enableHeartbeat = false;
    cfg.verifyPanelBan = false;
    cfg.enableAntiDebug = false;
    cfg.enableIntegrityScan = true;
    cfg.enableSpeedhackDetection = false;
    cfg.enableMemoryScan = true;
    cfg.enableUnhooker = false;
    cfg.enableForensics = false;
    cfg.enableDmaDetection = false;
    cfg.enableOverlayDetection = false;
    cfg.enforceBanOnViolation = false;

    core::AntiCheatEngine engine(cfg);
    ASSERT_TRUE(engine.Initialize());
    engine.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(40));
    engine.Stop();

    // After Stop(), a synchronous AuditCycle() must still execute rather than aborting
    // on a stale stop_requested_ == true flag.
#if defined(_WIN32)
    void* rwx = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_TRUE(rwx != nullptr);
#else
    void* rwx = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_TRUE(rwx != MAP_FAILED);
#endif
    std::memset(rwx, 0x90, 64);

    auto events = engine.AuditCycle();
#if defined(_WIN32)
    VirtualFree(rwx, 0, MEM_RELEASE);
#else
    munmap(rwx, 4096);
#endif
    ASSERT_GT(events.size(), 0u);
    ASSERT_GT(engine.GetThreatScore(), 0u);
}

#if !defined(_WIN32)
TEST(Regression, UninitializedEngineDestructorPreservesDumpableState) {
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    ASSERT_EQ(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0), 0);
    {
        core::EngineConfig cfg;
        cfg.enableAntiDebug = true;
        core::AntiCheatEngine uninitializedEngine(cfg);
        // Destroyed without calling Initialize(): must not clobber PR_SET_DUMPABLE to 1
    }
    int after = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    ASSERT_EQ(after, 0);
}

TEST(Regression, ConcurrentUnhookerAndCanaryUnderNonDumpable) {
    void* mockPage = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_TRUE(mockPage != MAP_FAILED);
    uint8_t cleanBytes[8] = {0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20};
    std::memcpy(mockPage, cleanBytes, sizeof(cleanBytes));

    memory::HookInfo info;
    info.function_name = "ConcurrentMock";
    info.function_address = reinterpret_cast<uintptr_t>(mockPage);
    info.hook_type = "JMP_REL32 (0xE9)";

    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    std::atomic<bool> failed{false};

    std::thread t1([&]() {
        for (int i = 0; i < 25; ++i) {
            if (!memory::Unhooker::Instance().RestoreHook(info, cleanBytes, sizeof(cleanBytes))) {
                failed.store(true);
            }
        }
    });
    std::thread t2([&]() {
        auto& c = memory::CanaryMonitor::Instance();
        for (int i = 0; i < 15; ++i) {
            c.Shutdown();
            if (!c.Initialize(1)) {
                failed.store(true);
            }
        }
    });
    t1.join();
    t2.join();

    int finalDumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    munmap(mockPage, 4096);

    ASSERT_FALSE(failed.load());
    ASSERT_EQ(finalDumpable, 0);
}
#endif

TEST(Regression, UnhookerAndOverlayDetectCetEndbr64OffsetHooks) {
    // 1. Synthetic function beginning with 4-byte Intel CET endbr64 (F3 0F 1E FA)
    // followed at +4 by JMP rel32 (E9 20 00 00 00)
    alignas(16) uint8_t cetHooked[32] = {
        0xF3, 0x0F, 0x1E, 0xFA,             // endbr64
        0xE9, 0x20, 0x00, 0x00, 0x00,       // jmp +0x20 (from insnAddr = base + 4)
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
    };
    uintptr_t base = reinterpret_cast<uintptr_t>(cetHooked);
    auto h1 = memory::Unhooker::Instance().InspectFunction("CetEndbrJmp", cetHooked);
    ASSERT_TRUE(h1.has_value());
    ASSERT_EQ(h1->hook_type, "JMP_REL32 (0xE9)");
    ASSERT_EQ(h1->target_destination, base + 4 + 5 + 0x20);
    ASSERT_EQ(h1->patched_bytes.size(), 9u);

    // 2. endbr64 followed at +4 by MOV RAX, imm64; JMP RAX (12 bytes -> total 16 bytes)
    alignas(16) uint8_t cetMovRax[32] = {
        0xF3, 0x0F, 0x1E, 0xFA,
        0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xFF, 0xE0
    };
    auto h2 = memory::Unhooker::Instance().InspectFunction("CetEndbrMovRax", cetMovRax);
    ASSERT_TRUE(h2.has_value());
    ASSERT_EQ(h2->hook_type, "MOV_RAX_JMP_RAX (0x48 0xB8 ... 0xFF 0xE0)");
    ASSERT_EQ(h2->target_destination, 0x1122334455667788ULL);

#if !defined(_WIN32)
    // 3. Real disk-backed function in libc.so.6 (fmtmsg) with endbr64 +4 inline detour:
    // verify OverlayDetector::InspectRenderingPointer flags it and AutoRestoreHook repairs it.
    void* libc = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD);
    if (!libc) return;
    void* fn = dlsym(libc, "fmtmsg");
    if (!fn) return;
    auto addr = reinterpret_cast<uintptr_t>(fn);
    uint8_t orig[16];
    std::memcpy(orig, fn, sizeof(orig));
    if (orig[0] == 0xF3 && orig[1] == 0x0F && orig[2] == 0x1E && orig[3] == 0xFA) {
        uint8_t detourAt4[5] = {0xE9, 0x40, 0x00, 0x00, 0x00};
        ASSERT_TRUE(PokeText(addr + 4, detourAt4, sizeof(detourAt4)));

        auto overlayEv = overlay::OverlayDetector::Instance().InspectRenderingPointer("fmtmsg_Present", fn);
        auto hookInfo = memory::Unhooker::Instance().InspectFunction("fmtmsg", fn);
        bool restored = false;
        if (hookInfo.has_value()) {
            restored = memory::Unhooker::Instance().AutoRestoreHook(*hookInfo);
        }
        if (std::memcmp(fn, orig, sizeof(orig)) != 0) {
            PokeText(addr, orig, sizeof(orig));
        }
        ASSERT_TRUE(overlayEv.has_value());
        ASSERT_EQ(overlayEv->type, core::DetectionType::RENDERING_HOOK_DETECTED);
        ASSERT_TRUE(hookInfo.has_value());
        ASSERT_TRUE(restored);
        ASSERT_EQ(std::memcmp(fn, orig, sizeof(orig)), 0);
    }
#endif
}

