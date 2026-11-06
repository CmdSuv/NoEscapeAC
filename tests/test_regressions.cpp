// Regression tests for the issues found in the full code audit.
#include "tests/test_framework.hpp"
#include "noescape_sdk.h"
#include "noescape/core/engine.hpp"
#include "noescape/core/blackbox.hpp"
#include "noescape/core/envutil.hpp"
#include "noescape/kinematics/aim_analyzer.hpp"
#include "noescape/memory/memory_scanner.hpp"
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
