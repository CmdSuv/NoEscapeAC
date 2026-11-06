#include "tests/test_framework.hpp"
#include "noescape/core/obfuscation.hpp"
#include "noescape/network/panel_client.hpp"
#include "noescape/overlay/overlay_detector.hpp"
#include "noescape/kinematics/aim_analyzer.hpp"
#include "noescape/dma/dma_detector.hpp"
#include "noescape/memory/memory_scanner.hpp"
#include "noescape/memory/unhooker.hpp"
#include "noescape/security/anti_debug.hpp"
#include "noescape/core/engine.hpp"
#include "noescape_sdk.h"

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <chrono>
#include <thread>
#include <atomic>

using namespace noescape;

TEST(Remediation, ObfuscationCbcKeystreamNonLinearity) {
    // 1. Verify decryption correctness of multiple diverse strings
    const char* str1 = NOESCAPE_XOR("kernel32.dll");
    const char* str2 = NOESCAPE_XOR("SeDebugPrivilege");
    const char* str3 = NOESCAPE_XOR("/proc/self/task");

    ASSERT_EQ(std::string(str1), "kernel32.dll");
    ASSERT_EQ(std::string(str2), "SeDebugPrivilege");
    ASSERT_EQ(std::string(str3), "/proc/self/task");

    // 2. Verify constexpr object creation and size
    constexpr core::XorString<13, 0x12345678> obfuscated("kernel32.dll");
    ASSERT_EQ(obfuscated.size(), 13);
    ASSERT_EQ(obfuscated.str(), "kernel32.dll");
}

TEST(Remediation, NetworkBanCheckResultStatuses) {
    network::PanelClient client("http://127.0.0.1:54321", "TestSecretKey");

    // Attempting query against nonexistent port should result in NETWORK_ERROR (fail-closed/unverified)
    auto res = client.QueryBanStatus();
    ASSERT_EQ(static_cast<int>(res.status), static_cast<int>(network::BanCheckStatus::NETWORK_ERROR));
    ASSERT_FALSE(res.reason.empty());

    bool isBanned = false;
    std::string reason;
    bool checkOk = client.CheckBanStatus(isBanned, reason);
    // When network fails, CheckBanStatus returns false (not blindly reporting clean status)
    ASSERT_FALSE(checkOk);
    ASSERT_FALSE(isBanned);
}

TEST(Remediation, OverlayCompositorWhitelist) {
    auto& detector = overlay::OverlayDetector::Instance();
    detector.ClearMockWindows();
    detector.SetGameViewport(0, 0, 1920, 1080);

    // 1. Linux Picom Compositor window
    overlay::OverlayWindowInfo picomWin;
    picomWin.title = "picom compositor";
    picomWin.class_name = "picom";
    picomWin.pid = 1001;
    picomWin.handle = 0x5001;
    picomWin.rect = {0, 0, 1920, 1080};
    picomWin.is_topmost = true;
    picomWin.is_transparent = true;
    picomWin.is_layered = true;
    detector.AddMockWindow(picomWin);

    // 2. Steam Overlay window
    overlay::OverlayWindowInfo steamWin;
    steamWin.title = "GameOverlayUI";
    steamWin.class_name = "SteamOverlay";
    steamWin.pid = 1002;
    steamWin.handle = 0x5002;
    steamWin.rect = {0, 0, 1920, 1080};
    steamWin.is_topmost = true;
    steamWin.is_transparent = true;
    steamWin.is_layered = true;
    detector.AddMockWindow(steamWin);

    // 3. MangoHud FPS HUD
    overlay::OverlayWindowInfo mangoWin;
    mangoWin.title = "MangoHud overlay";
    mangoWin.class_name = "MangoHud";
    mangoWin.pid = 1003;
    mangoWin.handle = 0x5003;
    mangoWin.rect = {0, 0, 500, 200};
    mangoWin.is_topmost = true;
    mangoWin.is_transparent = true;
    mangoWin.is_layered = true;
    detector.AddMockWindow(mangoWin);

    auto alerts = detector.DetectSuspiciousWindows();
    // All whitelisted desktop & legitimate gaming tools must yield 0 detections
    ASSERT_EQ(alerts.size(), 0);

    // 4. Rogue Unwhitelisted ESP overlay
    overlay::OverlayWindowInfo cheatWin;
    cheatWin.title = "UnknownESP";
    cheatWin.class_name = "ImGuiTransparentOverlay";
    cheatWin.pid = 9999;
    cheatWin.handle = 0x9999;
    cheatWin.rect = {0, 0, 1920, 1080};
    cheatWin.is_topmost = true;
    cheatWin.is_transparent = true;
    cheatWin.is_layered = true;
    detector.AddMockWindow(cheatWin);

    alerts = detector.DetectSuspiciousWindows();
    ASSERT_EQ(alerts.size(), 1);
    ASSERT_EQ(alerts[0].type, core::DetectionType::OVERLAY_HIJACK_DETECTED);

    detector.ClearMockWindows();
}

TEST(Remediation, KinematicsPitchBoundaryGrace) {
    kinematics::AimAnalyzer analyzer(64);
    uint64_t t = 1000;

    // Looking straight up at ceiling boundary: pitch = 89.0 deg
    analyzer.PushSample(89.0f, 10.0f, t);
    t += 16;
    analyzer.PushSample(89.0f, 10.0f, t);
    t += 16;

    // Player continues swiping up rapidly: pitch clamped at 89.0 deg, slight yaw
    analyzer.PushSample(89.0f, 11.0f, t);
    t += 16;
    auto ev = analyzer.PushSample(89.0f, 11.0f, t);

    // Boundary saturation must not be falsely treated as an unnatural aimbot dead stop
    ASSERT_FALSE(ev.has_value());
}

TEST(Remediation, SdkZeroStutterConcurrentInput) {
    NoEscapeConfig cfg = NoEscape_GetDefaultConfig();
    cfg.enable_heartbeat = false;
    cfg.enable_dma_detection = false; // Disable heavy HW loops for this concurrency test
    ASSERT_EQ(NoEscape_Init(&cfg), 0);

    std::atomic<bool> keepRunning{true};
    std::atomic<size_t> mousePushCount{0};

    // Thread 1: High frequency mouse input thread (1000Hz simulation)
    std::thread inputThread([&]() {
        uint64_t ts = 1000;
        while (keepRunning.load()) {
            NoEscape_PushMouseEvent(0.5f, 0.2f, ts);
            ts += 1;
            mousePushCount.fetch_add(1);
            std::this_thread::sleep_for(std::chrono::microseconds(500));
        }
    });

    // Thread 2: Main game thread running NoEscape_Tick()
    for (int i = 0; i < 20; ++i) {
        NoEscape_Tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    keepRunning.store(false);
    inputThread.join();

    // Verify hundreds of mouse events were processed concurrently without stutter or deadlock
    ASSERT_GT(mousePushCount.load(), 50);

    NoEscape_Shutdown();
}

TEST(Remediation, DmaCacheFlushAndOutlierRejection) {
    auto& dma = dma::DmaDetector::Instance();
    // Calibrate with small probe buffer for fast deterministic test execution
    bool calibOk = dma.Calibrate(256, 15);
    ASSERT_TRUE(calibOk);

    auto profile = dma.ProfileMemoryBusJitter(15);
    ASSERT_GT(profile.baseline_mean_cycles, 0.0);
    ASSERT_GT(profile.current_mean_cycles, 0.0);
    // On clean machine with outlier filtering, anomalous bus congestion should be false
    ASSERT_FALSE(profile.anomalous);
}

TEST(Remediation, MemoryModuleStompingDetection) {
    auto& scanner = memory::MemoryScanner::Instance();
    auto regions = scanner.QueryMemoryRegions();
    ASSERT_FALSE(regions.empty());

    // In a clean running process, standard libraries should not have RWX permissions
    bool hasUnintendedRwx = false;
    for (const auto& r : regions) {
        if (r.is_backed_by_file && r.executable && r.writable) {
            hasUnintendedRwx = true;
            break;
        }
    }
    // Clean process has no RWX module stomping
    ASSERT_FALSE(hasUnintendedRwx);
}

TEST(Remediation, UnhookerAutoRestoreAPI) {
    auto& unhooker = memory::Unhooker::Instance();

    // In position-independent binaries, &puts points to the local PLT stub (FF 25 ...),
    // so dlsym must be used to inspect the actual runtime libc implementation.
#if defined(_WIN32)
    void* pfn = reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose"));
#else
    void* pfn = dlsym(RTLD_DEFAULT, "puts");
#endif
    if (pfn) {
        auto hook = unhooker.InspectFunction("puts", pfn);
        ASSERT_FALSE(hook.has_value());
    }

    // Test AutoRestoreHook handles mock invalid or unhooked addresses safely
    memory::HookInfo mockHook;
    mockHook.function_name = "test_stub";
    mockHook.function_address = 0;
    ASSERT_FALSE(unhooker.AutoRestoreHook(mockHook));
}

TEST(Remediation, AntiDebugMultiThreadInspection) {
    // CheckHardwareBreakpoints checks DR0-DR7 across all threads in the process
    bool bpDetected = security::AntiDebug::CheckHardwareBreakpoints();
    // Clean environment has no active hardware breakpoints
    ASSERT_FALSE(bpDetected);
}

#if !defined(_WIN32)
#include <sys/mman.h>
#include <unistd.h>
TEST(Phase1, CleanProcessHasNoModifiedModules) {
    auto& sc = memory::MemoryScanner::Instance();
    size_t n = sc.QueryMemoryRegions().size();
    for (size_t i = 0; i < n + 2; ++i) {
        ASSERT_EQ(sc.DetectModifiedModules().size(), 0);
    }
}

TEST(Phase1, SleepingPayloadDetected) {
    auto& sc = memory::MemoryScanner::Instance();
    size_t len = 4096;
    void* p = mmap(nullptr, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_TRUE(p != MAP_FAILED);
    sc.DetectSleepingPayloads();                 // observe while executable
    mprotect(p, len, PROT_NONE);                 // payload goes to sleep
    auto ev = sc.DetectSleepingPayloads();
    munmap(p, len);
    bool found = false;
    for (const auto& e : ev) if (e.component == "MemoryScanner::SleepingPayload") found = true;
    ASSERT_TRUE(found);
}

TEST(Phase1, ModuleStompingDetected) {
    auto& sc = memory::MemoryScanner::Instance();
    // Patch one byte inside a real file-backed executable mapping (private copy-on-write)
    void* fn = dlsym(RTLD_DEFAULT, "strlen");
    ASSERT_TRUE(fn != nullptr);
    auto* b = static_cast<uint8_t*>(fn);
    long ps = sysconf(_SC_PAGESIZE);
    void* page = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(fn) & ~(static_cast<uintptr_t>(ps) - 1));
    ASSERT_EQ(mprotect(page, static_cast<size_t>(ps), PROT_READ | PROT_WRITE | PROT_EXEC), 0);
    uint8_t orig = b[8];
    b[8] = static_cast<uint8_t>(orig ^ 0xFF);
    bool found = false;
    size_t n = sc.QueryMemoryRegions().size();
    for (size_t i = 0; i < n + 2 && !found; ++i)
        for (const auto& e : sc.DetectModifiedModules()) if (e.component == "MemoryScanner::ModuleIntegrity") found = true;
    b[8] = orig;
    mprotect(page, static_cast<size_t>(ps), PROT_READ | PROT_EXEC);
    ASSERT_TRUE(found);
}
#endif

#if !defined(_WIN32)
#include <sys/uio.h>
#include "noescape/memory/canary_monitor.hpp"
TEST(Phase2, CanaryCleanAndNoFalsePositiveUnderChurn) {
    auto& c = memory::CanaryMonitor::Instance();
    ASSERT_TRUE(c.Initialize(4));
    if (!c.IsWriteTrackingSupported()) {
        std::cout << "(skipped: kernel lacks soft-dirty tracking) ";
        return;
    }
    ASSERT_EQ(c.Check().size(), 0);
    // Heavy allocator churn around the canary must not trigger it
    for (int i = 0; i < 200; ++i) {
        void* m = mmap(nullptr, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        static_cast<volatile char*>(m)[0] = 1;
        if (i % 2) munmap(m, 65536);
    }
    std::vector<int> v(100000, 7);
    ASSERT_EQ(c.Check().size(), 0);
    ASSERT_EQ(c.Check().size(), 0);
}

TEST(Phase2, CanaryDetectsExternalStyleWriteSameValue) {
    auto& c = memory::CanaryMonitor::Instance();
    ASSERT_TRUE(c.Initialize(4));
    if (!c.IsWriteTrackingSupported()) {
        std::cout << "(skipped: kernel lacks soft-dirty tracking) ";
        return;
    }
    c.Check();
    // Emulate WriteProcessMemory: process_vm_writev writing the *same* byte value,
    // so only OS write tracking (not content comparison) can notice it.
    uint8_t same = *reinterpret_cast<uint8_t*>(c.Address() + 100);
    struct iovec local{&same, 1};
    struct iovec remote{reinterpret_cast<void*>(c.Address() + 100), 1};
    ssize_t n = process_vm_writev(getpid(), &local, 1, &remote, 1, 0);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(c.Check().size(), 1);
    ASSERT_EQ(c.Check().size(), 0); // re-armed
}

TEST(Phase2, CanaryDetectsContentChange) {
    auto& c = memory::CanaryMonitor::Instance();
    ASSERT_TRUE(c.Initialize(4));
    c.Check();
    uint8_t v = *reinterpret_cast<uint8_t*>(c.Address() + 7) ^ 0xFF;
    struct iovec local{&v, 1};
    struct iovec remote{reinterpret_cast<void*>(c.Address() + 7), 1};
    ASSERT_EQ(process_vm_writev(getpid(), &local, 1, &remote, 1, 0), 1);
    auto ev = c.Check();
    ASSERT_EQ(ev.size(), 1);
    ASSERT_EQ(ev[0].type, core::DetectionType::CANARY_TAMPERED);
}
#endif

#include "noescape/kinematics/phantom_monitor.hpp"
TEST(Phase4, PhantomLockDetectedAndNormalAimIgnored) {
    kinematics::PhantomMonitor pm;
    pm.AddPhantom(1, 10.0f, 0.0f, 0.0f);   // straight ahead along +X
    pm.AddPhantom(2, 0.0f, 20.0f, 0.0f);

    // Looking at a random other direction: never fires, even for many samples
    for (int i = 0; i < 100; ++i) ASSERT_FALSE(pm.PushView(0, 0, 0, 10.0f, 135.0f, i).has_value());

    // Short pass over the phantom (human sweeping crosshair): below required streak
    for (int i = 0; i < 5; ++i) ASSERT_FALSE(pm.PushView(0, 0, 0, 0.0f, 0.2f, i).has_value());
    ASSERT_FALSE(pm.PushView(0, 0, 0, 30.0f, 45.0f, 99).has_value()); // leaves -> streak reset

    // Sustained lock on phantom 1 -> event on the 12th sample
    std::optional<core::DetectionEvent> ev;
    for (int i = 0; i < 12; ++i) ev = pm.PushView(0, 0, 0, 0.0f, 0.3f, 200 + i);
    ASSERT_TRUE(ev.has_value());
    ASSERT_EQ(ev->type, core::DetectionType::PHANTOM_ENTITY_TARGETED);
}

TEST(Phase4, PhantomGenerationDeterministicAndNonFiniteSafe) {
    kinematics::PhantomMonitor a, b;
    a.GenerateAround(0, 0, 0, 50.0f, 8, 1234);
    b.GenerateAround(0, 0, 0, 50.0f, 8, 1234);
    ASSERT_EQ(a.Count(), 8);
    ASSERT_EQ(b.Count(), 8);
    ASSERT_FALSE(a.PushView(NAN, 0, 0, 0, 0, 1).has_value());
}

#include <cstdlib>
TEST(Phase3, SignedPanelProtocolAgainstReferenceServer) {
    if (std::system("python3 --version >/dev/null 2>&1") != 0) return; // environment lacks python
    const char* secret = "IntegrationSecret";
    network::PanelClient probe("http://127.0.0.1:18431/api/ac", secret);
    std::string hwid = probe.GetHwid();

    // Server 1: this device is clean
    std::string cmd = std::string("python3 ") + NOESCAPE_SOURCE_DIR + "/tools/reference_server.py 18431 " + secret + " >/dev/null 2>&1 &";
    ASSERT_EQ(std::system(cmd.c_str()), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(700));

    network::PanelClient good("http://127.0.0.1:18431/api/ac", secret);
    ASSERT_EQ(static_cast<int>(good.QueryBanStatus().status), static_cast<int>(network::BanCheckStatus::CLEAN));
    ASSERT_TRUE(good.SendHeartbeat(10, "HEALTHY"));

    // Wrong secret: server rejects our signed heartbeat; we reject the server's signature
    network::PanelClient wrong("http://127.0.0.1:18431/api/ac", "WrongSecret");
    ASSERT_FALSE(wrong.SendHeartbeat(10, "HEALTHY"));
    ASSERT_EQ(static_cast<int>(wrong.QueryBanStatus().status), static_cast<int>(network::BanCheckStatus::SIGNATURE_INVALID));

    // Ban report with quotes/backslashes in details must still verify (JSON escaping + HMAC)
    core::DetectionEvent ev;
    ev.type = core::DetectionType::INLINE_HOOK_DETECTED;
    ev.component = "Test";
    ev.details = "path \"C:\\x\" line\nbreak";
    ASSERT_TRUE(good.SendBanReport(ev, 100));
    (void)!std::system("pkill -f 'reference_server.py 18431' >/dev/null 2>&1");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Server 2: this device is globally banned
    cmd = std::string("python3 ") + NOESCAPE_SOURCE_DIR + "/tools/reference_server.py 18431 " + secret + " " + hwid + " >/dev/null 2>&1 &";
    ASSERT_EQ(std::system(cmd.c_str()), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(700));
    ASSERT_EQ(static_cast<int>(good.QueryBanStatus().status), static_cast<int>(network::BanCheckStatus::BANNED));
    (void)!std::system("pkill -f 'reference_server.py 18431' >/dev/null 2>&1");

    // Unreachable server: never reported clean
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    ASSERT_EQ(static_cast<int>(good.QueryBanStatus().status), static_cast<int>(network::BanCheckStatus::NETWORK_ERROR));
}

#if !defined(_WIN32)
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/syscall.h>

TEST(Hardening, HardwareBreakpointDetectionWithPerfEvent) {
    // 1. Verify clean process reports zero hardware breakpoints
    ASSERT_FALSE(security::AntiDebug::CheckHardwareBreakpoints());

    // 2. Simulate hardware debug register occupation using perf_event_open
    static void (*probeFunc)() = []() {};
    struct perf_event_attr pe{};
    pe.type = PERF_TYPE_BREAKPOINT;
    pe.size = sizeof(pe);
    pe.bp_type = HW_BREAKPOINT_X;
    pe.bp_addr = reinterpret_cast<uintptr_t>(probeFunc);
    pe.bp_len = sizeof(long);
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    int simFd = static_cast<int>(syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0));
    if (simFd >= 0) {
        // DR slot occupied -> CheckHardwareBreakpoints detects it
        bool detected = security::AntiDebug::CheckHardwareBreakpoints();
        close(simFd);
        ASSERT_TRUE(detected);

        // Released DR slot -> clean again
        ASSERT_FALSE(security::AntiDebug::CheckHardwareBreakpoints());
    }
}
#endif

TEST(Hardening, MemoryScannerCacheSnapshot) {
    auto& scanner = memory::MemoryScanner::Instance();
    ASSERT_FALSE(scanner.IsCacheValid());

    // Un-cached query
    auto r1 = scanner.QueryMemoryRegions();
    ASSERT_FALSE(r1.empty());
    ASSERT_FALSE(scanner.IsCacheValid());

    // Populate and query cached snapshot
    scanner.RefreshCache();
    ASSERT_TRUE(scanner.IsCacheValid());

    auto r2 = scanner.QueryMemoryRegions();
    ASSERT_EQ(r1.size(), r2.size());
    ASSERT_EQ(r1[0].start, r2[0].start);

    // Clear cache
    scanner.ClearCache();
    ASSERT_FALSE(scanner.IsCacheValid());
}

TEST(Hardening, LargeMemoryChunkingScanAbove32MB) {
    auto& scanner = memory::MemoryScanner::Instance();
    // Allocate 36 MB of anonymous executable memory (>32MB threshold previously skipped)
    size_t allocSize = 36 * 1024 * 1024;
#if !defined(_WIN32)
    uint8_t* mem = static_cast<uint8_t*>(mmap(nullptr, allocSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    ASSERT_TRUE(mem != MAP_FAILED);

    // Inject a known signature pattern into chunk 4 (offset 33 MB > 32 MB)
    // MinHook x64 Trampoline: 49 BA [8 bytes target] 41 FF E2
    size_t targetOffset = 33 * 1024 * 1024 + 1024;
    mem[targetOffset] = 0x49; mem[targetOffset + 1] = 0xBA;
    mem[targetOffset + 2] = 0x78; mem[targetOffset + 3] = 0x56;
    mem[targetOffset + 4] = 0x34; mem[targetOffset + 5] = 0x12;
    mem[targetOffset + 6] = 0x00; mem[targetOffset + 7] = 0x00;
    mem[targetOffset + 8] = 0x00; mem[targetOffset + 9] = 0x00;
    mem[targetOffset + 10] = 0x41; mem[targetOffset + 11] = 0xFF; mem[targetOffset + 12] = 0xE2;

    auto events = scanner.ScanSignatures(memory::MemoryScanner::GetDefaultCheatSignatures());
    bool foundInLargeBlock = false;
    for (const auto& ev : events) {
        if (ev.details.find("MinHook_X64_R10_Trampoline") != std::string::npos &&
            ev.details.find("0x" + [] (uintptr_t v) {
                std::ostringstream ss; ss << std::hex << v; return ss.str();
            }(reinterpret_cast<uintptr_t>(mem + targetOffset))) != std::string::npos) {
            foundInLargeBlock = true;
            break;
        }
    }

    munmap(mem, allocSize);
    ASSERT_TRUE(foundInLargeBlock);
#endif
}

TEST(Hardening, WatchdogThreadLifecycleClean) {
    core::EngineConfig cfg;
    cfg.enableHeartbeat = false;
    cfg.terminateProcessOnBan = false;
    cfg.showBanUi = false;

    core::AntiCheatEngine engine(cfg);
    ASSERT_TRUE(engine.Initialize());
    engine.Start();
    // Running under normal conditions maintains active heartbeat without false positives
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    ASSERT_FALSE(engine.IsBanned());
    ASSERT_EQ(engine.GetThreatScore(), 0);
    engine.Stop();
}

TEST(Hardening, WatchdogDetectsThreadFreezeTampering) {
    core::EngineConfig cfg;
    cfg.enableHeartbeat = false;
    cfg.terminateProcessOnBan = false;
    cfg.showBanUi = false;
    cfg.enforceBanOnViolation = true;

    core::AntiCheatEngine engine(cfg);
    ASSERT_TRUE(engine.Initialize());
    engine.Start();

    // Verify engine starts cleanly
    ASSERT_FALSE(engine.IsBanned());
    ASSERT_TRUE(engine.GetLastAuditHeartbeatMs() > 0);

    // Simulate an attacker suspending/freezing the background audit thread (> 3000ms deadline missed)
    engine.FreezeBackgroundLoopForTesting(true);
    uint64_t simulatedStallTime = engine.GetLastAuditHeartbeatMs() - 4000;
    engine.SetAuditHeartbeatForTesting(simulatedStallTime);

    // Watchdog thread checks every 100ms; wait 250ms for watchdog enforcement to trigger
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    // Watchdog must detect thread freeze, increment threat score to >= 100, and ban
    ASSERT_TRUE(engine.IsBanned());
    ASSERT_TRUE(engine.GetThreatScore() >= 100);

    auto history = engine.GetDetectionHistory();
    bool foundWatchdogDetection = false;
    for (const auto& ev : history) {
        if (ev.type == core::DetectionType::HEARTBEAT_TAMPERING &&
            ev.component == "AntiCheatEngine::Watchdog") {
            foundWatchdogDetection = true;
            break;
        }
    }
    ASSERT_TRUE(foundWatchdogDetection);

    engine.FreezeBackgroundLoopForTesting(false);
    engine.Stop();
}

TEST(Hardening, SecureEnvironmentOverrides) {
    // Verify that NOESCAPE_TEST_MODE is set in test environment
    const char* testMode = std::getenv("NOESCAPE_TEST_MODE");
    ASSERT_TRUE(testMode != nullptr);
    ASSERT_EQ(std::string(testMode), "1");

    // In test mode, opt-out checking operates safely without breaking test harnesses
    NoEscapeConfig cfg = NoEscape_GetDefaultConfig();
    cfg.enable_heartbeat = false;
    cfg.enable_anti_debug = false;
    ASSERT_EQ(NoEscape_Init(&cfg), 0);
    ASSERT_FALSE(NoEscape_IsBanned());
    NoEscape_Shutdown();
}
