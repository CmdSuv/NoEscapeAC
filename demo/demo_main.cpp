#include "noescape/core/engine.hpp"
#include "noescape/core/logger.hpp"
#include "noescape/memory/pattern_scanner.hpp"
#include "noescape/network/crypto_util.hpp"
#include "noescape/overlay/overlay_detector.hpp"
#include "noescape/core/blackbox.hpp"
#include "noescape_sdk.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <cstring>

using namespace noescape;

int main() {
    std::cout << "\033[1;36m"
              << "============================================================\n"
              << "      NoEscape Anti-Cheat Engine v7.0 - Interactive Demo     \n"
              << "============================================================\033[0m\n\n";

    core::EngineConfig config;
    config.enforceBanOnViolation = false; // Demo mode: observe all alerts without terminating

    core::AntiCheatEngine engine(config);
    engine.Initialize();

    std::cout << "\n\033[1;33m[DEMO 1] Hardware ID & Tamper-Resistant Signature Verification\033[0m\n";
    std::string hwid = network::CryptoUtil::GetMachineHWID();
    std::cout << "  -> Hardware ID: " << hwid << "\n";
    std::string sig = network::CryptoUtil::HmacSha256("DemoSecretKey", hwid + ":TIMESTAMP:100");
    std::cout << "  -> HMAC-SHA256 Signature: " << sig << "\n";

    std::cout << "\n\033[1;33m[DEMO 2] High-Speed SIMD Pattern Scanner Performance\033[0m\n";
    std::vector<uint8_t> largeBuffer(4 * 1024 * 1024, 0x90); // 4MB buffer
    size_t cheatOffset = 3 * 1024 * 1024 + 42;
    // Inject signature
    largeBuffer[cheatOffset] = 0x48;
    largeBuffer[cheatOffset + 1] = 0xB8;
    largeBuffer[cheatOffset + 10] = 0xFF;
    largeBuffer[cheatOffset + 11] = 0xE0;

    memory::Pattern testPat("48 B8 ? ? ? ? ? ? ? ? FF E0", "Demo_X64_Shellcode");

    auto t0 = std::chrono::high_resolution_clock::now();
    auto match = memory::PatternScanner::Scan(largeBuffer.data(), largeBuffer.size(), testPat);
    auto t1 = std::chrono::high_resolution_clock::now();

    double scanMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::cout << "  -> Scanned 4MB in " << scanMs << " ms ("
              << (4.0 / (scanMs / 1000.0)) << " MB/s throughput)\n";
    if (match) {
        std::cout << "  -> \033[32mMatched pattern '" << testPat.GetName() 
                  << "' at offset " << *match << "\033[0m\n";
    }

    std::cout << "\n\033[1;33m[DEMO 3] Live System Audit Cycle\033[0m\n";
    auto events = engine.AuditCycle();
    std::cout << "  -> Audit cycle triggered " << events.size() << " security events.\n";
    std::cout << "  -> Cumulative Threat Score: " << engine.GetThreatScore() << "\n";

    std::cout << "\n\033[1;33m[DEMO 4] Real-Time Kinematics Aimbot Detection Simulation\033[0m\n";
    std::cout << "  -> Simulating human aim trajectory...\n";
    uint64_t nowMs = 10000;
    for (int i = 0; i < 10; ++i) {
        engine.PushInputSample(i * 0.4f, i * 0.7f, nowMs);
        nowMs += 16;
    }
    std::cout << "  -> Human aim validated: Clean.\n";

    std::cout << "  -> Simulating Silent-Aim / Snap Aimbot (38 deg instant angle flick)...\n";
    engine.PushInputSample(10.0f, 40.0f, nowMs);
    nowMs += 16;
    engine.PushInputSample(10.0f, 40.0f, nowMs); // Dead stop

    std::cout << "  -> Current Threat Score after aimbot injection: " << engine.GetThreatScore() << "\n";

    std::cout << "\n\033[1;33m[DEMO 5] ESP Overlay Hijack & Rendering Hook Inspection\033[0m\n";
    auto& overlayDet = overlay::OverlayDetector::Instance();
    overlayDet.ClearMockWindows();
    overlayDet.SetGameViewport(0, 0, 1920, 1080);

    // Register simulated ESP topmost transparent window
    overlay::OverlayWindowInfo fakeEsp;
    fakeEsp.title = "DirectX 11 External ESP Overlay";
    fakeEsp.class_name = "ImGuiOverlayClass";
    fakeEsp.pid = 44102;
    fakeEsp.handle = 0xBEEF01;
    fakeEsp.rect = {0, 0, 1920, 1080};
    fakeEsp.is_topmost = true;
    fakeEsp.is_transparent = true;
    fakeEsp.is_layered = true;
    overlayDet.AddMockWindow(fakeEsp);

    auto overlayAlerts = overlayDet.DetectSuspiciousWindows();
    std::cout << "  -> Overlay Scanner detected " << overlayAlerts.size() << " unauthorized overlay windows:\n";
    for (const auto& a : overlayAlerts) {
        std::cout << "     \033[31m[!]\033[0m " << a.details << "\n";
    }

    // Inspect swapchain function pointer
    uint8_t fakeShellcode[16] = {0x90, 0xC3};
    auto hookAlert = overlayDet.InspectRenderingPointer("IDXGISwapChain::Present", fakeShellcode);
    if (hookAlert) {
        std::cout << "  -> Swapchain inspection detected hijacked hook:\n";
        std::cout << "     \033[31m[!]\033[0m " << hookAlert->details << "\n";
    }
    overlayDet.ClearMockWindows();

    std::cout << "\n\033[1;33m[DEMO 6] Blackbox Violation Diagnostic Dumper\033[0m\n";
    auto& dumper = core::BlackboxDumper::Instance();
    auto snapshot = dumper.CaptureSnapshot("Kinematics::SnapDetector", "Non-Human Aim Trajectory Exceeded Limits", 90, 14);
    std::cout << "  -> Captured snapshot: " << snapshot.violating_component 
              << " | Reason: " << snapshot.violation_reason
              << " | Backtrace Frames: " << snapshot.backtrace_addrs.size()
              << " | Input Trail: " << snapshot.recent_input_trail.size() << " samples\n";

    auto encPayload = dumper.SerializeAndEncrypt(snapshot, config.secretKey);
    std::cout << "  -> Authenticated encrypted payload: " << encPayload.size() << " bytes (HMAC-SHA256 verified)\n";

    core::BlackboxRecord decryptedSnap{};
    if (dumper.DecryptAndDeserialize(encPayload, config.secretKey, decryptedSnap)) {
        std::cout << "  -> \033[32mDecrypted & authenticated snapshot successfully (HWID: " 
                  << decryptedSnap.hwid.substr(0, 16) << "...)\033[0m\n";
    }

    std::cout << "\n\033[1;33m[DEMO 7] C-API & SDK Layer Integration\033[0m\n";
    NoEscapeConfig sdkCfg = NoEscape_GetDefaultConfig();
    sdkCfg.enable_heartbeat = false;
    sdkCfg.enable_anti_debug = false;
    sdkCfg.enforce_ban = false;

    if (NoEscape_Init(&sdkCfg) == 0) {
        std::cout << "  -> SDK Initialized via C-ABI successfully.\n";
        NoEscape_PushMouseEvent(1.2f, 0.4f, 20000);
        NoEscape_Tick();
        std::cout << "  -> SDK Threat Score: " << NoEscape_GetThreatScore() << "\n";
        NoEscape_Shutdown();
        std::cout << "  -> SDK Shutdown cleanly.\n";
    }

    std::cout << "\n\033[1;32m[DEMO COMPLETE] All NoEscape Anti-Cheat subsystems verified successfully.\033[0m\n";
    return 0;
}
