#include "tests/test_framework.hpp"
#include "noescape/overlay/overlay_detector.hpp"
#include <cstring>

#if !defined(_WIN32)
#include <sys/mman.h>
#include <unistd.h>
#endif

using namespace noescape;
using namespace noescape::overlay;

TEST(Overlay, ViewportGeometry) {
    ViewportRect r1{0, 0, 1920, 1080};
    ViewportRect r2{5, 5, 1915, 1075};
    ViewportRect r3{200, 200, 800, 600};

    ASSERT_TRUE(r1.Overlaps(r2, 10));
    ASSERT_FALSE(r1.Overlaps(r3, 10));
}

TEST(Overlay, WindowDetectionLayeredTopmost) {
    auto& detector = OverlayDetector::Instance();
    detector.ClearMockWindows();
    detector.SetGameViewport(0, 0, 1920, 1080);

    // 1. Normal game child or background window (clean)
    OverlayWindowInfo cleanWin;
    cleanWin.title = "Game Chat Window";
    cleanWin.class_name = "GameUI";
    cleanWin.pid = 12345;
    cleanWin.handle = 0x1000;
    cleanWin.rect = {100, 100, 400, 300};
    cleanWin.is_layered = false;
    cleanWin.is_transparent = false;
    cleanWin.is_topmost = false;
    detector.AddMockWindow(cleanWin);

    auto alertsClean = detector.DetectSuspiciousWindows();
    ASSERT_EQ(alertsClean.size(), 0);

    // 2. Suspicious ESP overlay: Topmost + Layered + Transparent matching game viewport
    OverlayWindowInfo cheatOverlay;
    cheatOverlay.title = "Overlay Window";
    cheatOverlay.class_name = "TransparentOverlay";
    cheatOverlay.pid = 99999;
    cheatOverlay.handle = 0x2000;
    cheatOverlay.rect = {0, 0, 1920, 1080};
    cheatOverlay.is_layered = true;
    cheatOverlay.is_transparent = true;
    cheatOverlay.is_topmost = true;
    detector.AddMockWindow(cheatOverlay);

    auto alertsOverlay = detector.DetectSuspiciousWindows();
    ASSERT_EQ(alertsOverlay.size(), 1);
    ASSERT_EQ(alertsOverlay[0].type, core::DetectionType::OVERLAY_HIJACK_DETECTED);
    ASSERT_EQ(alertsOverlay[0].severity, core::Severity::HIGH);

    // 3. Suspicious Window with ImGui / ESP title
    OverlayWindowInfo imguiOverlay;
    imguiOverlay.title = "Dear ImGui ESP Overlay v1.2";
    imguiOverlay.class_name = "ImGuiWindow";
    imguiOverlay.pid = 88888;
    imguiOverlay.handle = 0x3000;
    imguiOverlay.rect = {200, 200, 500, 400};
    imguiOverlay.is_layered = false;
    imguiOverlay.is_transparent = false;
    imguiOverlay.is_topmost = true;
    detector.AddMockWindow(imguiOverlay);

    auto alertsAll = detector.DetectSuspiciousWindows();
    ASSERT_EQ(alertsAll.size(), 2);

    detector.ClearMockWindows();
}

static void LegitimateSwapchainStub() {
    volatile int x = 42;
    (void)x;
}

TEST(Overlay, SwapchainPointerInspectionValidRoutine) {
    auto& detector = OverlayDetector::Instance();

    // Valid routine residing in text section of loaded binary
    void* validFn = reinterpret_cast<void*>(&LegitimateSwapchainStub);
    auto ev = detector.InspectRenderingPointer("LegitimateSwapchainStub", validFn);
    ASSERT_FALSE(ev.has_value());
}

TEST(Overlay, SwapchainPointerInspectionUnbackedAddress) {
    auto& detector = OverlayDetector::Instance();

    // Allocate memory on heap / anonymous memory (not backed by executable file module)
    uint8_t dummyCode[16] = {0x90, 0x90, 0xC3};
    void* fakeSwapchainFn = reinterpret_cast<void*>(dummyCode);

    auto ev = detector.InspectRenderingPointer("FakeIDXGISwapChain_Present", fakeSwapchainFn);
    ASSERT_TRUE(ev.has_value());
    ASSERT_EQ(ev->type, core::DetectionType::RENDERING_HOOK_DETECTED);
    ASSERT_EQ(ev->severity, core::Severity::CRITICAL);
}

TEST(Overlay, SwapchainInlineHookDetection) {
#if !defined(_WIN32)
    auto& detector = OverlayDetector::Instance();
    // Create an executable page with an inline hook stub (e.g. 0xE9 JMP rel32)
    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) pageSize = 4096;

    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_TRUE(page != MAP_FAILED);

    uint8_t* code = static_cast<uint8_t*>(page);
    code[0] = 0xE9; // JMP rel32
    int32_t rel = 0x1234;
    std::memcpy(code + 1, &rel, sizeof(rel));

    auto ev = detector.InspectRenderingPointer("Hooked_Present", page);
    ASSERT_TRUE(ev.has_value());
    ASSERT_EQ(ev->type, core::DetectionType::RENDERING_HOOK_DETECTED);

    munmap(page, pageSize);
#endif
}

TEST(Overlay, DynamicSwapchainVTableInspection) {
    auto& detector = OverlayDetector::Instance();
    detector.ClearRegisteredVTables();

    void* dummyVtable[4];
    dummyVtable[0] = reinterpret_cast<void*>(&LegitimateSwapchainStub);
    dummyVtable[1] = reinterpret_cast<void*>(&LegitimateSwapchainStub);
    // Vtable entry 2: hooked/unbacked address
    uint8_t fakeTrampoline[8] = {0x90, 0xC3};
    dummyVtable[2] = reinterpret_cast<void*>(fakeTrampoline);
    dummyVtable[3] = nullptr;

    detector.RegisterSwapchainVTable(dummyVtable, 4);

    auto events = detector.AuditSwapchainHooks();
    ASSERT_GT(events.size(), 0);
    ASSERT_EQ(events[0].type, core::DetectionType::RENDERING_HOOK_DETECTED);

    detector.ClearRegisteredVTables();
}

TEST(Overlay, ViewportContainmentAndMultiMonitor) {
    auto& detector = OverlayDetector::Instance();
    detector.ClearMockWindows();
    detector.SetGameViewport(0, 0, 1920, 1080);

    // 1. Multi-monitor fullscreen overlay completely enclosing game viewport
    OverlayWindowInfo enclosingOverlay;
    enclosingOverlay.title = "Multi-Monitor Transparent Canvas";
    enclosingOverlay.class_name = "MultiMonOverlay";
    enclosingOverlay.pid = 91919;
    enclosingOverlay.handle = 0x5000;
    enclosingOverlay.rect = {-1920, 0, 3840, 1080}; // Spans left monitor across main monitor
    enclosingOverlay.is_layered = true;
    enclosingOverlay.is_transparent = true;
    enclosingOverlay.is_topmost = true;
    detector.AddMockWindow(enclosingOverlay);

    // 2. Non-overlapping window placed entirely on the secondary screen
    OverlayWindowInfo otherMonitorWin;
    otherMonitorWin.title = "Secondary Screen Utility Window";
    otherMonitorWin.class_name = "CleanApp";
    otherMonitorWin.pid = 92929;
    otherMonitorWin.handle = 0x6000;
    otherMonitorWin.rect = {-1920, 0, 1920, 1080};
    otherMonitorWin.is_layered = true;
    otherMonitorWin.is_transparent = true;
    otherMonitorWin.is_topmost = true;
    detector.AddMockWindow(otherMonitorWin);

    auto alerts = detector.DetectSuspiciousWindows();
    // Only the enclosing overlay covering the game viewport should trigger
    ASSERT_EQ(alerts.size(), 1);
    ASSERT_EQ(alerts[0].type, core::DetectionType::OVERLAY_HIJACK_DETECTED);

    detector.ClearMockWindows();
}

TEST(Overlay, SwapchainPointerInspectionInvalidAddressSafe) {
    auto& detector = OverlayDetector::Instance();

    // Passing an address below 0x10000: safely handled without crash
    void* lowAddr = reinterpret_cast<void*>(0x1000);
    auto evLow = detector.InspectRenderingPointer("LowAddrRoutine", lowAddr);
    ASSERT_FALSE(evLow.has_value());

    // Passing unbacked / unmapped address: safely detects unbacked trampoline without SIGSEGV
    void* unbacked = reinterpret_cast<void*>(0x7FFFF0001000ULL);
    auto evUnbacked = detector.InspectRenderingPointer("UnbackedRoutine", unbacked);
    ASSERT_TRUE(evUnbacked.has_value());
    ASSERT_EQ(evUnbacked->type, core::DetectionType::RENDERING_HOOK_DETECTED);
}

TEST(Overlay, SwapchainPointerInspectionDataSectionNonExecutable) {
    auto& detector = OverlayDetector::Instance();

    // Static buffer residing in non-executable data section
    static const char s_dummyData[] = "NonExecutableDataSectionBuffer";
    void* dataPtr = const_cast<void*>(static_cast<const void*>(s_dummyData));

    auto ev = detector.InspectRenderingPointer("DataSectionVTableEntry", dataPtr);
    ASSERT_TRUE(ev.has_value());
    ASSERT_EQ(ev->type, core::DetectionType::RENDERING_HOOK_DETECTED);
}
