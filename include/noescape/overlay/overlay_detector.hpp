#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <mutex>
#include "noescape/core/types.hpp"

namespace noescape::overlay {

struct ViewportRect {
    int32_t x{0};
    int32_t y{0};
    int32_t width{0};
    int32_t height{0};

    bool IsZero() const {
        return width <= 0 || height <= 0;
    }

    bool Overlaps(const ViewportRect& other, int tolerance = 20) const {
        if (IsZero() || other.IsZero()) return false;

        // 1. Close boundary match (within tolerance)
        bool matches = (std::abs(x - other.x) <= tolerance) &&
                       (std::abs(y - other.y) <= tolerance) &&
                       (std::abs(width - other.width) <= tolerance) &&
                       (std::abs(height - other.height) <= tolerance);
        if (matches) return true;

        // 2. Enclosing overlay (e.g. fullscreen overlay window completely enclosing the viewport)
        bool covers = (other.x <= (x + tolerance)) &&
                      (other.y <= (y + tolerance)) &&
                      ((other.x + other.width) >= (x + width - tolerance)) &&
                      ((other.y + other.height) >= (y + height - tolerance));
        if (covers) return true;

        // 3. Substantial area intersection (>= 50% of viewport covered by overlay)
        int32_t ix1 = std::max(x, other.x);
        int32_t iy1 = std::max(y, other.y);
        int32_t ix2 = std::min(x + width, other.x + other.width);
        int32_t iy2 = std::min(y + height, other.y + other.height);

        if (ix2 > ix1 && iy2 > iy1) {
            int64_t interArea = static_cast<int64_t>(ix2 - ix1) * static_cast<int64_t>(iy2 - iy1);
            int64_t vpArea = static_cast<int64_t>(width) * static_cast<int64_t>(height);
            if (vpArea > 0 && interArea * 2 >= vpArea) {
                return true;
            }
        }

        return false;
    }
};

struct OverlayWindowInfo {
    std::string title;
    std::string class_name;
    uint32_t pid{0};
    uintptr_t handle{0};
    ViewportRect rect;
    uint32_t style{0};
    uint32_t ex_style{0};
    bool is_layered{false};
    bool is_transparent{false};
    bool is_topmost{false};
    std::string exe_path{""};
};

class OverlayDetector {
public:
    static OverlayDetector& Instance();

    // Configure game viewport and window
    void SetGameViewport(int32_t x, int32_t y, int32_t width, int32_t height);
    ViewportRect GetGameViewport() const;
    void SetGameWindowHandle(uintptr_t handle);
    uintptr_t GetGameWindowHandle() const;

    // Window enumeration & overlay detection
    std::vector<OverlayWindowInfo> EnumerateTopLevelWindows();
    std::vector<core::DetectionEvent> DetectSuspiciousWindows();

    // Swapchain & rendering hook detection
    std::vector<core::DetectionEvent> AuditSwapchainHooks();
    std::optional<core::DetectionEvent> InspectRenderingPointer(const char* routine_name, void* function_ptr);

    // Dynamic vtable swapchain inspection
    void RegisterSwapchainVTable(void** vtable, size_t entry_count);
    void ClearRegisteredVTables();

    // Full combined audit pass
    std::vector<core::DetectionEvent> PerformAudit();

    // Mock/Simulation support for deterministic cross-platform tests
    void AddMockWindow(const OverlayWindowInfo& window);
    void ClearMockWindows();

    // Helper: checks whether an address is within a mapped module
    bool IsAddressInLoadedModule(uintptr_t addr) const;

    // Auditable custom overlay allowlist (still requires authentic PID image provenance)
    void AllowlistOverlayTitle(const std::string& title_keyword);
    void ClearCustomOverlayAllowlist();

private:
    OverlayDetector();

    mutable std::mutex mutex_;
    ViewportRect game_viewport_{0, 0, 1920, 1080};
    uintptr_t game_window_handle_{0};
    std::vector<void**> registered_vtables_;
    std::vector<size_t> registered_vtable_sizes_;
    std::vector<OverlayWindowInfo> mock_windows_;
    std::vector<std::string> custom_allowlisted_titles_;

    bool IsSuspiciousOverlayWindow(const OverlayWindowInfo& win) const;
};

} // namespace noescape::overlay
