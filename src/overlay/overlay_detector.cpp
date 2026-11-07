#include "noescape/overlay/overlay_detector.hpp"
#include "noescape/memory/memory_scanner.hpp"
#include "noescape/memory/unhooker.hpp"
#include "noescape/core/logger.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <ctime>
#include <cstring>
#include <cctype>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#include <dirent.h>
#endif

namespace noescape::overlay {

namespace {

#if !defined(_WIN32)
// Xlib's default error handler calls exit(): a window destroyed between XQueryTree and
// XGetWindowAttributes (BadWindow) would otherwise terminate the whole game process.
int SwallowX11Error(void*, void*) { return 0; }
#endif

std::string ToLower(std::string_view str) {
    std::string s(str);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

std::string PtrToHex(uintptr_t addr) {
    std::ostringstream ss;
    ss << "0x" << std::hex << addr;
    return ss.str();
}

} // namespace

OverlayDetector& OverlayDetector::Instance() {
    static OverlayDetector* instance = new OverlayDetector();
    return *instance;
}

OverlayDetector::OverlayDetector() {
    game_viewport_ = {0, 0, 1920, 1080};
}

void OverlayDetector::SetGameViewport(int32_t x, int32_t y, int32_t width, int32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);
    game_viewport_ = {x, y, width, height};
}

ViewportRect OverlayDetector::GetGameViewport() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return game_viewport_;
}

void OverlayDetector::SetGameWindowHandle(uintptr_t handle) {
    std::lock_guard<std::mutex> lock(mutex_);
    game_window_handle_ = handle;
}

uintptr_t OverlayDetector::GetGameWindowHandle() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return game_window_handle_;
}

void OverlayDetector::AddMockWindow(const OverlayWindowInfo& window) {
    std::lock_guard<std::mutex> lock(mutex_);
    mock_windows_.push_back(window);
}

void OverlayDetector::ClearMockWindows() {
    std::lock_guard<std::mutex> lock(mutex_);
    mock_windows_.clear();
}

void OverlayDetector::RegisterSwapchainVTable(void** vtable, size_t entry_count) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (vtable && entry_count > 0) {
        registered_vtables_.push_back(vtable);
        registered_vtable_sizes_.push_back(entry_count);
    }
}

void OverlayDetector::ClearRegisteredVTables() {
    std::lock_guard<std::mutex> lock(mutex_);
    registered_vtables_.clear();
    registered_vtable_sizes_.clear();
}

std::vector<OverlayWindowInfo> OverlayDetector::EnumerateTopLevelWindows() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!mock_windows_.empty()) {
        return mock_windows_;
    }
    std::vector<OverlayWindowInfo> windows;

#if defined(_WIN32)
    struct EnumData {
        DWORD currentPid;
        HWND gameHwnd;
        std::vector<OverlayWindowInfo>* list;
    };

    DWORD curPid = GetCurrentProcessId();
    EnumData data{curPid, reinterpret_cast<HWND>(game_window_handle_), &windows};

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* d = reinterpret_cast<EnumData*>(lParam);
        if (!IsWindowVisible(hwnd)) return TRUE;
        if (d->gameHwnd && hwnd == d->gameHwnd) return TRUE;

        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid == d->currentPid) return TRUE;

        LONG_PTR exStyle = GetWindowLongPtrA(hwnd, GWL_EXSTYLE);
        LONG_PTR style = GetWindowLongPtrA(hwnd, GWL_STYLE);

        RECT rc{};
        GetWindowRect(hwnd, &rc);

        char title[256] = {0};
        GetWindowTextA(hwnd, title, sizeof(title));

        char className[256] = {0};
        GetClassNameA(hwnd, className, sizeof(className));

        OverlayWindowInfo info;
        info.title = title;
        info.class_name = className;
        info.pid = static_cast<uint32_t>(pid);
        info.handle = reinterpret_cast<uintptr_t>(hwnd);
        info.rect = {rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top};
        info.style = static_cast<uint32_t>(style);
        info.ex_style = static_cast<uint32_t>(exStyle);
        info.is_topmost = (exStyle & WS_EX_TOPMOST) != 0;
        info.is_transparent = (exStyle & WS_EX_TRANSPARENT) != 0;
        info.is_layered = (exStyle & WS_EX_LAYERED) != 0;

        d->list->push_back(info);
        return TRUE;
    }, reinterpret_cast<LPARAM>(&data));
#else
    // 1. Dynamic X11 Window Inspection (detects transparent, override-redirect, and unmapped draw windows)
    void* libX11 = dlopen("libX11.so.6", RTLD_LAZY);
    if (!libX11) {
        libX11 = dlopen("libX11.so", RTLD_LAZY);
    }

    if (libX11) {
        typedef void* (*XOpenDisplayFn)(const char*);
        typedef int (*XCloseDisplayFn)(void*);
        typedef unsigned long (*XDefaultRootWindowFn)(void*);
        typedef int (*XQueryTreeFn)(void*, unsigned long, unsigned long*, unsigned long*, unsigned long**, unsigned int*);
        typedef int (*XGetWindowAttributesFn)(void*, unsigned long, void*);
        typedef int (*XFreeFn)(void*);
        typedef int (*XFetchNameFn)(void*, unsigned long, char**);
        typedef int (*(*XSetErrorHandlerFn)(int (*)(void*, void*)))(void*, void*);
        typedef int (*XSyncFn)(void*, int);

        auto pXOpenDisplay = reinterpret_cast<XOpenDisplayFn>(dlsym(libX11, "XOpenDisplay"));
        auto pXCloseDisplay = reinterpret_cast<XCloseDisplayFn>(dlsym(libX11, "XCloseDisplay"));
        auto pXDefaultRootWindow = reinterpret_cast<XDefaultRootWindowFn>(dlsym(libX11, "XDefaultRootWindow"));
        auto pXQueryTree = reinterpret_cast<XQueryTreeFn>(dlsym(libX11, "XQueryTree"));
        auto pXGetWindowAttributes = reinterpret_cast<XGetWindowAttributesFn>(dlsym(libX11, "XGetWindowAttributes"));
        auto pXFree = reinterpret_cast<XFreeFn>(dlsym(libX11, "XFree"));
        auto pXFetchName = reinterpret_cast<XFetchNameFn>(dlsym(libX11, "XFetchName"));
        auto pXSetErrorHandler = reinterpret_cast<XSetErrorHandlerFn>(dlsym(libX11, "XSetErrorHandler"));
        auto pXSync = reinterpret_cast<XSyncFn>(dlsym(libX11, "XSync"));

        if (pXOpenDisplay && pXCloseDisplay && pXDefaultRootWindow && pXQueryTree && pXGetWindowAttributes && pXFree) {
            // Install a non-fatal handler for the duration of the scan only
            auto prevHandler = pXSetErrorHandler ? pXSetErrorHandler(SwallowX11Error) : nullptr;
            void* display = pXOpenDisplay(nullptr);
            if (display) {
                unsigned long root = pXDefaultRootWindow(display);
                unsigned long rootRet = 0, parentRet = 0;
                unsigned long* children = nullptr;
                unsigned int numChildren = 0;

                if (pXQueryTree(display, root, &rootRet, &parentRet, &children, &numChildren) && children) {
                    struct XWindowAttributesRaw {
                        int x, y, width, height, border_width, depth;
                        void* visual;
                        unsigned long root;
                        int c_class;
                        int bit_gravity, win_gravity, backing_store;
                        unsigned long backing_planes, backing_pixel;
                        int save_under;
                        void* colormap;
                        int map_installed;
                        int map_state; // 0=IsUnmapped, 1=IsUnviewable, 2=IsViewable
                        long all_event_masks, your_event_mask, do_not_propagate_mask;
                        int override_redirect;
                        void* screen;
                    };

                    for (unsigned int i = 0; i < numChildren; ++i) {
                        XWindowAttributesRaw attrs{};
                        if (pXGetWindowAttributes(display, children[i], &attrs)) {
                            bool isOverride = (attrs.override_redirect != 0);
                            bool is32Bit = (attrs.depth == 32);
                            bool isUnmapped = (attrs.map_state == 0);

                            ViewportRect winRect{attrs.x, attrs.y, attrs.width, attrs.height};

                            if (is32Bit && (isOverride || isUnmapped || attrs.map_state == 2) && game_viewport_.Overlaps(winRect)) {
                                char* winName = nullptr;
                                if (pXFetchName) pXFetchName(display, children[i], &winName);
                                std::string titleStr = winName ? winName : "X11Window";
                                if (winName && pXFree) pXFree(winName);

                                OverlayWindowInfo info;
                                info.title = titleStr;
                                info.class_name = isOverride ? "X11OverrideRedirect" : (isUnmapped ? "X11UnmappedDraw" : "X11ARGBWindow");
                                info.handle = static_cast<uintptr_t>(children[i]);
                                info.rect = winRect;
                                info.is_topmost = isOverride;
                                info.is_transparent = true;
                                info.is_layered = true;
                                windows.push_back(info);
                            }
                        }
                    }
                    pXFree(children);
                }
                if (pXSync) pXSync(display, 0);
                pXCloseDisplay(display);
            }
            if (pXSetErrorHandler) pXSetErrorHandler(prevHandler);
        }
        dlclose(libX11);
    }

    // 2. On Linux: scan /proc for active processes that exhibit overlay characteristics
    DIR* procDir = opendir("/proc");
    if (procDir) {
        struct dirent* entry = nullptr;
        pid_t myPid = getpid();
        while ((entry = readdir(procDir)) != nullptr) {
            if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) continue;
            std::string name = entry->d_name;
            if (name.empty() || !std::isdigit(name[0])) continue;

            pid_t pid = std::atoi(name.c_str());
            if (pid <= 0 || pid == myPid) continue;

            std::string cmdPath = "/proc/" + name + "/cmdline";
            std::ifstream cmdFile(cmdPath);
            if (!cmdFile.is_open()) continue;

            std::string cmd;
            std::string line;
            while (std::getline(cmdFile, line, '\0')) {
                if (!cmd.empty()) cmd += " ";
                cmd += line;
            }

            std::string lowerCmd = ToLower(cmd);

            // Whitelist verified system compositors and legitimate gaming utilities
            static const std::vector<std::string> whitelistedTools = {
                "picom", "compton", "kwin", "mutter", "sway", "waybar",
                "wf-shell", "mangohud", "vkbasalt", "obs-vkcapture", "obs",
                "steam", "discord", "gamescope", "xwayland", "gnome-shell",
                "plasmashell", "xfwm4", "marco", "compiz"
            };

            // Match on the executable's own name only; a path or argument containing "obs"/"steam"
            // must not exempt an arbitrary program.
            std::string argv0 = lowerCmd.substr(0, lowerCmd.find(' '));
            size_t slash = argv0.find_last_of('/');
            if (slash != std::string::npos) argv0 = argv0.substr(slash + 1);
            bool isWhitelisted = false;
            for (const auto& w : whitelistedTools) {
                if (argv0 == w || (argv0.rfind(w, 0) == 0 && argv0.size() > w.size() &&
                                   !std::isalpha(static_cast<unsigned char>(argv0[w.size()])))) {
                    isWhitelisted = true;
                    break;
                }
            }
            if (isWhitelisted) continue;

            static const std::vector<std::string> overlayTools = {
                "gl-inject", "pyglass", "esp_overlay", "liboverlay",
                "gameoverlay", "cheat_overlay", "d3d_overlay", "aimbot_overlay"
            };

            for (const auto& tool : overlayTools) {
                if (lowerCmd.find(tool) != std::string::npos) {
                    OverlayWindowInfo info;
                    info.title = tool + " (Active Overlay Process)";
                    info.class_name = "LinuxOverlayProcess";
                    info.pid = static_cast<uint32_t>(pid);
                    info.handle = static_cast<uintptr_t>(pid);
                    info.rect = game_viewport_;
                    info.is_topmost = true;
                    info.is_transparent = true;
                    info.is_layered = true;
                    windows.push_back(info);
                    break;
                }
            }
        }
        closedir(procDir);
    }
#endif

    return windows;
}

bool OverlayDetector::IsSuspiciousOverlayWindow(const OverlayWindowInfo& win) const {
    std::string lowerTitle = ToLower(win.title);
    std::string lowerClass = ToLower(win.class_name);

    // Whitelist desktop compositors, official overlays (Steam, Discord, GeForce)
    static const std::vector<std::string> whitelistedTitles = {
        "picom", "compton", "kwin", "mutter", "sway", "waybar",
        "wf-shell", "mangohud", "steam", "steam overlay", "gameoverlayui",
        "discord overlay", "obs", "nvidia share", "geforce experience"
    };

    for (const auto& white : whitelistedTitles) {
        if (lowerTitle.find(white) != std::string::npos || lowerClass.find(white) != std::string::npos) {
            return false;
        }
    }

    // Check 1: Explicit topmost + transparent + layered window matching, enclosing, or intersecting viewport
    if (win.is_layered && win.is_transparent && win.is_topmost) {
        if (game_viewport_.Overlaps(win.rect)) {
            return true;
        }
    }

    // Check 2: Topmost transparent window with suspicious class or window title keywords
    static const std::vector<std::string> suspiciousKeywords = {
        "overlay", "esp", "wallhack", "imgui", "dear imgui",
        "external", "aimbot", "chams", "d3d overlay", "transparent draw",
        "crosshair", "radar", "glow"
    };

    for (const auto& kw : suspiciousKeywords) {
        if (lowerTitle.find(kw) != std::string::npos || lowerClass.find(kw) != std::string::npos) {
            if (win.is_topmost || win.is_layered || win.is_transparent) {
                return true;
            }
        }
    }

    return false;
}

std::vector<core::DetectionEvent> OverlayDetector::DetectSuspiciousWindows() {
    std::vector<core::DetectionEvent> events;
    auto windows = EnumerateTopLevelWindows();

    for (const auto& win : windows) {
        if (IsSuspiciousOverlayWindow(win)) {
            core::DetectionEvent ev;
            ev.type = core::DetectionType::OVERLAY_HIJACK_DETECTED;
            ev.severity = core::Severity::HIGH;
            ev.threat_score = 75;
            ev.component = "OverlayDetector::WindowScanner";
            ev.timestamp = static_cast<uint64_t>(std::time(nullptr));

            std::ostringstream ss;
            ss << "Suspicious transparent overlay window detected: '" << win.title 
               << "' (Class: '" << win.class_name << "', PID: " << win.pid 
               << ", Rect: [" << win.rect.x << "," << win.rect.y << " " 
               << win.rect.width << "x" << win.rect.height << "]"
               << ", Layered=" << win.is_layered 
               << ", Transparent=" << win.is_transparent 
               << ", Topmost=" << win.is_topmost << ")";
            ev.details = ss.str();

            events.push_back(ev);
        }
    }

    return events;
}

bool OverlayDetector::IsAddressInLoadedModule(uintptr_t addr) const {
    if (addr < 0x10000) return false;

#if defined(_WIN32)
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != 0) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE) {
            DWORD execMask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
            if (mbi.Protect & execMask) {
                return true;
            }
        }
    }
    return false;
#else
    auto regions = memory::MemoryScanner::Instance().QueryMemoryRegions();
    for (const auto& reg : regions) {
        if (addr >= reg.start && addr < reg.end) {
            // Must be backed by an image file, not heap/stack, and marked executable
            if (!reg.is_backed_by_file || reg.pathname.empty() || !reg.executable) {
                return false;
            }
            if (reg.pathname == "[heap]" || reg.pathname == "[stack]" || reg.pathname == "[vdso]") {
                return false;
            }
            std::string lowerPath = ToLower(reg.pathname);
            if (lowerPath.find("inject") != std::string::npos ||
                lowerPath.find("hook.so") != std::string::npos ||
                lowerPath.find("libcheat") != std::string::npos ||
                lowerPath.find("(deleted)") != std::string::npos) {
                return false;
            }
            return true;
        }
    }
    return false;
#endif
}

std::optional<core::DetectionEvent> OverlayDetector::InspectRenderingPointer(const char* routine_name, void* function_ptr) {
    if (!function_ptr) return std::nullopt;

    uintptr_t addr = reinterpret_cast<uintptr_t>(function_ptr);
    if (addr < 0x10000) return std::nullopt;

    // 1. Check if the function pointer itself resides in a legitimate executable module image
    if (!IsAddressInLoadedModule(addr)) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::RENDERING_HOOK_DETECTED;
        ev.severity = core::Severity::CRITICAL;
        ev.threat_score = 100;
        ev.component = "OverlayDetector::SwapchainValidator";
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));

        std::ostringstream ss;
        ss << "Swapchain function pointer '" << (routine_name ? routine_name : "VTableEntry")
           << "' [" << PtrToHex(addr) << "] points outside legitimate loaded module address space (Unbacked Trampoline)";
        ev.details = ss.str();
        return ev;
    }

    // 2. Check for inline hooks (JMP rel32, MOV RAX, imm; JMP RAX, INT3, etc.)
    auto hook = memory::Unhooker::Instance().InspectFunction(routine_name, function_ptr);
    if (hook) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::RENDERING_HOOK_DETECTED;
        ev.severity = core::Severity::CRITICAL;
        ev.threat_score = 95;
        ev.component = "OverlayDetector::RenderingIntegrity";
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));

        std::ostringstream ss;
        ss << "Inline hook detected on rendering swapchain routine '" << routine_name 
           << "' [" << PtrToHex(addr) << "] Type: " << hook->hook_type 
           << " -> Diverted Target: " << PtrToHex(hook->target_destination);
        ev.details = ss.str();
        return ev;
    }

    return std::nullopt;
}

std::vector<core::DetectionEvent> OverlayDetector::AuditSwapchainHooks() {
    std::vector<core::DetectionEvent> events;

    // 1. Audit system graphics swapchain APIs
    std::vector<std::pair<const char*, void*>> graphicsApis;

#if defined(_WIN32)
    HMODULE hOpengl = GetModuleHandleA("opengl32.dll");
    if (hOpengl) {
        graphicsApis.emplace_back("wglSwapBuffers", reinterpret_cast<void*>(GetProcAddress(hOpengl, "wglSwapBuffers")));
    }
    HMODULE hDxgi = GetModuleHandleA("dxgi.dll");
    if (hDxgi) {
        graphicsApis.emplace_back("CreateDXGIFactory", reinterpret_cast<void*>(GetProcAddress(hDxgi, "CreateDXGIFactory")));
        graphicsApis.emplace_back("CreateDXGIFactory1", reinterpret_cast<void*>(GetProcAddress(hDxgi, "CreateDXGIFactory1")));
        graphicsApis.emplace_back("CreateDXGIFactory2", reinterpret_cast<void*>(GetProcAddress(hDxgi, "CreateDXGIFactory2")));
    }
    HMODULE hD3d11 = GetModuleHandleA("d3d11.dll");
    if (hD3d11) {
        graphicsApis.emplace_back("D3D11CreateDeviceAndSwapChain", reinterpret_cast<void*>(GetProcAddress(hD3d11, "D3D11CreateDeviceAndSwapChain")));
    }
    HMODULE hD3d9 = GetModuleHandleA("d3d9.dll");
    if (hD3d9) {
        graphicsApis.emplace_back("Direct3DCreate9", reinterpret_cast<void*>(GetProcAddress(hD3d9, "Direct3DCreate9")));
    }
    HMODULE hVulkan = GetModuleHandleA("vulkan-1.dll");
    if (hVulkan) {
        graphicsApis.emplace_back("vkQueuePresentKHR", reinterpret_cast<void*>(GetProcAddress(hVulkan, "vkQueuePresentKHR")));
    }
#else
    void* pGlx = dlsym(RTLD_DEFAULT, "glXSwapBuffers");
    if (pGlx) graphicsApis.emplace_back("glXSwapBuffers", pGlx);

    void* pEgl = dlsym(RTLD_DEFAULT, "eglSwapBuffers");
    if (pEgl) graphicsApis.emplace_back("eglSwapBuffers", pEgl);

    void* pVk = dlsym(RTLD_DEFAULT, "vkQueuePresentKHR");
    if (pVk) graphicsApis.emplace_back("vkQueuePresentKHR", pVk);
#endif

    for (const auto& [name, ptr] : graphicsApis) {
        auto ev = InspectRenderingPointer(name, ptr);
        if (ev) {
            events.push_back(*ev);
        }
    }

    // 2. Audit dynamically registered vtables (e.g. game IDXGISwapChain or Vulkan dispatch table)
    std::vector<void**> vtablesCopy;
    std::vector<size_t> sizesCopy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        vtablesCopy = registered_vtables_;
        sizesCopy = registered_vtable_sizes_;
    }

    for (size_t i = 0; i < vtablesCopy.size(); ++i) {
        void** vtable = vtablesCopy[i];
        size_t count = sizesCopy[i];
        if (!vtable) continue;

        for (size_t idx = 0; idx < count; ++idx) {
            void* entryPtr = vtable[idx];
            if (!entryPtr) continue;

            std::string entryName = "VTable[" + std::to_string(i) + "][" + std::to_string(idx) + "]";
            auto ev = InspectRenderingPointer(entryName.c_str(), entryPtr);
            if (ev) {
                events.push_back(*ev);
            }
        }
    }

    return events;
}

std::vector<core::DetectionEvent> OverlayDetector::PerformAudit() {
    std::vector<core::DetectionEvent> events;

    auto winEvents = DetectSuspiciousWindows();
    events.insert(events.end(), winEvents.begin(), winEvents.end());

    auto hookEvents = AuditSwapchainHooks();
    events.insert(events.end(), hookEvents.begin(), hookEvents.end());

    return events;
}

} // namespace noescape::overlay
