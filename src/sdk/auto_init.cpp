#if defined(NOESCAPE_EXPORTS) || defined(NOESCAPE_BUILD_SHARED)

#include "noescape_sdk.h"

// ============================================================================
// Windows Platform Auto-Initialization (DllMain / Loader Lock Safe)
// ============================================================================
#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <process.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <cstring>
#include <cstdlib>

namespace {

HANDLE g_winWorkerThread = NULL;
std::atomic<bool> g_winShutdownRequested{false};
std::atomic<bool> g_winInitInProgress{false};
std::atomic<bool> g_winInitFinished{false};

DWORD WINAPI WindowsAutoInitWorker(LPVOID lpParam) {
    (void)lpParam;
    g_winInitInProgress.store(true, std::memory_order_release);

    // Yield/sleep briefly to let OS Loader Lock release completely
    for (int i = 0; i < 10 && !g_winShutdownRequested.load(std::memory_order_acquire); ++i) {
        Sleep(1);
    }

    if (g_winShutdownRequested.load(std::memory_order_acquire)) {
        g_winInitFinished.store(true, std::memory_order_release);
        return 0;
    }

    // Fast check: allow runtime opt-out (in secure production builds, require NOESCAPE_TEST_MODE)
#if defined(NOESCAPE_SECURE_BUILD) || defined(NDEBUG)
    char testModeBuf[16]{};
    DWORD testLen = GetEnvironmentVariableA("NOESCAPE_TEST_MODE", testModeBuf, sizeof(testModeBuf));
    bool allowDevOptOut = (testLen > 0 && (_stricmp(testModeBuf, "1") == 0 || _stricmp(testModeBuf, "true") == 0));
#else
    bool allowDevOptOut = true;
#endif

    if (allowDevOptOut) {
        char envBuf[256]{};
        DWORD len = GetEnvironmentVariableA("NOESCAPE_DISABLE_AUTO_INIT", envBuf, sizeof(envBuf));
        if (len > 0 && (_stricmp(envBuf, "1") == 0 || _stricmp(envBuf, "true") == 0)) {
            g_winInitFinished.store(true, std::memory_order_release);
            return 0;
        }

        len = GetEnvironmentVariableA("NOESCAPE_AUTO_START", envBuf, sizeof(envBuf));
        if (len > 0 && (_stricmp(envBuf, "0") == 0 || _stricmp(envBuf, "false") == 0)) {
            g_winInitFinished.store(true, std::memory_order_release);
            return 0;
        }
    }

    NoEscapeConfig cfg = NoEscape_GetDefaultConfig();

    // Stack buffers for environment overrides (NoEscape_Init copies into std::string immediately)
    char urlBuf[256]{};
    len = GetEnvironmentVariableA("NOESCAPE_PANEL_URL", urlBuf, sizeof(urlBuf));
    if (len > 0) {
        cfg.panel_url = urlBuf;
    }

    char keyBuf[256]{};
    len = GetEnvironmentVariableA("NOESCAPE_SECRET_KEY", keyBuf, sizeof(keyBuf));
    if (len > 0) {
        cfg.secret_key = keyBuf;
    }

    char dumpBuf[MAX_PATH]{};
    len = GetEnvironmentVariableA("NOESCAPE_DUMP_DIR", dumpBuf, sizeof(dumpBuf));
    if (len > 0) {
        cfg.blackbox_dump_dir = dumpBuf;
    }

    char threshBuf[32]{};
    len = GetEnvironmentVariableA("NOESCAPE_BAN_THRESHOLD", threshBuf, sizeof(threshBuf));
    if (allowDevOptOut && len > 0) {
        int v = std::atoi(threshBuf);
        if (v > 0) cfg.ban_threshold = static_cast<uint32_t>(v);
    }

    char enforceBuf[16]{};
    len = GetEnvironmentVariableA("NOESCAPE_ENFORCE_BAN", enforceBuf, sizeof(enforceBuf));
    if (allowDevOptOut && len > 0) {
        if (_stricmp(enforceBuf, "0") == 0 || _stricmp(enforceBuf, "false") == 0) {
            cfg.enforce_ban = false;
        } else if (_stricmp(enforceBuf, "1") == 0 || _stricmp(enforceBuf, "true") == 0) {
            cfg.enforce_ban = true;
        }
    }

    char antiDebugBuf[16]{};
    len = GetEnvironmentVariableA("NOESCAPE_ENABLE_ANTI_DEBUG", antiDebugBuf, sizeof(antiDebugBuf));
    if (allowDevOptOut && len > 0) {
        if (_stricmp(antiDebugBuf, "0") == 0 || _stricmp(antiDebugBuf, "false") == 0) {
            cfg.enable_anti_debug = false;
        } else if (_stricmp(antiDebugBuf, "1") == 0 || _stricmp(antiDebugBuf, "true") == 0) {
            cfg.enable_anti_debug = true;
        }
    }

    char heartbeatBuf[16]{};
    len = GetEnvironmentVariableA("NOESCAPE_ENABLE_HEARTBEAT", heartbeatBuf, sizeof(heartbeatBuf));
    if (len > 0) {
        if (_stricmp(heartbeatBuf, "1") == 0 || _stricmp(heartbeatBuf, "true") == 0) {
            cfg.enable_heartbeat = true;
        }
    }

    char termBuf[16]{};
    len = GetEnvironmentVariableA("NOESCAPE_TERMINATE_ON_BAN", termBuf, sizeof(termBuf));
    if (allowDevOptOut && len > 0) {
        if (_stricmp(termBuf, "0") == 0 || _stricmp(termBuf, "false") == 0) {
            cfg.terminate_on_ban = false;
        } else if (_stricmp(termBuf, "1") == 0 || _stricmp(termBuf, "true") == 0) {
            cfg.terminate_on_ban = true;
        }
    } else {
        cfg.terminate_on_ban = true;
    }

    char banUiBuf[16]{};
    len = GetEnvironmentVariableA("NOESCAPE_SHOW_BAN_UI", banUiBuf, sizeof(banUiBuf));
    if (len > 0) {
        if (_stricmp(banUiBuf, "0") == 0 || _stricmp(banUiBuf, "false") == 0) {
            cfg.show_ban_ui = false;
        } else if (_stricmp(banUiBuf, "1") == 0 || _stricmp(banUiBuf, "true") == 0) {
            cfg.show_ban_ui = true;
        }
    } else {
        cfg.show_ban_ui = true;
    }

    char uiPathBuf[MAX_PATH]{};
    len = GetEnvironmentVariableA("NOESCAPE_BAN_UI_PATH", uiPathBuf, sizeof(uiPathBuf));
    if (len > 0) {
        cfg.ban_ui_path = uiPathBuf;
    }

    if (!g_winShutdownRequested.load(std::memory_order_acquire)) {
        if (NoEscape_Init(&cfg) == 0) {
            if (g_winShutdownRequested.load(std::memory_order_acquire)) {
                NoEscape_Shutdown();
            } else {
                NoEscape_Start();
            }
        }
    }

    g_winInitFinished.store(true, std::memory_order_release);

    // Keep thread alive until process shutdown or explicit FreeLibrary unload
    while (!g_winShutdownRequested.load(std::memory_order_acquire)) {
        Sleep(20);
    }
    return 0;
}

} // namespace

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);

        // Fast opt-out check to avoid thread creation if explicitly disabled
        {
#if defined(NOESCAPE_SECURE_BUILD) || defined(NDEBUG)
            char testModeBuf[16]{};
            DWORD testLen = GetEnvironmentVariableA("NOESCAPE_TEST_MODE", testModeBuf, sizeof(testModeBuf));
            bool allowDevOptOut = (testLen > 0 && (_stricmp(testModeBuf, "1") == 0 || _stricmp(testModeBuf, "true") == 0));
#else
            bool allowDevOptOut = true;
#endif
            if (allowDevOptOut) {
                char envBuf[32]{};
                DWORD len = GetEnvironmentVariableA("NOESCAPE_DISABLE_AUTO_INIT", envBuf, sizeof(envBuf));
                if (len > 0 && len < sizeof(envBuf) && (_stricmp(envBuf, "1") == 0 || _stricmp(envBuf, "true") == 0)) {
                    break;
                }
                len = GetEnvironmentVariableA("NOESCAPE_AUTO_START", envBuf, sizeof(envBuf));
                if (len > 0 && len < sizeof(envBuf) && (_stricmp(envBuf, "0") == 0 || _stricmp(envBuf, "false") == 0)) {
                    break;
                }
            }
        }

        // Classic Windows Loader Lock Rule:
        // Spawning a background worker thread via CreateThread is safe.
        // Never wait for or perform blocking operations inside DllMain.
        g_winWorkerThread = CreateThread(
            nullptr,
            0,
            WindowsAutoInitWorker,
            nullptr,
            0,
            nullptr
        );
        break;

    case DLL_PROCESS_DETACH:
        g_winShutdownRequested.store(true, std::memory_order_release);

        if (lpReserved != nullptr) {
            // Process termination (ExitProcess):
            // Windows has already forcefully terminated all other threads.
            // Calling NoEscape_Shutdown() or waiting on/joining threads causes an unrecoverable
            // loader lock deadlock because the worker threads are already dead.
            if (g_winWorkerThread != NULL) {
                CloseHandle(g_winWorkerThread);
                g_winWorkerThread = NULL;
            }
        } else {
            // Explicit unload via FreeLibrary while process continues:
            // Other threads are still running normally, so full graceful shutdown is performed.
            NoEscape_Shutdown();
            if (g_winWorkerThread != NULL) {
                WaitForSingleObject(g_winWorkerThread, 3000);
                CloseHandle(g_winWorkerThread);
                g_winWorkerThread = NULL;
            }
        }
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

// ============================================================================
// Linux Platform Auto-Initialization (ELF Constructor & Destructor)
// ============================================================================
#else

#include <pthread.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <strings.h>
#include <chrono>
#include <thread>
#include <atomic>

namespace {

pthread_t g_linuxWorkerThread{};
std::atomic<bool> g_linuxThreadSpawned{false};
std::atomic<bool> g_linuxShutdownRequested{false};
std::atomic<bool> g_linuxInitInProgress{false};
std::atomic<bool> g_linuxInitFinished{false};

void* LinuxAutoInitWorker(void* arg) {
    (void)arg;
    g_linuxInitInProgress.store(true, std::memory_order_release);

    // Yield/sleep briefly to let dynamic linker complete relocations and host process main begin
    for (int i = 0; i < 10 && !g_linuxShutdownRequested.load(std::memory_order_acquire); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    if (g_linuxShutdownRequested.load(std::memory_order_acquire)) {
        g_linuxInitFinished.store(true, std::memory_order_release);
        return nullptr;
    }

#if defined(NOESCAPE_SECURE_BUILD) || defined(NDEBUG)
    const char* testEnv = std::getenv("NOESCAPE_TEST_MODE");
    bool allowDevOptOut = (testEnv && (std::strcmp(testEnv, "1") == 0 || strcasecmp(testEnv, "true") == 0));
#else
    bool allowDevOptOut = true;
#endif

    if (allowDevOptOut) {
        const char* disableEnv = std::getenv("NOESCAPE_DISABLE_AUTO_INIT");
        if (disableEnv && (std::strcmp(disableEnv, "1") == 0 || strcasecmp(disableEnv, "true") == 0)) {
            g_linuxInitFinished.store(true, std::memory_order_release);
            return nullptr;
        }

        const char* autoStartEnv = std::getenv("NOESCAPE_AUTO_START");
        if (autoStartEnv && (std::strcmp(autoStartEnv, "0") == 0 || strcasecmp(autoStartEnv, "false") == 0)) {
            g_linuxInitFinished.store(true, std::memory_order_release);
            return nullptr;
        }
    }

    NoEscapeConfig cfg = NoEscape_GetDefaultConfig();

    // Support runtime environment variable overrides for headless / preloaded deployments
    const char* panelUrlEnv = std::getenv("NOESCAPE_PANEL_URL");
    if (panelUrlEnv && std::strlen(panelUrlEnv) > 0) {
        cfg.panel_url = panelUrlEnv;
    }

    const char* secretKeyEnv = std::getenv("NOESCAPE_SECRET_KEY");
    if (secretKeyEnv && std::strlen(secretKeyEnv) > 0) {
        cfg.secret_key = secretKeyEnv;
    }

    const char* dumpDirEnv = std::getenv("NOESCAPE_DUMP_DIR");
    if (dumpDirEnv && std::strlen(dumpDirEnv) > 0) {
        cfg.blackbox_dump_dir = dumpDirEnv;
    }

    const char* banThreshEnv = std::getenv("NOESCAPE_BAN_THRESHOLD");
    if (allowDevOptOut && banThreshEnv) {
        char* endp = nullptr;
        unsigned long v = std::strtoul(banThreshEnv, &endp, 10);
        if (endp && *endp == '\0' && v > 0) {
            cfg.ban_threshold = static_cast<uint32_t>(v);
        }
    }

    const char* enforceBanEnv = std::getenv("NOESCAPE_ENFORCE_BAN");
    if (allowDevOptOut && enforceBanEnv) {
        if (std::strcmp(enforceBanEnv, "0") == 0 || strcasecmp(enforceBanEnv, "false") == 0) {
            cfg.enforce_ban = false;
        } else if (std::strcmp(enforceBanEnv, "1") == 0 || strcasecmp(enforceBanEnv, "true") == 0) {
            cfg.enforce_ban = true;
        }
    }

    const char* antiDebugEnv = std::getenv("NOESCAPE_ENABLE_ANTI_DEBUG");
    if (allowDevOptOut && antiDebugEnv) {
        if (std::strcmp(antiDebugEnv, "0") == 0 || strcasecmp(antiDebugEnv, "false") == 0) {
            cfg.enable_anti_debug = false;
        } else if (std::strcmp(antiDebugEnv, "1") == 0 || strcasecmp(antiDebugEnv, "true") == 0) {
            cfg.enable_anti_debug = true;
        }
    }

    const char* heartbeatEnv = std::getenv("NOESCAPE_ENABLE_HEARTBEAT");
    if (heartbeatEnv) {
        if (std::strcmp(heartbeatEnv, "1") == 0 || strcasecmp(heartbeatEnv, "true") == 0) {
            cfg.enable_heartbeat = true;
        }
    }

    const char* termEnv = std::getenv("NOESCAPE_TERMINATE_ON_BAN");
    if (allowDevOptOut && termEnv) {
        if (std::strcmp(termEnv, "0") == 0 || strcasecmp(termEnv, "false") == 0) {
            cfg.terminate_on_ban = false;
        } else if (std::strcmp(termEnv, "1") == 0 || strcasecmp(termEnv, "true") == 0) {
            cfg.terminate_on_ban = true;
        }
    } else {
        cfg.terminate_on_ban = true;
    }

    const char* banUiEnv = std::getenv("NOESCAPE_SHOW_BAN_UI");
    if (banUiEnv) {
        if (std::strcmp(banUiEnv, "0") == 0 || strcasecmp(banUiEnv, "false") == 0) {
            cfg.show_ban_ui = false;
        } else if (std::strcmp(banUiEnv, "1") == 0 || strcasecmp(banUiEnv, "true") == 0) {
            cfg.show_ban_ui = true;
        }
    } else {
        cfg.show_ban_ui = true;
    }

    const char* banUiPathEnv = std::getenv("NOESCAPE_BAN_UI_PATH");
    if (banUiPathEnv && std::strlen(banUiPathEnv) > 0) {
        cfg.ban_ui_path = banUiPathEnv;
    }

    if (!g_linuxShutdownRequested.load(std::memory_order_acquire)) {
        if (NoEscape_Init(&cfg) == 0) {
            if (!g_linuxShutdownRequested.load(std::memory_order_acquire)) {
                NoEscape_Start();
            }
        }
    }

    g_linuxInitFinished.store(true, std::memory_order_release);

    // Keep worker thread alive until shutdown requested, preventing premature unmapping
    // of its thread stack while background engine audits are running.
    while (!g_linuxShutdownRequested.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    return nullptr;
}

std::atomic<bool> g_linuxDestructorRan{false};

void NoEscape_AutoInit_Destructor();

__attribute__((constructor))
void NoEscape_AutoInit_Constructor() {
    // Fast path: avoid thread creation if explicitly disabled
#if defined(NOESCAPE_SECURE_BUILD) || defined(NDEBUG)
    const char* testEnv = std::getenv("NOESCAPE_TEST_MODE");
    bool allowDevOptOut = (testEnv && (std::strcmp(testEnv, "1") == 0 || strcasecmp(testEnv, "true") == 0));
#else
    bool allowDevOptOut = true;
#endif

    if (allowDevOptOut) {
        const char* disableEnv = std::getenv("NOESCAPE_DISABLE_AUTO_INIT");
        if (disableEnv && (std::strcmp(disableEnv, "1") == 0 || strcasecmp(disableEnv, "true") == 0)) {
            return;
        }
        const char* autoStartEnv = std::getenv("NOESCAPE_AUTO_START");
        if (autoStartEnv && (std::strcmp(autoStartEnv, "0") == 0 || strcasecmp(autoStartEnv, "false") == 0)) {
            return;
        }
    }

    // Register atexit handler so clean shutdown occurs before C++ runtime / thread caches are torn down
    std::atexit(NoEscape_AutoInit_Destructor);

    g_linuxThreadSpawned.store(true, std::memory_order_release);
    if (pthread_create(&g_linuxWorkerThread, nullptr, LinuxAutoInitWorker, nullptr) != 0) {
        g_linuxThreadSpawned.store(false, std::memory_order_release);
    }
}

__attribute__((destructor))
void NoEscape_AutoInit_Destructor() {
    if (g_linuxDestructorRan.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    g_linuxShutdownRequested.store(true, std::memory_order_release);

    // If init thread was spawned and has not finished initialization yet, wait briefly for it
    if (g_linuxThreadSpawned.load(std::memory_order_acquire)) {
        int waitCount = 0;
        while (!g_linuxInitFinished.load(std::memory_order_acquire) && waitCount++ < 200) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    NoEscape_Shutdown();

    // Cleanly join the auto-init worker thread before dynamic linker unloads the library
    if (g_linuxThreadSpawned.exchange(false, std::memory_order_acq_rel)) {
        pthread_join(g_linuxWorkerThread, nullptr);
    }
}

} // namespace

#endif

#endif // NOESCAPE_EXPORTS || NOESCAPE_BUILD_SHARED
