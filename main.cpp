// ============================================================================
// NoEscape Anti-Cheat Engine - Standalone Open Source Edition (v7.0)
// Next-Generation C++20 Ring-3 Defense System
// ============================================================================

#include "noescape/core/engine.hpp"
#include "noescape/core/logger.hpp"
#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

#if defined(_WIN32)
#include <windows.h>
#endif

static std::atomic<bool> g_running{true};

void SignalHandler(int signum) {
    (void)signum;
    g_running = false;
}

void PrintBanner() {
    std::cout << "\033[1;36m"
              << "====================================================================\n"
              << "     _   _       _____                         \n"
              << "    | \\ | |     |  ___|                        \n"
              << "    |  \\| | ___ | |__   ___  ___ __ _ _ __   ___ \n"
              << "    | . ` |/ _ \\|  __| / __|/ __/ _` | '_ \\ / _ \\\n"
              << "    | |\\  | (_) | |___ \\__ \\ (_| (_| | |_) |  __/\n"
              << "    |_| \\_|\\___/\\____/ |___/\\___\\__,_| .__/ \\___|\n"
              << "                                     | |         \n"
              << "     Anti-Cheat System (v7.0 - C++20)|_|         \n"
              << "====================================================================\n"
              << "\033[0m" << std::endl;
}

int main(int argc, char* argv[]) {
#if defined(_WIN32)
    // Optional: Hide console window in stealth mode
    // if (HWND hwnd = GetConsoleWindow()) ShowWindow(hwnd, SW_HIDE);
#endif

    std::signal(SIGINT, SignalHandler);
    std::signal(SIGTERM, SignalHandler);

    PrintBanner();

    noescape::core::EngineConfig cfg;
    cfg.enforceBanOnViolation = true;
    cfg.banScoreThreshold = 100;
    cfg.panelUrl = "http://127.0.0.1:8080/api/ac";
    cfg.showBanUi = true;

    noescape::core::AntiCheatEngine engine(cfg);

    engine.SetBanCallback([](const std::string& reason, uint32_t finalScore) {
        std::cout << "\n\033[1;41;37m [BAN ENFORCED] " << reason 
                  << " (Final Threat Score: " << finalScore << ") \033[0m\n\n";
    });

    if (!engine.Initialize()) {
        std::cerr << "Failed to initialize AntiCheat engine.\n";
        return 1;
    }

    noescape::core::Logger::Instance().Info("Running initial synchronous security audit...");
    auto initialEvents = engine.AuditCycle();
    noescape::core::Logger::Instance().Info("Initial audit completed with " + 
                                           std::to_string(initialEvents.size()) + " detection events.");

    if (argc > 1 && std::string(argv[1]) == "--once") {
        return engine.IsBanned() ? 1 : 0;
    }

    noescape::core::Logger::Instance().Info("Starting real-time continuous background monitoring. Press Ctrl+C to stop.");
    engine.Start();

    while (g_running && !engine.IsBanned()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    noescape::core::Logger::Instance().Info("Shutting down NoEscape Anti-Cheat Engine...");
    engine.Stop();

    return 0;
}
