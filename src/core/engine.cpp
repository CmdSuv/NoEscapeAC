#include "noescape/core/engine.hpp"
#include "noescape/security/anti_debug.hpp"
#include "noescape/security/integrity.hpp"
#include "noescape/security/timing.hpp"
#include "noescape/memory/memory_scanner.hpp"
#include "noescape/memory/unhooker.hpp"
#include "noescape/memory/canary_monitor.hpp"
#include "noescape/forensics/process_analyzer.hpp"
#include "noescape/forensics/artifact_analyzer.hpp"
#include "noescape/dma/dma_detector.hpp"
#include "noescape/overlay/overlay_detector.hpp"
#include "noescape/core/blackbox.hpp"

#include <chrono>
#include <thread>
#include <random>
#include <cstring>
#include <cstdlib>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace noescape::core {

AntiCheatEngine::AntiCheatEngine(EngineConfig config)
    : config_(std::move(config)),
      thread_pool_(2),
      panel_client_(config_.panelUrl, config_.secretKey),
      aim_analyzer_(64) {}

AntiCheatEngine::~AntiCheatEngine() {
    Stop();
}

bool AntiCheatEngine::Initialize() {
    Logger::Instance().Info("Initializing NoEscape Anti-Cheat Engine v7.0 (C++20 Unified Ring-3 Architecture)...");

    // Must run before HideCurrentThread(): it opens /proc/self handles that become
    // inaccessible once the process is marked non-dumpable.
    if (config_.enableMemoryScan) {
        memory::CanaryMonitor::Instance().Initialize();
        default_signatures_ = memory::MemoryScanner::GetDefaultCheatSignatures();
    }

    if (config_.enableAntiDebug) {
        security::AntiDebug::HideCurrentThread();
    }

    if (config_.enableIntegrityScan) {
        if (security::IntegrityChecker::Instance().Initialize()) {
            Logger::Instance().Info("Self-integrity baseline initialized (Text hash: " + 
                                   security::IntegrityChecker::Instance().GetBaselineHash().substr(0, 16) + "...)");
        } else {
            Logger::Instance().Warn("Failed to initialize self-integrity baseline");
        }
    }

    if (config_.enableSpeedhackDetection) {
        if (security::TimingIntegrity::Instance().Calibrate(30)) {
            Logger::Instance().Info("Timing TSC baseline calibrated (" + 
                                   std::to_string(static_cast<uint64_t>(security::TimingIntegrity::Instance().GetCyclesPerMs())) + " cycles/ms)");
        }
    }

    if (config_.enableDmaDetection) {
        dma::DmaDetector::Instance().Calibrate(512, 10);
    }

    if (config_.enableBlackboxDump && !config_.blackboxDumpDirectory.empty()) {
        BlackboxDumper::Instance().SetDumpDirectory(config_.blackboxDumpDirectory);
    }

    Logger::Instance().Info("Hardware ID Fingerprint: " + panel_client_.GetHwid());
    return true;
}

std::vector<DetectionEvent> AntiCheatEngine::VerifyPanelStatus() {
    std::vector<DetectionEvent> events;
    auto res = panel_client_.QueryBanStatus();
    using network::BanCheckStatus;

    if (res.status == BanCheckStatus::BANNED) {
        DetectionEvent ev;
        ev.type = DetectionType::HEARTBEAT_TAMPERING;
        ev.severity = Severity::FATAL_BAN;
        ev.component = "PanelClient::GlobalBanList";
        ev.details = res.reason;
        ev.timestamp = static_cast<uint64_t>(time(nullptr));
        ev.threat_score = 100;
        events.push_back(ev);
        panel_failures_ = 0;
    } else if (res.status == BanCheckStatus::CLEAN) {
        panel_failures_ = 0;
    } else {
        // Unreachable backend or bad signature: a forged reply is far more suspicious than silence
        ++panel_failures_;
        bool forged = (res.status == BanCheckStatus::SIGNATURE_INVALID);
        if (forged || panel_failures_ >= 5) {
            DetectionEvent ev;
            ev.type = DetectionType::HEARTBEAT_TAMPERING;
            ev.severity = forged ? Severity::HIGH : Severity::MEDIUM;
            ev.component = "PanelClient::Verification";
            ev.details = res.reason + " (consecutive failures: " + std::to_string(panel_failures_) + ")";
            ev.timestamp = static_cast<uint64_t>(time(nullptr));
            ev.threat_score = forged ? 60 : 20;
            events.push_back(ev);
            if (!forged) panel_failures_ = 0; // re-arm: at most one scored event per 5 failed checks
        }
    }

    for (const auto& ev : events) ProcessDetection(ev);
    return events;
}

std::vector<DetectionEvent> AntiCheatEngine::AuditCycle() {
    std::vector<DetectionEvent> cycleEvents;
    if (!running_.load(std::memory_order_acquire)) return cycleEvents;

    // 1. Anti-Debug Audit
    if (config_.enableAntiDebug) {
        auto adEvents = security::AntiDebug::PerformAudit(config_.blacklistedProcesses);
        cycleEvents.insert(cycleEvents.end(), adEvents.begin(), adEvents.end());
    }
    if (!running_.load(std::memory_order_acquire)) return cycleEvents;

    // 2. Self-Integrity Check
    if (config_.enableIntegrityScan) {
        auto integEvent = security::IntegrityChecker::Instance().VerifyIntegrity();
        if (integEvent) {
            cycleEvents.push_back(*integEvent);
        }
    }
    if (!running_.load(std::memory_order_acquire)) return cycleEvents;

    // 3. Timing / Speedhack Check
    if (config_.enableSpeedhackDetection) {
        auto speedEvent = security::TimingIntegrity::Instance().CheckSpeedhack();
        if (speedEvent) {
            cycleEvents.push_back(*speedEvent);
        }
    }
    if (!running_.load(std::memory_order_acquire)) return cycleEvents;

    // 4. Memory Scanner (Unbacked executable memory + signature scan)
    if (config_.enableMemoryScan) {
        auto memEvents = memory::MemoryScanner::Instance().PerformAudit(default_signatures_);
        cycleEvents.insert(cycleEvents.end(), memEvents.begin(), memEvents.end());
    }
    if (!running_.load(std::memory_order_acquire)) return cycleEvents;

    // 4b. Tripwire (canary) memory: detects external memory writes
    if (config_.enableMemoryScan) {
        auto canaryEvents = memory::CanaryMonitor::Instance().Check();
        cycleEvents.insert(cycleEvents.end(), canaryEvents.begin(), canaryEvents.end());
    }
    if (!running_.load(std::memory_order_acquire)) return cycleEvents;

    // 5. Inline Unhooker Audit
    if (config_.enableUnhooker) {
        auto hookEvents = memory::Unhooker::Instance().AuditSystemHooks();
        cycleEvents.insert(cycleEvents.end(), hookEvents.begin(), hookEvents.end());
    }
    if (!running_.load(std::memory_order_acquire)) return cycleEvents;

    // 6. Forensics Process & Environment Audit
    if (config_.enableForensics) {
        std::vector<std::string> cmdlineBlacklist = {"--inject", "gdb -p", "frida", "inject.so", "ld_preload="};
        auto procEvents = forensics::ProcessAnalyzer::Instance().AuditProcesses(
            config_.blacklistedProcesses,
            cmdlineBlacklist
        );
        cycleEvents.insert(cycleEvents.end(), procEvents.begin(), procEvents.end());
        if (!running_.load(std::memory_order_acquire)) return cycleEvents;

        std::vector<std::string> driverBlacklist = {"dbk64", "winring0", "ksdumper", "leechcore"};
        auto artEvents = forensics::ArtifactAnalyzer::Instance().PerformAudit(
            config_.blacklistedArtifacts,
            driverBlacklist
        );
        cycleEvents.insert(cycleEvents.end(), artEvents.begin(), artEvents.end());
    }
    if (!running_.load(std::memory_order_acquire)) return cycleEvents;

    // 7. DMA Hardware & Bus Latency Check
    if (config_.enableDmaDetection) {
        auto dmaEvents = dma::DmaDetector::Instance().PerformAudit();
        cycleEvents.insert(cycleEvents.end(), dmaEvents.begin(), dmaEvents.end());
    }
    if (!running_.load(std::memory_order_acquire)) return cycleEvents;

    // 8. Overlay & ESP/Wallhack Detector (Rendering hooks & fake window scanner)
    if (config_.enableOverlayDetection) {
        auto overlayEvents = overlay::OverlayDetector::Instance().PerformAudit();
        cycleEvents.insert(cycleEvents.end(), overlayEvents.begin(), overlayEvents.end());
    }
    if (!running_.load(std::memory_order_acquire)) return cycleEvents;

    // Process all generated events through threat scoring
    for (const auto& ev : cycleEvents) {
        ProcessDetection(ev);
    }

    return cycleEvents;
}

void AntiCheatEngine::PushInputSample(float pitch, float yaw, uint64_t timestamp_ms) {
    if (config_.enableBlackboxDump) {
        BlackboxDumper::Instance().RecordInputSample(pitch, yaw, timestamp_ms);
    }

    if (!config_.enableKinematics) return;

    std::optional<DetectionEvent> ev;
    {
        std::lock_guard<std::mutex> lock(input_mutex_);
        ev = aim_analyzer_.PushSample(pitch, yaw, timestamp_ms);
    }
    if (ev) {
        ProcessDetection(*ev);
    }
}

void AntiCheatEngine::PushViewSample(float x, float y, float z, float pitch, float yaw, uint64_t timestamp_ms) {
    if (!config_.enableKinematics) return;
    auto ev = phantom_monitor_.PushView(x, y, z, pitch, yaw, timestamp_ms);
    if (ev) ProcessDetection(*ev);
}

void AntiCheatEngine::ProcessDetection(const DetectionEvent& event) {
    {
        std::lock_guard<std::mutex> lock(history_mutex_);
        history_.push_back(event);
    }

    threat_score_.fetch_add(event.threat_score);
    Logger::Instance().SecurityAlert(event);

    if (violation_callback_) {
        violation_callback_(event);
    }

    if (config_.enforceBanOnViolation) {
        if (threat_score_.load() >= config_.banScoreThreshold || event.severity == Severity::FATAL_BAN) {
            TriggerBan(event.details, event.type, event.component);
        }
    }
}

void AntiCheatEngine::TriggerBan(const std::string& reason, DetectionType type, const std::string& component) {
    if (is_banned_.exchange(true)) {
        return; // Already banned
    }

    uint32_t finalScore = threat_score_.load();
    Logger::Instance().Error("CRITICAL SECURITY ENFORCEMENT: Device HWID banned. Reason: " + reason +
                             " (Threat Score: " + std::to_string(finalScore) + ")");

    if (config_.enableBlackboxDump) {
        auto snapshot = BlackboxDumper::Instance().CaptureSnapshot(
            component.empty() ? "AntiCheatEngine::Enforcement" : component,
            reason,
            finalScore,
            static_cast<uint32_t>(type)
        );
        last_blackbox_payload_ = BlackboxDumper::Instance().SerializeAndEncrypt(snapshot, config_.secretKey);
        std::string dumpPath = BlackboxDumper::Instance().GenerateDumpFilename();
        BlackboxDumper::Instance().SaveDumpToFile(dumpPath, last_blackbox_payload_);
        Logger::Instance().Info("Blackbox crash/violation diagnostic dump written to: " + dumpPath);
    }

    // Report ban event to backend panel
    panel_client_.SendBanReport(
        DetectionEvent{
            type,
            Severity::FATAL_BAN,
            component.empty() ? "AntiCheatEngine::Enforcement" : component,
            reason,
            static_cast<uint64_t>(time(nullptr)),
            finalScore
        },
        finalScore
    );

    if (ban_callback_) {
        ban_callback_(reason, finalScore);
    }

    // In test harness, bypass UI and process termination
    const char* testEnv = std::getenv("NOESCAPE_TEST_MODE");
    bool inTestMode = (testEnv && (std::strcmp(testEnv, "1") == 0 || strcasecmp(testEnv, "true") == 0));

    if (!inTestMode && config_.showBanUi) {
        SpawnBanScreen(reason, finalScore, component, type);
    }

    if (!inTestMode && config_.terminateProcessOnBan) {
        Logger::Instance().Error("CRITICAL: Terminating target process due to security ban enforcement.");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
#if defined(_WIN32)
        ExitProcess(1);
#else
        _exit(1);
#endif
    }
}

void AntiCheatEngine::SpawnBanScreen(const std::string& reason, 
                                     uint32_t finalScore, 
                                     const std::string& component, 
                                     DetectionType type) {
    std::string uiPath = config_.banUiExecutable;
    if (uiPath.empty()) {
        const char* envPath = std::getenv("NOESCAPE_BAN_UI_PATH");
        if (envPath && std::strlen(envPath) > 0) {
            uiPath = envPath;
        }
    }

    std::vector<std::string> candidatePaths;
    if (!uiPath.empty()) candidatePaths.push_back(uiPath);
    candidatePaths.push_back("/home/COSMOS/NoEscapeAC/tools/noescape_ban_ui.py");
    candidatePaths.push_back("/home/COSMOS/NoEscapeAC/build/noescape_ban_ui");

    std::string resolvedPath;
    for (const auto& cp : candidatePaths) {
#if defined(_WIN32)
        DWORD attr = GetFileAttributesA(cp.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            resolvedPath = cp;
            break;
        }
#else
        if (access(cp.c_str(), X_OK) == 0 || access(cp.c_str(), R_OK) == 0) {
            resolvedPath = cp;
            break;
        }
#endif
    }

    if (resolvedPath.empty()) {
        Logger::Instance().Warn("Vanguard ban screen executable not found in candidate paths.");
        return;
    }

    std::string hwid = panel_client_.GetHwid();
    std::string scoreStr = std::to_string(finalScore);
    std::string typeStr = DetectionEvent::TypeToString(type);
    std::string compStr = component.empty() ? "AntiCheatEngine::Enforcement" : component;

#if defined(_WIN32)
    std::string cmd = "python.exe \"" + resolvedPath + "\" --hwid \"" + hwid +
                      "\" --score " + scoreStr +
                      " --reason \"" + reason +
                      "\" --component \"" + compStr +
                      "\" --type \"" + typeStr + "\"";
    STARTUPINFOA si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, nullptr, &si, &pi);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
#else
    pid_t pid = fork();
    if (pid == 0) {
        // Child: create independent session detached from terminal / game process
        setsid();
        pid_t gpid = fork();
        if (gpid > 0) {
            _exit(0); // Exit intermediate child so grandchild is adopted by init/systemd
        }
        if (gpid == 0) {
            // Grandchild UI process
            // Unset LD_PRELOAD so python child does not load libnoescape.so
            unsetenv("LD_PRELOAD");
            setenv("NOESCAPE_DISABLE_AUTO_INIT", "1", 1);

            uid_t uid = getuid();
            std::string runUserDir = "/run/user/" + std::to_string(uid);
            std::string waylandSocket = runUserDir + "/wayland-0";

            if (!std::getenv("WAYLAND_DISPLAY") && access(waylandSocket.c_str(), F_OK) == 0) {
                setenv("WAYLAND_DISPLAY", "wayland-0", 1);
            }
            if (!std::getenv("XDG_RUNTIME_DIR") && access(runUserDir.c_str(), F_OK) == 0) {
                setenv("XDG_RUNTIME_DIR", runUserDir.c_str(), 1);
            }
            if (!std::getenv("DISPLAY")) {
                setenv("DISPLAY", ":0", 1);
            }
            setenv("QT_QPA_PLATFORM", "wayland;xcb", 0);

            // Redirect stdout and stderr to a log file instead of discarding
            int logFd = open("/tmp/noescape_ban_ui.log", O_CREAT | O_WRONLY | O_APPEND, 0644);
            if (logFd >= 0) {
                dup2(logFd, STDOUT_FILENO);
                dup2(logFd, STDERR_FILENO);
                close(logFd);
            }
            int devNull = open("/dev/null", O_RDONLY);
            if (devNull >= 0) {
                dup2(devNull, STDIN_FILENO);
                close(devNull);
            }

            execlp("python3", "python3", resolvedPath.c_str(),
                   "--hwid", hwid.c_str(),
                   "--score", scoreStr.c_str(),
                   "--reason", reason.c_str(),
                   "--component", compStr.c_str(),
                   "--type", typeStr.c_str(),
                   static_cast<char*>(nullptr));
            _exit(1);
        }
    } else if (pid > 0) {
        waitpid(pid, nullptr, 0);
    }
#endif
    Logger::Instance().Info("Vanguard-style security ban screen spawned successfully.");
}

std::vector<DetectionEvent> AntiCheatEngine::GetDetectionHistory() const {
    std::lock_guard<std::mutex> lock(history_mutex_);
    return history_;
}

void AntiCheatEngine::Start() {
    if (running_.exchange(true)) return;

    thread_pool_.Enqueue([this]() {
        BackgroundLoop();
    });
}

void AntiCheatEngine::Stop() {
    if (!running_.exchange(false)) return;
    thread_pool_.Stop();
}

void AntiCheatEngine::BackgroundLoop() {
    auto lastHeartbeat = std::chrono::steady_clock::now();
    auto lastPanelCheck = std::chrono::steady_clock::now() - std::chrono::seconds(60);

    while (running_.load()) {
        AuditCycle();

        auto now = std::chrono::steady_clock::now();
        if (config_.enableHeartbeat && 
            std::chrono::duration_cast<std::chrono::seconds>(now - lastHeartbeat).count() >= 10) {
            panel_client_.SendHeartbeat(threat_score_.load(), is_banned_.load() ? "BANNED" : "HEALTHY");
            lastHeartbeat = now;
        }

        // Randomized interval (300-1200 ms) so audit windows cannot be predicted
        thread_local std::mt19937 rng{std::random_device{}()};
        std::uniform_int_distribution<int> jitter(300, 1200);
        if (config_.verifyPanelBan &&
            std::chrono::duration_cast<std::chrono::seconds>(now - lastPanelCheck).count() >= 60) {
            VerifyPanelStatus();
            lastPanelCheck = now;
        }

        int waitMs = jitter(rng);
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(waitMs);
        while (running_.load() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

} // namespace noescape::core
