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
#include "noescape/core/envutil.hpp"

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

#if !defined(_WIN32)
extern "C" char** environ;
#endif

namespace noescape::core {

namespace {

uint64_t GetSteadyNowMs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    );
}

} // namespace

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

    if (config_.secretKey == EngineConfig().secretKey) {
        Logger::Instance().Warn("Using the built-in default secret key: panel/blackbox signatures are forgeable. "
                                "Configure a unique per-deployment key.");
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
    if (stop_requested_.load(std::memory_order_acquire)) return cycleEvents;

    // Cache memory maps snapshot for the entire audit cycle to eliminate 25+ redundant file reads
    memory::MemoryScanner::Instance().RefreshCache();
    struct AuditCycleCacheGuard {
        ~AuditCycleCacheGuard() {
            memory::MemoryScanner::Instance().ClearCache();
        }
    } cycleCacheGuard;

    UpdateAuditHeartbeat();

    // 1. Anti-Debug Audit
    if (config_.enableAntiDebug) {
        auto adEvents = security::AntiDebug::PerformAudit(config_.blacklistedProcesses);
        cycleEvents.insert(cycleEvents.end(), adEvents.begin(), adEvents.end());
    }
    if (stop_requested_.load(std::memory_order_acquire)) return cycleEvents;
    UpdateAuditHeartbeat();

    // 2. Self-Integrity Check
    if (config_.enableIntegrityScan) {
        auto integEvent = security::IntegrityChecker::Instance().VerifyIntegrity();
        if (integEvent) {
            cycleEvents.push_back(*integEvent);
        }
    }
    if (stop_requested_.load(std::memory_order_acquire)) return cycleEvents;
    UpdateAuditHeartbeat();

    // 3. Timing / Speedhack Check
    if (config_.enableSpeedhackDetection) {
        auto speedEvent = security::TimingIntegrity::Instance().CheckSpeedhack();
        if (speedEvent) {
            cycleEvents.push_back(*speedEvent);
        }
    }
    if (stop_requested_.load(std::memory_order_acquire)) return cycleEvents;
    UpdateAuditHeartbeat();

    // 4. Memory Scanner (Unbacked executable memory + signature scan)
    if (config_.enableMemoryScan) {
        auto memEvents = memory::MemoryScanner::Instance().PerformAudit(default_signatures_);
        cycleEvents.insert(cycleEvents.end(), memEvents.begin(), memEvents.end());
    }
    if (stop_requested_.load(std::memory_order_acquire)) return cycleEvents;
    UpdateAuditHeartbeat();

    // 4b. Tripwire (canary) memory: detects external memory writes
    // Soft-dirty reset walks every PTE of the process, so run it at a low cadence (every 5th cycle)
    if (config_.enableMemoryScan && (audit_cycle_counter_.fetch_add(1) % 5 == 0)) {
        auto canaryEvents = memory::CanaryMonitor::Instance().Check();
        cycleEvents.insert(cycleEvents.end(), canaryEvents.begin(), canaryEvents.end());
    }
    if (stop_requested_.load(std::memory_order_acquire)) return cycleEvents;
    UpdateAuditHeartbeat();

    // 5. Inline Unhooker Audit
    if (config_.enableUnhooker) {
        auto hookEvents = memory::Unhooker::Instance().AuditSystemHooks();
        cycleEvents.insert(cycleEvents.end(), hookEvents.begin(), hookEvents.end());
    }
    if (stop_requested_.load(std::memory_order_acquire)) return cycleEvents;
    UpdateAuditHeartbeat();

    // 6. Forensics Process & Environment Audit
    if (config_.enableForensics) {
        std::vector<std::string> cmdlineBlacklist = {"--inject", "gdb -p", "frida", "inject.so", "ld_preload="};
        auto procEvents = forensics::ProcessAnalyzer::Instance().AuditProcesses(
            config_.blacklistedProcesses,
            cmdlineBlacklist
        );
        cycleEvents.insert(cycleEvents.end(), procEvents.begin(), procEvents.end());
        if (stop_requested_.load(std::memory_order_acquire)) return cycleEvents;

        std::vector<std::string> driverBlacklist = {"dbk64", "winring0", "ksdumper", "leechcore"};
        auto artEvents = forensics::ArtifactAnalyzer::Instance().PerformAudit(
            config_.blacklistedArtifacts,
            driverBlacklist
        );
        cycleEvents.insert(cycleEvents.end(), artEvents.begin(), artEvents.end());
    }
    if (stop_requested_.load(std::memory_order_acquire)) return cycleEvents;
    UpdateAuditHeartbeat();

    // 7. DMA Hardware & Bus Latency Check
    // The bus-latency probe flushes caches and is comparatively heavy: at most once per 10 s
    if (config_.enableDmaDetection &&
        (GetSteadyNowMs() - last_dma_audit_ms_.load(std::memory_order_acquire) >= 10000)) {
        last_dma_audit_ms_.store(GetSteadyNowMs(), std::memory_order_release);
        auto dmaEvents = dma::DmaDetector::Instance().PerformAudit();
        cycleEvents.insert(cycleEvents.end(), dmaEvents.begin(), dmaEvents.end());
    }
    if (stop_requested_.load(std::memory_order_acquire)) return cycleEvents;
    UpdateAuditHeartbeat();

    // 8. Overlay & ESP/Wallhack Detector (Rendering hooks & fake window scanner)
    if (config_.enableOverlayDetection) {
        auto overlayEvents = overlay::OverlayDetector::Instance().PerformAudit();
        cycleEvents.insert(cycleEvents.end(), overlayEvents.begin(), overlayEvents.end());
    }
    if (stop_requested_.load(std::memory_order_acquire)) return cycleEvents;
    UpdateAuditHeartbeat();

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

void AntiCheatEngine::ResetInput() {
    std::lock_guard<std::mutex> lock(input_mutex_);
    aim_analyzer_.Reset();
}

void AntiCheatEngine::PushViewSample(float x, float y, float z, float pitch, float yaw, uint64_t timestamp_ms) {
    if (!config_.enableKinematics) return;
    auto ev = phantom_monitor_.PushView(x, y, z, pitch, yaw, timestamp_ms);
    if (ev) ProcessDetection(*ev);
}

namespace {
// Normalises an event into a stable identity: addresses / counters after the first "0x" are dropped
// so the same persistent condition is not re-scored on every audit cycle.
std::string DetectionKey(const DetectionEvent& e) {
    std::string d = e.details;
    size_t p = d.find("0x");
    if (p != std::string::npos) d.resize(p);
    return std::to_string(static_cast<uint32_t>(e.type)) + "|" + e.component + "|" + d;
}
} // namespace

void AntiCheatEngine::ProcessDetection(const DetectionEvent& event) {
    bool firstSighting = true;
    {
        std::lock_guard<std::mutex> lock(history_mutex_);
        firstSighting = scored_keys_.insert(DetectionKey(event)).second;
        if (firstSighting) history_.push_back(event);
    }

    // A persistent condition is scored once; repeats must not snowball into a ban.
    // Fatal events still enforce on every sighting.
    if (firstSighting) {
        threat_score_.fetch_add(event.threat_score);
        Logger::Instance().SecurityAlert(event);
        std::function<void(const DetectionEvent&)> cb;
        { std::lock_guard<std::mutex> lock(history_mutex_); cb = violation_callback_; }
        if (cb) cb(event);
    }

    if (config_.enforceBanOnViolation) {
        uint32_t cur = threat_score_.load();
        if ((cur >= config_.banScoreThreshold && cur > 0) || event.severity == Severity::FATAL_BAN) {
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
    bool inTestMode = (testEnv && EnvFlagTrue(testEnv));

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
    candidatePaths.push_back("./noescape_ban_ui");
    candidatePaths.push_back("./tools/noescape_ban_ui.py");

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
        Logger::Instance().Warn("Security ban screen executable not found in candidate paths.");
        return;
    }

    std::string hwid = panel_client_.GetHwid();
    std::string scoreStr = std::to_string(finalScore);
    std::string typeStr = DetectionEvent::TypeToString(type);
    std::string compStr = component.empty() ? "AntiCheatEngine::Enforcement" : component;

#if defined(_WIN32)
    // Strip characters that could break out of a quoted argument (argument injection)
    auto sanitize = [](std::string v) {
        for (char& c : v) if (c == '"' || c == '\\' || c == '%' || c < 0x20) c = '\'';
        return v;
    };
    std::string cmd = "python.exe \"" + sanitize(resolvedPath) + "\" --hwid \"" + sanitize(hwid) +
                      "\" --score " + scoreStr +
                      " --reason \"" + sanitize(reason) +
                      "\" --component \"" + sanitize(compStr) +
                      "\" --type \"" + sanitize(typeStr) + "\"";
    STARTUPINFOA si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, nullptr, &si, &pi);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
#else
    // Everything that allocates (strings, environment, argv) is prepared BEFORE fork():
    // in a multithreaded process the child may only call async-signal-safe functions.
    std::vector<std::string> envStore;
    for (char** e = environ; e && *e; ++e) {
        if (std::strncmp(*e, "LD_PRELOAD=", 11) == 0) continue; // never load libnoescape into the UI
        if (std::strncmp(*e, "NOESCAPE_DISABLE_AUTO_INIT=", 27) == 0) continue;
        envStore.emplace_back(*e);
    }
    envStore.emplace_back("NOESCAPE_DISABLE_AUTO_INIT=1");
    envStore.emplace_back("NOESCAPE_TEST_MODE=1"); // lets the UI process honour the opt-out
    std::string runUserDir = "/run/user/" + std::to_string(getuid());
    if (!std::getenv("WAYLAND_DISPLAY") && access((runUserDir + "/wayland-0").c_str(), F_OK) == 0)
        envStore.emplace_back("WAYLAND_DISPLAY=wayland-0");
    if (!std::getenv("XDG_RUNTIME_DIR") && access(runUserDir.c_str(), F_OK) == 0)
        envStore.emplace_back("XDG_RUNTIME_DIR=" + runUserDir);
    if (!std::getenv("DISPLAY")) envStore.emplace_back("DISPLAY=:0");
    if (!std::getenv("QT_QPA_PLATFORM")) envStore.emplace_back("QT_QPA_PLATFORM=wayland;xcb");

    std::vector<char*> envp;
    for (auto& e : envStore) envp.push_back(e.data());
    envp.push_back(nullptr);

    std::vector<std::string> argStore = {"python3", resolvedPath, "--hwid", hwid, "--score", scoreStr,
                                         "--reason", reason, "--component", compStr, "--type", typeStr};
    std::vector<char*> argv;
    for (auto& a : argStore) argv.push_back(a.data());
    argv.push_back(nullptr);
    const char* logPath = "/tmp/noescape_ban_ui.log";

    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        pid_t gpid = fork();
        if (gpid > 0) {
            _exit(0); // intermediate child exits so the grandchild is adopted by init
        }
        if (gpid == 0) {
            int logFd = open(logPath, O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW, 0600);
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
            execvpe("python3", argv.data(), envp.data());
            _exit(1);
        }
        _exit(1);
    } else if (pid > 0) {
        waitpid(pid, nullptr, 0);
    }
#endif
    Logger::Instance().Info("Security ban screen spawned successfully.");
}

std::vector<DetectionEvent> AntiCheatEngine::GetDetectionHistory() const {
    std::lock_guard<std::mutex> lock(history_mutex_);
    return history_;
}

void AntiCheatEngine::Start() {
    if (running_.exchange(true)) return;
    stop_requested_.store(false, std::memory_order_release);

    last_audit_heartbeat_ms_.store(GetSteadyNowMs(), std::memory_order_release);

    // Long memory scans report progress so a legitimately slow scan is not mistaken for a freeze
    memory::MemoryScanner::Instance().SetProgressCallback([this]() { UpdateAuditHeartbeat(); });

    thread_pool_.Enqueue([this]() {
        BackgroundLoop();
    });

    // Network I/O (DNS, connect, recv) must never stall the audit loop or the watchdog
    if (config_.enableHeartbeat || config_.verifyPanelBan) {
        network_thread_ = std::thread([this]() { NetworkLoop(); });
    }

    watchdog_thread_ = std::thread([this]() {
        WatchdogLoop();
    });
}

void AntiCheatEngine::Stop() {
    if (!running_.exchange(false)) return;
    stop_requested_.store(true, std::memory_order_release);
    freeze_background_loop_for_testing_.store(false, std::memory_order_release);
    if (watchdog_thread_.joinable()) {
        watchdog_thread_.join();
    }
    if (network_thread_.joinable()) {
        network_thread_.join();
    }
    thread_pool_.Stop();
    memory::MemoryScanner::Instance().SetProgressCallback(nullptr);
}

void AntiCheatEngine::NetworkLoop() {
    auto lastHeartbeat = std::chrono::steady_clock::now();
    auto lastPanelCheck = std::chrono::steady_clock::now() - std::chrono::seconds(60);
    while (running_.load(std::memory_order_acquire)) {
        auto now = std::chrono::steady_clock::now();
        try {
            if (config_.enableHeartbeat &&
                std::chrono::duration_cast<std::chrono::seconds>(now - lastHeartbeat).count() >= 10) {
                panel_client_.SendHeartbeat(threat_score_.load(), is_banned_.load() ? "BANNED" : "HEALTHY");
                lastHeartbeat = std::chrono::steady_clock::now();
            }
            if (config_.verifyPanelBan &&
                std::chrono::duration_cast<std::chrono::seconds>(now - lastPanelCheck).count() >= 60) {
                VerifyPanelStatus();
                lastPanelCheck = std::chrono::steady_clock::now();
            }
        } catch (...) {
            // Network failures must never take the host process down
        }
        for (int i = 0; i < 50 && running_.load(std::memory_order_acquire); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
}

void AntiCheatEngine::BackgroundLoop() {
    while (running_.load(std::memory_order_acquire)) {
        while (freeze_background_loop_for_testing_.load(std::memory_order_acquire) &&
               running_.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (!running_.load(std::memory_order_acquire)) break;

        UpdateAuditHeartbeat();
        try {
            AuditCycle();
        } catch (const std::exception& ex) {
            Logger::Instance().Error(std::string("Audit cycle aborted by exception: ") + ex.what());
        } catch (...) {
            Logger::Instance().Error("Audit cycle aborted by unknown exception");
        }
        UpdateAuditHeartbeat();

        // Randomized interval (300-1200 ms) so audit windows cannot be predicted
        thread_local std::mt19937 rng{std::random_device{}()};
        std::uniform_int_distribution<int> jitter(300, 1200);
        int waitMs = jitter(rng);
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(waitMs);
        while (running_.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline) {
            if (freeze_background_loop_for_testing_.load(std::memory_order_acquire)) {
                break;
            }
            UpdateAuditHeartbeat();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

void AntiCheatEngine::UpdateAuditHeartbeat() {
    if (!freeze_background_loop_for_testing_.load(std::memory_order_acquire)) {
        last_audit_heartbeat_ms_.store(GetSteadyNowMs(), std::memory_order_release);
    }
}

void AntiCheatEngine::WatchdogLoop() {
    while (running_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load(std::memory_order_acquire)) break;
        if (is_banned_.load(std::memory_order_acquire)) break;

        uint64_t now = GetSteadyNowMs();
        uint64_t last = last_audit_heartbeat_ms_.load(std::memory_order_acquire);
        if (last > 0 && now > last && (now - last) > 3000) {
            Logger::Instance().Error("Watchdog detected thread freeze or suspension (> 3000ms heartbeat deadline missed). Flagging tampering.");
            DetectionEvent ev;
            ev.type = DetectionType::HEARTBEAT_TAMPERING;
            ev.severity = Severity::FATAL_BAN;
            ev.component = "AntiCheatEngine::Watchdog";
            ev.details = "Watchdog heartbeat timeout: background audit loop frozen or suspended (> 3000ms)";
            ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
            ev.threat_score = 100;
            ProcessDetection(ev);
            if (!is_banned_.load(std::memory_order_acquire)) {
                TriggerBan(ev.details, ev.type, ev.component);
            }
            break;
        }
    }
}

} // namespace noescape::core
