#if !defined(_WIN32)

#include "noescape/security/anti_debug.hpp"
#include "noescape/core/obfuscation.hpp"
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <climits>

namespace noescape::security {

namespace {

std::string ToLower(const std::string& str) {
    std::string s = str;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

} // namespace

bool AntiDebug::IsDebuggerAttached() {
    int tracerPid = 0;
    if (CheckTracerPid(tracerPid) && tracerPid > 0) {
        return true;
    }
    if (CheckWchanWait()) {
        return true;
    }
    return false;
}

bool AntiDebug::CheckTracerPid(int& outPid) {
    outPid = 0;
    std::ifstream statusFile(NOESCAPE_XOR("/proc/self/status"));
    if (!statusFile.is_open()) return false;

    std::string line;
    std::string targetPrefix = NOESCAPE_XOR("TracerPid:");
    while (std::getline(statusFile, line)) {
        if (line.compare(0, targetPrefix.length(), targetPrefix) == 0) {
            std::istringstream iss(line.substr(targetPrefix.length()));
            iss >> outPid;
            return outPid != 0;
        }
    }
    return false;
}

bool AntiDebug::CheckWchanWait() {
    std::ifstream wchanFile(NOESCAPE_XOR("/proc/self/wchan"));
    if (!wchanFile.is_open()) return false;

    std::string wchan;
    if (std::getline(wchanFile, wchan)) {
        std::string lower = ToLower(wchan);
        if (lower.find("ptrace") != std::string::npos ||
            lower.find("sys_ptrace") != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool AntiDebug::CheckHardwareBreakpoints() {
    // Check all threads in /proc/self/task/ for tracer attachment
    DIR* taskDir = opendir(NOESCAPE_XOR("/proc/self/task"));
    if (taskDir) {
        struct dirent* entry = nullptr;
        while ((entry = readdir(taskDir)) != nullptr) {
            if (entry->d_type != DT_DIR) continue;
            std::string tidStr = entry->d_name;
            if (tidStr.empty() || !std::isdigit(tidStr[0])) continue;

            std::string statusPath = std::string("/proc/self/task/") + tidStr + "/status";
            std::ifstream statusFile(statusPath);
            if (!statusFile.is_open()) continue;

            std::string line;
            std::string targetPrefix = NOESCAPE_XOR("TracerPid:");
            while (std::getline(statusFile, line)) {
                if (line.compare(0, targetPrefix.length(), targetPrefix) == 0) {
                    std::istringstream iss(line.substr(targetPrefix.length()));
                    int tracerPid = 0;
                    if (iss >> tracerPid && tracerPid != 0) {
                        closedir(taskDir);
                        return true;
                    }
                    break;
                }
            }
        }
        closedir(taskDir);
    }

    return false;
}

bool AntiDebug::HideCurrentThread() {
    // PR_SET_DUMPABLE=0 disables ptrace attaching by non-root users and suppresses core dumps.
    // However, on Linux setting PR_SET_DUMPABLE=0 changes ownership of /proc/self/* to root,
    // which prevents JIT runtimes (such as Java JVM / HotSpot) from accessing /proc/self/maps
    // and causes fatal JVM aborts. For JVM environments, only restrict ptrace via PR_SET_PTRACER.
    bool isJvmRuntime = false;
    char exeBuf[PATH_MAX]{};
    ssize_t len = readlink("/proc/self/exe", exeBuf, sizeof(exeBuf) - 1);
    if (len > 0) {
        exeBuf[len] = '\0';
        std::string exeStr(exeBuf);
        std::transform(exeStr.begin(), exeStr.end(), exeStr.begin(), ::tolower);
        if (exeStr.find("java") != std::string::npos ||
            exeStr.find("mono") != std::string::npos ||
            exeStr.find("node") != std::string::npos ||
            exeStr.find("dotnet") != std::string::npos) {
            isJvmRuntime = true;
        }
    }

    int res1 = 0;
    if (!isJvmRuntime) {
        res1 = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
#ifdef PR_SET_PTRACER
    int res2 = prctl(PR_SET_PTRACER, 0, 0, 0, 0);
    return (res1 == 0 && res2 == 0);
#else
    return (res1 == 0);
#endif
}

bool AntiDebug::CheckKnownDebuggerProcesses(const std::vector<std::string>& blacklist, std::string& detectedName) {
    DIR* procDir = opendir("/proc");
    if (!procDir) return false;

    struct dirent* entry = nullptr;
    while ((entry = readdir(procDir)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;

        // Check if directory name is numeric (PID)
        char* endPtr = nullptr;
        long pid = strtol(entry->d_name, &endPtr, 10);
        if (pid <= 0 || *endPtr != '\0') continue;

        // Ignore our own PID
        if (pid == getpid()) continue;

        std::string commPath = std::string("/proc/") + entry->d_name + "/comm";
        std::ifstream commFile(commPath);
        if (!commFile.is_open()) continue;

        std::string comm;
        if (std::getline(commFile, comm)) {
            std::string lowerComm = ToLower(comm);
            for (const auto& target : blacklist) {
                if (lowerComm.find(ToLower(target)) != std::string::npos) {
                    detectedName = comm;
                    closedir(procDir);
                    return true;
                }
            }
        }
    }

    closedir(procDir);
    return false;
}

std::vector<core::DetectionEvent> AntiDebug::PerformAudit(const std::vector<std::string>& blacklist) {
    std::vector<core::DetectionEvent> events;

    int tracerPid = 0;
    if (CheckTracerPid(tracerPid) && tracerPid > 0) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::ANTI_DEBUG_TRACER;
        ev.severity = core::Severity::FATAL_BAN;
        ev.component = "AntiDebug::LinuxTracer";
        ev.details = "Active TracerPid detected attached to process: PID " + std::to_string(tracerPid);
        ev.timestamp = static_cast<uint64_t>(time(nullptr));
        ev.threat_score = 100;
        events.push_back(ev);
    }

    if (CheckWchanWait()) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::ANTI_DEBUG_TRACER;
        ev.severity = core::Severity::CRITICAL;
        ev.component = "AntiDebug::LinuxWchan";
        ev.details = "Process is waiting in ptrace_stop state via kernel wchan";
        ev.timestamp = static_cast<uint64_t>(time(nullptr));
        ev.threat_score = 80;
        events.push_back(ev);
    }

    std::string detectedTool;
    if (CheckKnownDebuggerProcesses(blacklist, detectedTool)) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::ANTI_DEBUG_TOOL;
        ev.severity = core::Severity::HIGH;
        ev.component = "AntiDebug::ProcessScanner";
        ev.details = "Debugger or analysis tool process running in background: " + detectedTool;
        ev.timestamp = static_cast<uint64_t>(time(nullptr));
        ev.threat_score = 60;
        events.push_back(ev);
    }

    return events;
}

} // namespace noescape::security

#endif
