#include "noescape/forensics/process_analyzer.hpp"
#include "noescape/core/obfuscation.hpp"
#include "noescape/core/envutil.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>
#include <ctime>

#if defined(_WIN32)
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#else
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <cstdlib>
#endif

namespace noescape::forensics {

namespace {

std::string ToLower(const std::string& str) {
    std::string s = str;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

} // namespace

ProcessAnalyzer& ProcessAnalyzer::Instance() {
    static ProcessAnalyzer* instance = new ProcessAnalyzer();
    return *instance;
}

bool ProcessAnalyzer::CheckCurrentProcessEnvironment() {
#if defined(_WIN32)
    char buffer[256]{};
    if (GetEnvironmentVariableA("COR_ENABLE_PROFILING", buffer, sizeof(buffer)) > 0) return true;
    if (GetEnvironmentVariableA("ATTACH_DEBUGGER", buffer, sizeof(buffer)) > 0) return true;
    return false;
#else
    auto isSafePreload = [](const char* envVal) {
        if (!envVal || std::strlen(envVal) == 0) return true;
        std::string lowerVal = ToLower(envVal);
        std::istringstream iss(lowerVal);
        std::string token;
        while (std::getline(iss, token, ':')) {
            size_t first = token.find_first_not_of(" \t\r\n");
            if (first == std::string::npos) continue;
            size_t last = token.find_last_not_of(" \t\r\n");
            std::string item = token.substr(first, (last - first + 1));
            if (item.empty()) continue;

            std::string base = core::BaseName(item);
            bool itemSafe = false;
            for (const char* ok : {"libextest.so", "libgamemode", "libmangohud", "libvkbasalt",
                                   "libnoescape", "gameoverlayrenderer", "libsteam"}) {
                if (base.rfind(ok, 0) == 0) { itemSafe = true; break; }
            }
            if (!itemSafe) {
                return false;
            }
        }
        return true;
    };

    const char* ldPreload = std::getenv(NOESCAPE_XOR("LD_PRELOAD"));
    if (ldPreload && !isSafePreload(ldPreload)) {
        return true;
    }
    const char* ldAudit = std::getenv(NOESCAPE_XOR("LD_AUDIT"));
    if (ldAudit && std::strlen(ldAudit) > 0) {
        return true;
    }
    return false;
#endif
}

std::vector<ProcessRecord> ProcessAnalyzer::EnumerateProcesses() {
    std::vector<ProcessRecord> records;

#if defined(_WIN32)
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return records;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessRecord rec;
            rec.pid = pe.th32ProcessID;
            rec.ppid = pe.th32ParentProcessID;

            char nameBuf[MAX_PATH]{};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nameBuf, MAX_PATH, nullptr, nullptr);
            rec.name = nameBuf;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                // Wide APIs: ANSI variants mangle non-ASCII paths (e.g. C:\Users\Yiğit\...) into '?'
                // which made GetFileAttributes fail and flagged every such process as "deleted".
                wchar_t fullPathW[MAX_PATH]{};
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, fullPathW, &size)) {
                    char utf8[MAX_PATH * 4]{};
                    WideCharToMultiByte(CP_UTF8, 0, fullPathW, -1, utf8, sizeof(utf8), nullptr, nullptr);
                    rec.path = utf8;
                    DWORD attrs = GetFileAttributesW(fullPathW);
                    DWORD err = (attrs == INVALID_FILE_ATTRIBUTES) ? GetLastError() : 0;
                    if (attrs == INVALID_FILE_ATTRIBUTES && (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)) {
                        rec.is_deleted_binary = true;
                    }
                }
                CloseHandle(hProc);
            }

            records.push_back(rec);
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);

#else
    DIR* procDir = opendir(NOESCAPE_XOR("/proc"));
    if (!procDir) return records;

    struct dirent* entry = nullptr;
    while ((entry = readdir(procDir)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;

        char* endPtr = nullptr;
        long pid = std::strtol(entry->d_name, &endPtr, 10);
        if (pid <= 0 || *endPtr != '\0') continue;

        ProcessRecord rec;
        rec.pid = static_cast<uint32_t>(pid);

        // Read exe link
        std::string exeLinkPath = std::string("/proc/") + entry->d_name + "/exe";
        char linkBuf[1024]{};
        ssize_t linkLen = readlink(exeLinkPath.c_str(), linkBuf, sizeof(linkBuf) - 1);
        if (linkLen > 0) {
            linkBuf[linkLen] = '\0';
            rec.path = linkBuf;
            if (rec.path.find("(deleted)") != std::string::npos) {
                rec.is_deleted_binary = true;
            }
        }

        // Read comm
        std::string commPath = std::string("/proc/") + entry->d_name + "/comm";
        std::ifstream commFile(commPath);
        if (commFile.is_open()) {
            std::getline(commFile, rec.name);
        }

        // Read cmdline
        std::string cmdlinePath = std::string("/proc/") + entry->d_name + "/cmdline";
        std::ifstream cmdlineFile(cmdlinePath, std::ios::binary);
        if (cmdlineFile.is_open()) {
            std::string cmdContent((std::istreambuf_iterator<char>(cmdlineFile)),
                                    std::istreambuf_iterator<char>());
            for (char& c : cmdContent) {
                if (c == '\0') c = ' ';
            }
            rec.cmdline = cmdContent;
        }

        // Read environ to check for suspicious LD_PRELOAD injection
        std::string envPath = std::string("/proc/") + entry->d_name + "/environ";
        std::ifstream envFile(envPath, std::ios::binary);
        if (envFile.is_open()) {
            std::string envContent((std::istreambuf_iterator<char>(envFile)),
                                   std::istreambuf_iterator<char>());
            size_t startPos = 0;
            while (startPos < envContent.size()) {
                size_t nullPos = envContent.find('\0', startPos);
                if (nullPos == std::string::npos) nullPos = envContent.size();
                std::string entryStr = envContent.substr(startPos, nullPos - startPos);
                startPos = nullPos + 1;

                if (entryStr.rfind("LD_PRELOAD=", 0) == 0 || entryStr.rfind("LD_AUDIT=", 0) == 0) {
                    std::string val = entryStr.substr(entryStr.find('=') + 1);
                    if (!val.empty()) {
                        std::string lowerVal = ToLower(val);
                        bool isSystemLib = (lowerVal.find("libextest.so") != std::string::npos ||
                                            lowerVal.find("libgamemode") != std::string::npos ||
                                            lowerVal.find("libmangohud") != std::string::npos ||
                                            lowerVal.find("libvkbasalt") != std::string::npos ||
                                            lowerVal.find("gameoverlayrenderer") != std::string::npos ||
                                            lowerVal.find("libeatmydata") != std::string::npos ||
                                            lowerVal.find("libfakeroot") != std::string::npos);
                        bool isSuspiciousLocation = (lowerVal.find("/dev/shm") != std::string::npos ||
                                                     lowerVal.find("/tmp") != std::string::npos ||
                                                     lowerVal.find("/var/tmp") != std::string::npos ||
                                                     lowerVal.find("cheat") != std::string::npos ||
                                                     lowerVal.find("inject") != std::string::npos ||
                                                     lowerVal.find("hook") != std::string::npos ||
                                                     lowerVal.find("aimbot") != std::string::npos ||
                                                     lowerVal.find("memhack") != std::string::npos);
                        if (!isSystemLib && isSuspiciousLocation) {
                            rec.has_injected_env = true;
                            break;
                        }
                    }
                }
            }
        }

        records.push_back(rec);
    }

    closedir(procDir);
#endif

    return records;
}

std::vector<core::DetectionEvent> ProcessAnalyzer::AuditProcesses(
    const std::vector<std::string>& blacklist,
    const std::vector<std::string>& cmdline_blacklist
) {
    std::vector<core::DetectionEvent> events;

    // Check self environment tampering
    if (CheckCurrentProcessEnvironment()) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::ENVIRONMENT_TAMPERING;
        ev.severity = core::Severity::FATAL_BAN;
        ev.component = "ProcessAnalyzer::EnvironmentAudit";
        ev.details = "Suspicious dynamic linker injection detected in process environment (LD_PRELOAD / LD_AUDIT)";
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 100;
        events.push_back(ev);
    }

    auto processes = EnumerateProcesses();
    for (const auto& proc : processes) {
        std::string lowerName = ToLower(proc.name);
        std::string lowerPath = ToLower(proc.path);
        std::string lowerCmd = ToLower(proc.cmdline);

        // 1. Blacklisted process name or path
        for (const auto& bl : blacklist) {
            std::string lowerBl = ToLower(bl);
            if (!lowerBl.empty() &&
                (core::NameMatchesEntry(lowerName, lowerBl) ||
                 core::NameMatchesEntry(core::BaseName(lowerPath), lowerBl))) {
                core::DetectionEvent ev;
                ev.type = core::DetectionType::SUSPICIOUS_PROCESS_DETECTED;
                ev.severity = core::Severity::HIGH;
                ev.component = "ProcessAnalyzer::ProcessBlacklist";
                ev.details = "Blacklisted process signature active: PID " + std::to_string(proc.pid) +
                             " (" + proc.name + " -> " + proc.path + ")";
                ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
                ev.threat_score = 80;
                events.push_back(ev);
                break;
            }
        }

        // 2. Suspicious command-line parameters
        for (const auto& cmdBl : cmdline_blacklist) {
            std::string lowerCmdBl = ToLower(cmdBl);
            if (!lowerCmdBl.empty() && lowerCmd.find(lowerCmdBl) != std::string::npos) {
                // Ignore legitimate preload of NoEscape itself or harmless Linux gaming utilities
                if (lowerCmdBl.find("ld_preload") != std::string::npos &&
                    (lowerCmd.find("noescape") != std::string::npos ||
                     lowerCmd.find("libmangohud") != std::string::npos ||
                     lowerCmd.find("libgamemode") != std::string::npos ||
                     lowerCmd.find("libvkbasalt") != std::string::npos)) {
                    continue;
                }

                core::DetectionEvent ev;
                ev.type = core::DetectionType::SUSPICIOUS_PROCESS_DETECTED;
                ev.severity = core::Severity::MEDIUM;
                ev.component = "ProcessAnalyzer::CmdlineInspection";
                ev.details = "Suspicious commandline injection argument found in PID " +
                             std::to_string(proc.pid) + ": matched '" + cmdBl + "'";
                ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
                ev.threat_score = 40;
                events.push_back(ev);
                break;
            }
        }

        // 3. Executed binary deleted from disk (Anti-Forensics trick)
        // A binary deleted by a package upgrade (or runc/Chrome re-exec via memfd) is routine; only
        // executables running from volatile locations are a meaningful anti-forensics signal.
        const bool volatileExe = lowerPath.rfind("/dev/shm", 0) == 0 || lowerPath.rfind("/tmp", 0) == 0 ||
                                 lowerPath.rfind("/var/tmp", 0) == 0 || lowerPath.rfind("/memfd:", 0) == 0 ||
                                 lowerPath.find("\\temp\\") != std::string::npos;
        const bool benignExe = lowerPath.find("runc") != std::string::npos ||
                               lowerPath.find("memfd:libffi") != std::string::npos ||
                               lowerPath.find("memfd:chrome") != std::string::npos ||
                               lowerPath.find("memfd:snapd") != std::string::npos ||
                               lowerPath.find("memfd:sbx") != std::string::npos;
        if (proc.is_deleted_binary && volatileExe && !benignExe) {
            core::DetectionEvent ev;
            ev.type = core::DetectionType::FORENSICS_ARTIFACT_DETECTED;
            ev.severity = core::Severity::HIGH;
            ev.component = "ProcessAnalyzer::AntiForensics";
            ev.details = "Process executing unlinked memory-ghosted/deleted executable: PID " +
                         std::to_string(proc.pid) + " (" + proc.path + ")";
            ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
            ev.threat_score = 50;
            events.push_back(ev);
        }

        // 4. Injected environment variables (ignore standard whitelisted platforms)
        if (proc.has_injected_env) {
            if (lowerName.find("steam") == std::string::npos &&
                lowerName.find("discord") == std::string::npos &&
                lowerPath.find("steam") == std::string::npos &&
                lowerPath.find("discord") == std::string::npos) {
                core::DetectionEvent ev;
                ev.type = core::DetectionType::ENVIRONMENT_TAMPERING;
                ev.severity = core::Severity::HIGH;
                ev.component = "ProcessAnalyzer::EnvironmentInjection";
                ev.details = "Process spawned with dangerous injection environment (LD_PRELOAD): PID " +
                             std::to_string(proc.pid) + " (" + proc.name + ")";
                ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
                ev.threat_score = 70;
                events.push_back(ev);
            }
        }
    }

    return events;
}

} // namespace noescape::forensics
