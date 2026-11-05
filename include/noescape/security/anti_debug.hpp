#pragma once

#include <vector>
#include <string>
#include "noescape/core/types.hpp"

namespace noescape::security {

class AntiDebug {
public:
    // Core anti-debugging routines
    static bool IsDebuggerAttached();
    static bool CheckHardwareBreakpoints();
    static bool CheckTracerPid(int& outPid);
    static bool CheckWchanWait();
    static bool HideCurrentThread();
    static bool CheckKnownDebuggerProcesses(const std::vector<std::string>& blacklist, std::string& detectedName);

    // Runs all checks and returns any generated events
    static std::vector<core::DetectionEvent> PerformAudit(const std::vector<std::string>& blacklist);
};

} // namespace noescape::security
