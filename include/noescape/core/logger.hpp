#pragma once

#include <string>
#include <mutex>
#include <functional>
#include <iostream>
#include "noescape/core/types.hpp"

namespace noescape::core {

class Logger {
public:
    using AlertCallback = std::function<void(const DetectionEvent&)>;

    static Logger& Instance();

    void Info(const std::string& msg);
    void Warn(const std::string& msg);
    void Error(const std::string& msg);
    void SecurityAlert(const DetectionEvent& event);

    void SetAlertCallback(AlertCallback cb);
    void SetConsoleOutput(bool enabled);

private:
    Logger() = default;
    std::mutex mutex_;
    AlertCallback alert_cb_;
    bool console_output_{true};

    void PrintFormatted(const char* prefix, const char* colorCode, const std::string& msg);
};

} // namespace noescape::core
