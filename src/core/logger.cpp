#include "noescape/core/logger.hpp"
#include <chrono>
#include <iomanip>
#include <sstream>

namespace noescape::core {

Logger& Logger::Instance() {
    static Logger* instance = new Logger();
    return *instance;
}

void Logger::SetAlertCallback(AlertCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    alert_cb_ = std::move(cb);
}

void Logger::SetConsoleOutput(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    console_output_ = enabled;
}

void Logger::PrintFormatted(const char* prefix, const char* colorCode, const std::string& msg) {
    if (!console_output_) return;

    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm bt{};
#if defined(_WIN32)
    localtime_s(&bt, &in_time_t);
#else
    localtime_r(&in_time_t, &bt);
#endif

    std::ostringstream ss;
    ss << "\033[90m[" << std::put_time(&bt, "%H:%M:%S") << '.'
       << std::setfill('0') << std::setw(3) << ms.count() << "]\033[0m "
       << colorCode << "[" << prefix << "]\033[0m " << msg << "\n";

    std::cout << ss.str() << std::flush;
}

void Logger::Info(const std::string& msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    PrintFormatted("INFO", "\033[36m", msg);
}

void Logger::Warn(const std::string& msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    PrintFormatted("WARN", "\033[33m", msg);
}

void Logger::Error(const std::string& msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    PrintFormatted("ERROR", "\033[31m", msg);
}

namespace {
std::string StripControl(const std::string& in) {
    std::string out = in;
    for (char& c : out) {
        unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7f) c = '?'; // blocks terminal escape / log-line injection
    }
    return out;
}
} // namespace

void Logger::SecurityAlert(const DetectionEvent& event) {
    AlertCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream ss;
        ss << "\033[1;31m[SECURITY ALERT: " << DetectionEvent::TypeToString(event.type)
           << " | SEVERITY: " << DetectionEvent::SeverityToString(event.severity)
           << " | SCORE: +" << event.threat_score << "]\033[0m "
           << "Component: " << StripControl(event.component) << " - " << StripControl(event.details);
        PrintFormatted("ALERT", "\033[41;37m", ss.str());
        cb = alert_cb_;
    }

    if (cb) {
        cb(event);
    }
}

} // namespace noescape::core
