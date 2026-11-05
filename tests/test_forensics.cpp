#include "tests/test_framework.hpp"
#include "noescape/forensics/process_analyzer.hpp"
#include "noescape/forensics/artifact_analyzer.hpp"

#if !defined(_WIN32)
#include <unistd.h>
#endif

using namespace noescape::forensics;
using namespace noescape::core;

TEST(Forensics, ProcessEnumeration) {
    auto procs = ProcessAnalyzer::Instance().EnumerateProcesses();
    ASSERT_FALSE(procs.empty());

#if !defined(_WIN32)
    uint32_t myPid = static_cast<uint32_t>(getpid());
    bool foundSelf = false;
    for (const auto& p : procs) {
        if (p.pid == myPid) {
            foundSelf = true;
            break;
        }
    }
    ASSERT_TRUE(foundSelf);
#endif
}

TEST(Forensics, ProcessBlacklistAudit) {
    std::vector<std::string> blacklist = {"non_existent_cheat_daemon_xyz", "vape", "cheatengine"};
    std::vector<std::string> cmdlineBlacklist = {"--inject-cheat-payload-mock"};

    auto events = ProcessAnalyzer::Instance().AuditProcesses(blacklist, cmdlineBlacklist);
    // On clean testing system, blacklisted cheat processes should not be running
    for (const auto& ev : events) {
        if (ev.type == DetectionType::SUSPICIOUS_PROCESS_DETECTED) {
            ASSERT_NE(ev.details.find("non_existent_cheat_daemon_xyz"), std::string::npos);
        }
        // Verify that benign system processes with libextest.so are NOT flagged as environment tampering
        ASSERT_NE(ev.type, DetectionType::ENVIRONMENT_TAMPERING);
    }
}

TEST(Forensics, ArtifactAnalyzer) {
    std::vector<std::string> fakeArtifacts = {"impossible_cheat_file_xyz123.bin"};
    auto fsArtifacts = ArtifactAnalyzer::Instance().ScanFilesystemArtifacts(fakeArtifacts);
    ASSERT_TRUE(fsArtifacts.empty());

    std::vector<std::string> fakeDrivers = {"impossible_driver_xyz.sys"};
    auto drvArtifacts = ArtifactAnalyzer::Instance().ScanKernelDrivers(fakeDrivers);
    ASSERT_TRUE(drvArtifacts.empty());
}
