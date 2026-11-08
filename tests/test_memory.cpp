#include "tests/test_framework.hpp"
#include "noescape/memory/memory_scanner.hpp"
#include "noescape/memory/unhooker.hpp"
#include <vector>
#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <dlfcn.h>
#endif

using namespace noescape::memory;
using namespace noescape::core;

TEST(Memory, QueryMemoryRegions) {
    auto regions = MemoryScanner::Instance().QueryMemoryRegions();
    ASSERT_FALSE(regions.empty());

    bool foundExecutable = false;
    for (const auto& r : regions) {
        ASSERT_GT(r.size, 0);
        ASSERT_GT(r.end, r.start);
        if (r.executable) {
            foundExecutable = true;
        }
    }
    ASSERT_TRUE(foundExecutable);
}

TEST(Memory, UnhookerInspection) {
    // 1. Clean function prologue: push rbp; mov rbp, rsp; sub rsp, 20h
    uint8_t cleanFunc[16] = {0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20};
    auto cleanRes = Unhooker::Instance().InspectFunction("CleanFunc", cleanFunc);
    ASSERT_FALSE(cleanRes.has_value());

    // 2. Hooked function with JMP rel32 (0xE9 0x10 0x00 0x00 0x00)
    uint8_t jmpHook[16] = {0xE9, 0x10, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90};
    auto jmpRes = Unhooker::Instance().InspectFunction("HookedJmp", jmpHook);
    ASSERT_TRUE(jmpRes.has_value());
    ASSERT_EQ(jmpRes->hook_type, "JMP_REL32 (0xE9)");

    // 3. Software Breakpoint (0xCC)
    uint8_t bpFunc[16] = {0xCC, 0x48, 0x89, 0xE5};
    auto bpRes = Unhooker::Instance().InspectFunction("BpFunc", bpFunc);
    ASSERT_TRUE(bpRes.has_value());
    ASSERT_EQ(bpRes->hook_type, "SOFTWARE_BREAKPOINT (0xCC)");

    // 4. MOV RAX, imm64; JMP RAX (48 B8 ... FF E0)
    uint8_t movJmpFunc[16] = {
        0x48, 0xB8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xFF, 0xE0
    };
    auto movJmpRes = Unhooker::Instance().InspectFunction("MovJmpFunc", movJmpFunc);
    ASSERT_TRUE(movJmpRes.has_value());
    ASSERT_EQ(movJmpRes->hook_type, "MOV_RAX_JMP_RAX (0x48 0xB8 ... 0xFF 0xE0)");
    ASSERT_EQ(movJmpRes->target_destination, 0x8877665544332211ULL);

    // 5. Short jump JMP rel8 (0xEB 0x10)
    uint8_t shortJmpFunc[16] = {0xEB, 0x10, 0x90, 0x90};
    auto shortJmpRes = Unhooker::Instance().InspectFunction("ShortJmpFunc", shortJmpFunc);
    ASSERT_TRUE(shortJmpRes.has_value());
    ASSERT_EQ(shortJmpRes->hook_type, "JMP_REL8 (0xEB)");

    // 6. MinHook 64-bit jump (MOV R10, imm64; JMP R10)
    uint8_t minHookFunc[16] = {
        0x49, 0xBA, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x41, 0xFF, 0xE2
    };
    auto minHookRes = Unhooker::Instance().InspectFunction("MinHookFunc", minHookFunc);
    ASSERT_TRUE(minHookRes.has_value());
    ASSERT_EQ(minHookRes->hook_type, "MOV_R10_JMP_R10 (0x49 0xBA ... 0x41 0xFF 0xE2)");
    ASSERT_EQ(minHookRes->target_destination, 0x8877665544332211ULL);

    // 7. Push-Ret x64 Jump (68 [low32] C7 44 24 04 [high32] C3)
    uint8_t pushRetFunc[16] = {
        0x68, 0x11, 0x22, 0x33, 0x44, 0xC7, 0x44, 0x24, 0x04, 0x55, 0x66, 0x77, 0x88, 0xC3
    };
    auto pushRetRes = Unhooker::Instance().InspectFunction("PushRetFunc", pushRetFunc);
    ASSERT_TRUE(pushRetRes.has_value());
    ASSERT_EQ(pushRetRes->hook_type, "PUSH_RET_X64 (0x68 ... 0xC3)");
    ASSERT_EQ(pushRetRes->target_destination, 0x8877665544332211ULL);

    // 8. Live system hooks audit on current process (clean process should not trigger critical hooks)
    auto systemEvents = Unhooker::Instance().AuditSystemHooks();
    (void)systemEvents; // Verify execution does not crash
}

TEST(Memory, UnhookerRestoration) {
#if defined(_WIN32)
    uint8_t* mockPage = static_cast<uint8_t*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    ASSERT_TRUE(mockPage != nullptr);
#else
    uint8_t* mockPage = static_cast<uint8_t*>(mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    ASSERT_TRUE(mockPage != MAP_FAILED);
#endif

    // Setup initial hooked code: JMP rel32
    mockPage[0] = 0xE9; mockPage[1] = 0x20; mockPage[2] = 0x00; mockPage[3] = 0x00; mockPage[4] = 0x00;
    mockPage[5] = 0x90; mockPage[6] = 0x90; mockPage[7] = 0x90;

    uint8_t originalBytes[5] = {0x55, 0x48, 0x89, 0xE5, 0x48};

    HookInfo info;
    info.function_name = "MockFunc";
    info.function_address = reinterpret_cast<uintptr_t>(mockPage);
    info.hook_type = "JMP_REL32 (0xE9)";

    bool restored = Unhooker::Instance().RestoreHook(info, originalBytes, sizeof(originalBytes));
    ASSERT_TRUE(restored);

    // Verify mockPage first 5 bytes now match original clean bytes
    for (size_t i = 0; i < sizeof(originalBytes); ++i) {
        ASSERT_EQ(mockPage[i], originalBytes[i]);
    }

#if defined(_WIN32)
    VirtualFree(mockPage, 0, MEM_RELEASE);
#else
    munmap(mockPage, 4096);
#endif
}

TEST(Memory, TableIntegrityAndModuleStomping) {
#if !defined(_WIN32)
    uintptr_t genuineAddr = reinterpret_cast<uintptr_t>(&::malloc);
    Dl_info dli{};
    ASSERT_TRUE(dladdr(reinterpret_cast<void*>(genuineAddr), &dli) != 0);
    ASSERT_TRUE(dli.dli_fname != nullptr);

    std::string genuineMod = dli.dli_fname;

    // 1. Expected module matches actual file-backed module -> CLEAN
    auto cleanEv = Unhooker::Instance().InspectTableEntry(
        "ELF_GOT", "libc!malloc", 0x7ffff7001000ULL, genuineAddr, genuineMod
    );
    ASSERT_FALSE(cleanEv.has_value());

    // 2. Expected module does NOT match actual file-backed module (Module Stomping) -> DETECTED
    auto stompEv = Unhooker::Instance().InspectTableEntry(
        "ELF_GOT", "libc!malloc", 0x7ffff7001000ULL, genuineAddr, "libCheatingModule.so"
    );
    ASSERT_TRUE(stompEv.has_value());
    ASSERT_EQ(stompEv->type, DetectionType::IAT_GOT_HOOK_DETECTED);
    ASSERT_NE(stompEv->details.find("module stomping detected"), std::string::npos);
#endif
}

TEST(Memory, ThreadProvenanceAndLiveSignalContext) {
    auto threads = MemoryScanner::Instance().QueryActiveThreads();
    ASSERT_FALSE(threads.empty());

    bool foundCurrentOrOther = false;
    for (const auto& th : threads) {
        if (th.tid > 0) {
            foundCurrentOrOther = true;
            // Instruction pointer must be non-zero (either via live SIGURG signal capture or procfs/GetThreadContext)
            ASSERT_NE(th.instruction_pointer, 0ULL);
        }
    }
    ASSERT_TRUE(foundCurrentOrOther);

    // AuditThreadProvenance should execute cleanly and inspect both start_address and instruction_pointer
    auto provEvents = MemoryScanner::Instance().AuditThreadProvenance();
    (void)provEvents;
}

