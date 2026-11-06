#include "tests/test_framework.hpp"
#include "noescape/memory/cheat_signature.hpp"
#include "noescape/memory/signature_database.hpp"
#include "noescape/memory/pattern_scanner.hpp"
#include "noescape/memory/memory_scanner.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <vector>
#include <string>
#include <cstring>

using namespace noescape::memory;
using namespace noescape::core;

TEST(Signatures, DatabaseIntegrityAndCount) {
    auto sigs = SignatureDatabase::GetAllSignatures();
    ASSERT_GT(sigs.size(), 35);
    ASSERT_EQ(SignatureDatabase::Count(), sigs.size());

    // Verify all 8 primary cheat categories are represented
    bool hasHookFramework = false;
    bool hasInjectorStub = false;
    bool hasDmaTool = false;
    bool hasDebuggerInterface = false;
    bool hasShellcodePrologue = false;
    bool hasOverlayHook = false;
    bool hasPackerProtector = false;
    bool hasSpeedhackWrapper = false;

    for (const auto& sig : sigs) {
        ASSERT_FALSE(sig.GetName().empty());
        ASSERT_GT(sig.Length(), 0);
        ASSERT_FALSE(sig.GetDescription().empty());
        ASSERT_GT(sig.GetThreatScore(), 0);

        switch (sig.GetCategory()) {
            case SignatureCategory::HOOK_FRAMEWORK: hasHookFramework = true; break;
            case SignatureCategory::INJECTOR_STUB: hasInjectorStub = true; break;
            case SignatureCategory::DMA_TOOL: hasDmaTool = true; break;
            case SignatureCategory::DEBUGGER_INTERFACE: hasDebuggerInterface = true; break;
            case SignatureCategory::SHELLCODE_PROLOGUE: hasShellcodePrologue = true; break;
            case SignatureCategory::OVERLAY_HOOK: hasOverlayHook = true; break;
            case SignatureCategory::PACKER_PROTECTOR: hasPackerProtector = true; break;
            case SignatureCategory::SPEEDHACK_WRAPPER: hasSpeedhackWrapper = true; break;
            default: break;
        }
    }

    ASSERT_TRUE(hasHookFramework);
    ASSERT_TRUE(hasInjectorStub);
    ASSERT_TRUE(hasDmaTool);
    ASSERT_TRUE(hasDebuggerInterface);
    ASSERT_TRUE(hasShellcodePrologue);
    ASSERT_TRUE(hasOverlayHook);
    ASSERT_TRUE(hasPackerProtector);
    ASSERT_TRUE(hasSpeedhackWrapper);
}

TEST(Signatures, CategoryFiltering) {
    auto hooks = SignatureDatabase::GetByCategory(SignatureCategory::HOOK_FRAMEWORK);
    ASSERT_FALSE(hooks.empty());
    for (const auto& h : hooks) {
        ASSERT_EQ(static_cast<int>(h.GetCategory()), static_cast<int>(SignatureCategory::HOOK_FRAMEWORK));
    }

    auto dma = SignatureDatabase::GetByCategory(SignatureCategory::DMA_TOOL);
    ASSERT_FALSE(dma.empty());
    for (const auto& d : dma) {
        ASSERT_EQ(static_cast<int>(d.GetCategory()), static_cast<int>(SignatureCategory::DMA_TOOL));
    }

    auto minhook = SignatureDatabase::FindByName("MinHook_X64_R10_Trampoline");
    ASSERT_TRUE(minhook.has_value());
    ASSERT_EQ(minhook->GetName(), "MinHook_X64_R10_Trampoline");
    ASSERT_EQ(static_cast<int>(minhook->GetCategory()), static_cast<int>(SignatureCategory::HOOK_FRAMEWORK));

    auto nonExistent = SignatureDatabase::FindByName("NonExistent_Cheat_Signature_XYZ");
    ASSERT_FALSE(nonExistent.has_value());
}

TEST(Signatures, TargetRuleMatchingLogic) {
    // 1. UNBACKED_ONLY rule
    ASSERT_TRUE(CheatSignature::IsTargetMatched(MemoryTargetRule::UNBACKED_ONLY, false, true, true));  // anon exec
    ASSERT_FALSE(CheatSignature::IsTargetMatched(MemoryTargetRule::UNBACKED_ONLY, true, true, true));  // file exec
    ASSERT_FALSE(CheatSignature::IsTargetMatched(MemoryTargetRule::UNBACKED_ONLY, false, false, true)); // anon non-exec
    ASSERT_FALSE(CheatSignature::IsTargetMatched(MemoryTargetRule::UNBACKED_ONLY, false, true, false)); // not readable

    // 2. ALL_EXECUTABLE rule
    ASSERT_TRUE(CheatSignature::IsTargetMatched(MemoryTargetRule::ALL_EXECUTABLE, false, true, true));  // anon exec
    ASSERT_TRUE(CheatSignature::IsTargetMatched(MemoryTargetRule::ALL_EXECUTABLE, true, true, true));   // file exec
    ASSERT_FALSE(CheatSignature::IsTargetMatched(MemoryTargetRule::ALL_EXECUTABLE, false, false, true)); // anon non-exec

    // 3. ANONYMOUS_DATA rule
    ASSERT_TRUE(CheatSignature::IsTargetMatched(MemoryTargetRule::ANONYMOUS_DATA, false, false, true)); // anon data
    ASSERT_FALSE(CheatSignature::IsTargetMatched(MemoryTargetRule::ANONYMOUS_DATA, true, false, true));  // file data
    ASSERT_FALSE(CheatSignature::IsTargetMatched(MemoryTargetRule::ANONYMOUS_DATA, false, true, true));  // anon exec

    // 4. ANY_ANONYMOUS rule
    ASSERT_TRUE(CheatSignature::IsTargetMatched(MemoryTargetRule::ANY_ANONYMOUS, false, true, true));  // anon exec
    ASSERT_TRUE(CheatSignature::IsTargetMatched(MemoryTargetRule::ANY_ANONYMOUS, false, false, true)); // anon data
    ASSERT_FALSE(CheatSignature::IsTargetMatched(MemoryTargetRule::ANY_ANONYMOUS, true, true, true));  // file exec
    ASSERT_FALSE(CheatSignature::IsTargetMatched(MemoryTargetRule::ANY_ANONYMOUS, true, false, true)); // file data

    // 5. ALL_REGIONS rule
    ASSERT_TRUE(CheatSignature::IsTargetMatched(MemoryTargetRule::ALL_REGIONS, true, true, true));
    ASSERT_TRUE(CheatSignature::IsTargetMatched(MemoryTargetRule::ALL_REGIONS, false, false, true));
    ASSERT_FALSE(CheatSignature::IsTargetMatched(MemoryTargetRule::ALL_REGIONS, false, false, false));
}

TEST(Signatures, CustomRegistrationAndReset) {
    size_t initialCount = SignatureDatabase::Count();

    CheatSignature custom(
        "90 90 90 CC CC",
        "Test_Custom_Breakpoint_Cluster",
        SignatureCategory::DEBUGGER_INTERFACE,
        90,
        Severity::HIGH,
        MemoryTargetRule::UNBACKED_ONLY,
        "Custom synthetic breakpoint cluster for test verification"
    );

    SignatureDatabase::RegisterCustomSignature(custom);
    ASSERT_EQ(SignatureDatabase::Count(), initialCount + 1);

    auto found = SignatureDatabase::FindByName("Test_Custom_Breakpoint_Cluster");
    ASSERT_TRUE(found.has_value());
    ASSERT_EQ(found->GetThreatScore(), 90);

    SignatureDatabase::Reset();
    ASSERT_EQ(SignatureDatabase::Count(), initialCount);
    ASSERT_FALSE(SignatureDatabase::FindByName("Test_Custom_Breakpoint_Cluster").has_value());
}

TEST(Signatures, HookFrameworkPatternMatching) {
    // MinHook x64 Trampoline: 49 BA [imm64] 41 FF E2
    std::vector<uint8_t> buffer(64, 0x90);
    // Inject at offset 16
    buffer[16] = 0x49; buffer[17] = 0xBA;
    buffer[18] = 0x11; buffer[19] = 0x22; buffer[20] = 0x33; buffer[21] = 0x44;
    buffer[22] = 0x55; buffer[23] = 0x66; buffer[24] = 0x77; buffer[25] = 0x88;
    buffer[26] = 0x41; buffer[27] = 0xFF; buffer[28] = 0xE2;

    auto minhookSig = SignatureDatabase::FindByName("MinHook_X64_R10_Trampoline");
    ASSERT_TRUE(minhookSig.has_value());

    auto match = PatternScanner::Scan(buffer.data(), buffer.size(), *minhookSig);
    ASSERT_TRUE(match.has_value());
    ASSERT_EQ(*match, 16);

    // PolyHook push-xchg-ret: 50 48 B8 [imm64] 48 87 04 24 C3
    std::vector<uint8_t> polyBuf(64, 0xCC);
    polyBuf[10] = 0x50; polyBuf[11] = 0x48; polyBuf[12] = 0xB8;
    polyBuf[13] = 0xAA; polyBuf[14] = 0xBB; polyBuf[15] = 0xCC; polyBuf[16] = 0xDD;
    polyBuf[17] = 0xEE; polyBuf[18] = 0xFF; polyBuf[19] = 0x00; polyBuf[20] = 0x11;
    polyBuf[21] = 0x48; polyBuf[22] = 0x87; polyBuf[23] = 0x04; polyBuf[24] = 0x24;
    polyBuf[25] = 0xC3;

    auto polySig = SignatureDatabase::FindByName("PolyHook_X64_PushXchgRet");
    ASSERT_TRUE(polySig.has_value());
    auto polyMatch = PatternScanner::Scan(polyBuf.data(), polyBuf.size(), *polySig);
    ASSERT_TRUE(polyMatch.has_value());
    ASSERT_EQ(*polyMatch, 10);
}

TEST(Signatures, DmaToolPatternMatching) {
    // LeechCore "LC_MEM" header and MemProcFS "VMMDLL"
    std::vector<uint8_t> buffer(128, 0x00);

    // Write "LC_MEM" at offset 20: 4C 43 5F 4D 45 4D
    const char* lc = "LC_MEM";
    std::memcpy(buffer.data() + 20, lc, 6);

    // Write "VMMDLL" at offset 80: 56 4D 4D 44 4C 4C
    const char* vmm = "VMMDLL";
    std::memcpy(buffer.data() + 80, vmm, 6);

    auto dmaSigs = SignatureDatabase::GetByCategory(SignatureCategory::DMA_TOOL);
    auto matches = PatternScanner::ScanSignatures(buffer.data(), buffer.size(), dmaSigs);

    ASSERT_TRUE(matches.size() >= 2);
    bool foundLc = false;
    bool foundVmm = false;

    for (const auto& m : matches) {
        if (m.signature_name == "LeechCore_Memory_Header") {
            foundLc = true;
            ASSERT_EQ(m.address, 20);
        } else if (m.signature_name == "MemProcFS_VmmDll") {
            foundVmm = true;
            ASSERT_EQ(m.address, 80);
        }
    }

    ASSERT_TRUE(foundLc);
    ASSERT_TRUE(foundVmm);
}

TEST(Signatures, InjectorAndShellcodePatternMatching) {
    // ManualMap DllMain invocation stub: 48 83 EC 20 B8 01 00 00 00 89 ? ? ? FF D2 48 83 C4 20
    std::vector<uint8_t> buffer(64, 0x90);
    uint8_t mmapStub[] = {
        0x48, 0x83, 0xEC, 0x20, 0xB8, 0x01, 0x00, 0x00, 0x00,
        0x89, 0x44, 0x24, 0x18, 0xFF, 0xD2, 0x48, 0x83, 0xC4, 0x20
    };
    std::memcpy(buffer.data() + 5, mmapStub, sizeof(mmapStub));

    auto mmapSig = SignatureDatabase::FindByName("ManualMap_DllMain_Invocation");
    ASSERT_TRUE(mmapSig.has_value());
    auto match = PatternScanner::Scan(buffer.data(), buffer.size(), *mmapSig);
    ASSERT_TRUE(match.has_value());
    ASSERT_EQ(*match, 5);

    // Generic EggHunter: E8 00 00 00 00 58
    uint8_t eggStub[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x58};
    std::memcpy(buffer.data() + 40, eggStub, sizeof(eggStub));

    auto eggSig = SignatureDatabase::FindByName("Generic_EggHunter_CallPop");
    ASSERT_TRUE(eggSig.has_value());
    auto eggMatch = PatternScanner::Scan(buffer.data(), buffer.size(), *eggSig);
    ASSERT_TRUE(eggMatch.has_value());
    ASSERT_EQ(*eggMatch, 40);
}

TEST(Signatures, OverlayAndSpeedhackPatternMatching) {
    // D3D Present hook stub: 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 48 8B D9 49 8B F8
    std::vector<uint8_t> buffer(100, 0x00);
    uint8_t d3dStub[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10,
        0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B, 0xD9, 0x49, 0x8B, 0xF8
    };
    std::memcpy(buffer.data() + 12, d3dStub, sizeof(d3dStub));

    auto d3dSig = SignatureDatabase::FindByName("D3D_SwapChain_Present_Hook");
    ASSERT_TRUE(d3dSig.has_value());
    auto match = PatternScanner::Scan(buffer.data(), buffer.size(), *d3dSig);
    ASSERT_TRUE(match.has_value());
    ASSERT_EQ(*match, 12);

    // Speedhack module name "Speedhack.dll"
    const char* ceSpeed = "Speedhack.dll";
    std::memcpy(buffer.data() + 60, ceSpeed, std::strlen(ceSpeed));

    auto speedSig = SignatureDatabase::FindByName("Speedhack_CE_ModuleName");
    ASSERT_TRUE(speedSig.has_value());
    auto speedMatch = PatternScanner::Scan(buffer.data(), buffer.size(), *speedSig);
    ASSERT_TRUE(speedMatch.has_value());
    ASSERT_EQ(*speedMatch, 60);
}

TEST(Signatures, LiveMemoryAuditDetectionInAnonymousMemory) {
#if defined(_WIN32)
    uint8_t* page = static_cast<uint8_t*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    ASSERT_TRUE(page != nullptr);
#else
    uint8_t* page = static_cast<uint8_t*>(mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    ASSERT_TRUE(page != MAP_FAILED);
#endif

    // Inject MinHook x64 Trampoline: 49 BA [8 bytes target] 41 FF E2
    page[100] = 0x49; page[101] = 0xBA;
    page[102] = 0x78; page[103] = 0x56; page[104] = 0x34; page[105] = 0x12;
    page[106] = 0x00; page[107] = 0x00; page[108] = 0x00; page[109] = 0x00;
    page[110] = 0x41; page[111] = 0xFF; page[112] = 0xE2;

    auto events = MemoryScanner::Instance().PerformAudit();

    bool foundMinHook = false;
    for (const auto& ev : events) {
        if (ev.type == DetectionType::MEMORY_SIGNATURE_MATCH &&
            ev.details.find("MinHook_X64_R10_Trampoline") != std::string::npos) {
            foundMinHook = true;
            ASSERT_EQ(ev.component, "MemoryScanner::HOOK_FRAMEWORK");
            ASSERT_EQ(ev.threat_score, 100);
            ASSERT_EQ(static_cast<int>(ev.severity), static_cast<int>(Severity::FATAL_BAN));
        }
    }

#if defined(_WIN32)
    VirtualFree(page, 0, MEM_RELEASE);
#else
    munmap(page, 4096);
#endif

    ASSERT_TRUE(foundMinHook);
}

TEST(Signatures, CleanProcessHasNoSignatureFalsePositives) {
    // In a clean process with no injected anonymous memory, default signatures
    // must not produce any MEMORY_SIGNATURE_MATCH events on genuine binaries!
    auto sigs = MemoryScanner::GetDefaultCheatSignatures();
    auto events = MemoryScanner::Instance().ScanSignatures(sigs);

    ASSERT_EQ(events.size(), 0);
}

TEST(Signatures, LiveMemoryAuditDetectionInAnonymousDataMemory) {
    // Allocate anonymous non-executable (data) memory: PROT_READ | PROT_WRITE
#if defined(_WIN32)
    uint8_t* page = static_cast<uint8_t*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    ASSERT_TRUE(page != nullptr);
#else
    uint8_t* page = static_cast<uint8_t*>(mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    ASSERT_TRUE(page != MAP_FAILED);
#endif

    // Inject LeechCore header "LC_MEM" (4C 43 5F 4D 45 4D) at offset 128
    const char* lc = "LC_MEM";
    std::memcpy(page + 128, lc, 6);

    // Inject MemProcFS header "VMMDLL" (56 4D 4D 44 4C 4C) at offset 256
    const char* vmm = "VMMDLL";
    std::memcpy(page + 256, vmm, 6);

    auto sigs = MemoryScanner::GetDefaultCheatSignatures();
    auto events = MemoryScanner::Instance().ScanSignatures(sigs);

    bool foundLc = false;
    bool foundVmm = false;
    for (const auto& ev : events) {
        if (ev.type == DetectionType::MEMORY_SIGNATURE_MATCH) {
            if (ev.details.find("LeechCore_Memory_Header") != std::string::npos) {
                foundLc = true;
                ASSERT_EQ(ev.component, "MemoryScanner::DMA_TOOL");
            }
            if (ev.details.find("MemProcFS_VmmDll") != std::string::npos) {
                foundVmm = true;
                ASSERT_EQ(ev.component, "MemoryScanner::DMA_TOOL");
            }
        }
    }

#if defined(_WIN32)
    VirtualFree(page, 0, MEM_RELEASE);
#else
    munmap(page, 4096);
#endif

    ASSERT_TRUE(foundLc);
    ASSERT_TRUE(foundVmm);
}

TEST(Signatures, NewCuratedSignaturesVerification) {
    ASSERT_EQ(SignatureDatabase::Count(), 50);

    auto refl = SignatureDatabase::FindByName("Reflective_Loader_Export");
    ASSERT_TRUE(refl.has_value());
    ASSERT_EQ(static_cast<int>(refl->GetCategory()), static_cast<int>(SignatureCategory::INJECTOR_STUB));

    auto ldr = SignatureDatabase::FindByName("ManualMap_LdrLoadDll_Resolver");
    ASSERT_TRUE(ldr.has_value());
    ASSERT_EQ(static_cast<int>(ldr->GetCategory()), static_cast<int>(SignatureCategory::INJECTOR_STUB));

    auto ceVeh = SignatureDatabase::FindByName("CheatEngine_VEH_Debugger");
    ASSERT_TRUE(ceVeh.has_value());
    ASSERT_EQ(static_cast<int>(ceVeh->GetCategory()), static_cast<int>(SignatureCategory::DEBUGGER_INTERFACE));

    auto d3d12 = SignatureDatabase::FindByName("D3D12_CommandQueue_Hook");
    ASSERT_TRUE(d3d12.has_value());
    ASSERT_EQ(static_cast<int>(d3d12->GetCategory()), static_cast<int>(SignatureCategory::OVERLAY_HOOK));

    auto upx2 = SignatureDatabase::FindByName("UPX_Section_2");
    ASSERT_TRUE(upx2.has_value());
    ASSERT_EQ(static_cast<int>(upx2->GetCategory()), static_cast<int>(SignatureCategory::PACKER_PROTECTOR));

    auto vmp = SignatureDatabase::FindByName("VMProtect_Section_Tag");
    ASSERT_TRUE(vmp.has_value());
    ASSERT_EQ(static_cast<int>(vmp->GetCategory()), static_cast<int>(SignatureCategory::PACKER_PROTECTOR));

    auto themida = SignatureDatabase::FindByName("ThemIDA_Section_Tag");
    ASSERT_TRUE(themida.has_value());
    ASSERT_EQ(static_cast<int>(themida->GetCategory()), static_cast<int>(SignatureCategory::PACKER_PROTECTOR));

    auto speedTgt = SignatureDatabase::FindByName("Speedhack_TimeGetTime_Detour");
    ASSERT_TRUE(speedTgt.has_value());
    ASSERT_EQ(static_cast<int>(speedTgt->GetCategory()), static_cast<int>(SignatureCategory::SPEEDHACK_WRAPPER));

    // Pattern match ReflectiveLoader
    std::vector<uint8_t> buf(64, 0x00);
    std::memcpy(buf.data() + 10, "ReflectiveLoader", 16);
    auto match = PatternScanner::Scan(buf.data(), buf.size(), *refl);
    ASSERT_TRUE(match.has_value());
    ASSERT_EQ(*match, 10);
}

TEST(Signatures, TrampolineAndDetourRuleSafety) {
    auto d3dSig = SignatureDatabase::FindByName("D3D_SwapChain_Present_Hook");
    ASSERT_TRUE(d3dSig.has_value());
    // Crucial false positive prevention: must NOT be ALL_EXECUTABLE
    ASSERT_EQ(static_cast<int>(d3dSig->GetTargetRule()), static_cast<int>(MemoryTargetRule::UNBACKED_ONLY));

    auto substrateSig = SignatureDatabase::FindByName("Substrate_X64_PushRet");
    ASSERT_TRUE(substrateSig.has_value());
    ASSERT_EQ(static_cast<int>(substrateSig->GetTargetRule()), static_cast<int>(MemoryTargetRule::UNBACKED_ONLY));
}
