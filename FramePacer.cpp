// FramePacer.cpp
//
// Paces frames immediately before GTA:SA's CTimer::Update samples its clock.
// Target: GTA:SA 1.0 US (Hoodlum) exe only (the version SA-MP requires).
//
// Why: GTA measures its frame delta inside CTimer::Update and advances the game
// clock by a whole number of milliseconds. Limiters that wait elsewhere (driver,
// RTSS, Present) let the message pump / input / etc. leak into that delta, so at
// 240+ FPS the game sees a random mix of e.g. 4 and 5 ms ticks -> aim/strafe
// jitter. This plugin waits right before the clock is sampled, so the delta the
// game sees is stable. Approach based on MTA:SA PR #5417 (mtasa-blue).
//
// How it hooks: it does NOT patch the function itself. It scans the exe's
// executable sections for CALL instructions that target CTimer::Update
// (0x561B10) and redirects those call sites to PacedUpdate(), which waits and
// then calls the real function. If no call sites are found (or too many), it
// installs nothing and leaves the game untouched.
//
// Build (x86 / 32-bit only!):  see build.bat

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include <intrin.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "winmm.lib")

namespace {

constexpr uintptr_t kCTimerUpdate = 0x561B10;  // CTimer::Update (GTA:SA 1.0 US)
constexpr uintptr_t kExpectedBase = 0x400000;
constexpr size_t    kMaxSites     = 4;         // sanity limit on call sites

struct Config {
    bool   enabled   = true;
    double targetMs  = 4.0;   // frame time to enforce (integer ms recommended)
    double epsilonMs = 0.02;  // tiny safety margin so the game never sees N-1 ms
    double spinMs    = 1.5;   // final stretch is busy-waited for accuracy
    bool   log       = true;
};

Config        g_cfg;
LARGE_INTEGER g_freq;
LARGE_INTEGER g_last;
bool          g_haveLast = false;
HANDLE        g_timer    = nullptr;
char          g_iniPath[MAX_PATH];
char          g_logPath[MAX_PATH];

void Log(const char* fmt, ...) {
    if (!g_cfg.log) return;
    FILE* f = nullptr;
    if (fopen_s(&f, g_logPath, "a") != 0 || !f) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);
    fputc('\n', f);
    fclose(f);
}

double ReadDouble(const char* key, double def) {
    char defBuf[64], buf[64];
    snprintf(defBuf, sizeof(defBuf), "%g", def);
    GetPrivateProfileStringA("FramePacer", key, defBuf, buf, sizeof(buf), g_iniPath);
    return atof(buf);
}

double Clamp(double v, double lo, double hi) { return v < lo ? lo : (v > hi ? hi : v); }

void LoadConfig() {
    g_cfg.enabled   = GetPrivateProfileIntA("FramePacer", "Enabled", 1, g_iniPath) != 0;
    g_cfg.log       = GetPrivateProfileIntA("FramePacer", "Log", 1, g_iniPath) != 0;
    g_cfg.targetMs  = Clamp(ReadDouble("TargetFrameMs", 4.0), 1.0, 33.0);
    g_cfg.epsilonMs = Clamp(ReadDouble("EpsilonMs", 0.02), 0.0, 0.2);
    g_cfg.spinMs    = Clamp(ReadDouble("SpinMs", 1.5), 0.2, 4.0);
}

// Sleep most of the wait with a (high-resolution if available) waitable timer.
void CoarseSleepMs(double ms) {
    if (g_timer) {
        LARGE_INTEGER due;
        due.QuadPart = -static_cast<LONGLONG>(ms * 10000.0);  // 100 ns units, relative
        if (SetWaitableTimer(g_timer, &due, 0, nullptr, nullptr, FALSE)) {
            WaitForSingleObject(g_timer, INFINITE);
            return;
        }
    }
    Sleep(static_cast<DWORD>(ms));
}

// Replacement for calls to CTimer::Update. Waits, then calls the real function.
void __cdecl PacedUpdate() {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);

    if (g_haveLast) {
        const double periodMs = g_cfg.targetMs + g_cfg.epsilonMs;
        const LONGLONG target =
            g_last.QuadPart + static_cast<LONGLONG>(periodMs * static_cast<double>(g_freq.QuadPart) / 1000.0);

        if (now.QuadPart < target) {
            const double remainMs =
                static_cast<double>(target - now.QuadPart) * 1000.0 / static_cast<double>(g_freq.QuadPart);
            const double coarseMs = remainMs - g_cfg.spinMs;
            if (coarseMs > 0.5) CoarseSleepMs(coarseMs);

            do {
                QueryPerformanceCounter(&now);
                if (now.QuadPart >= target) break;
                _mm_pause();
            } while (true);
        }
        // If we were already late, we simply go now (no catch-up bursts).
    }

    g_last     = now;   // anchor to the moment we actually call the game
    g_haveLast = true;

    reinterpret_cast<void(__cdecl*)()>(kCTimerUpdate)();
}

// Find all "call CTimer::Update" (E8 rel32) instructions in executable sections
// of the main exe, then redirect them to PacedUpdate.
bool InstallHook() {
    HMODULE exe = GetModuleHandleW(nullptr);
    if (reinterpret_cast<uintptr_t>(exe) != kExpectedBase) {
        Log("Unexpected exe base %p - not GTA:SA 1.0 US? Nothing patched.", exe);
        return false;
    }

    auto* base = reinterpret_cast<uint8_t*>(exe);
    auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { Log("Bad DOS header. Nothing patched."); return false; }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { Log("Bad NT header. Nothing patched."); return false; }

    uint8_t* sites[kMaxSites + 1];
    size_t   count = 0;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        uint8_t* start = base + sec[i].VirtualAddress;
        const size_t size = sec[i].Misc.VirtualSize;
        for (size_t o = 0; o + 5 <= size; ++o) {
            if (start[o] != 0xE8) continue;
            int32_t rel;
            memcpy(&rel, start + o + 1, sizeof(rel));
            const uintptr_t dest = reinterpret_cast<uintptr_t>(start + o + 5) + rel;
            if (dest == kCTimerUpdate) {
                if (count <= kMaxSites) sites[count] = start + o;
                ++count;
            }
        }
    }

    Log("Found %u call site(s) to CTimer::Update (0x%X).", static_cast<unsigned>(count),
        static_cast<unsigned>(kCTimerUpdate));
    if (count == 0 || count > kMaxSites) {
        Log("Expected 1-%u call sites. Nothing patched (game left untouched).",
            static_cast<unsigned>(kMaxSites));
        return false;
    }

    for (size_t i = 0; i < count; ++i) {
        uint8_t* p = sites[i];
        DWORD oldProt = 0;
        if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &oldProt)) {
            Log("VirtualProtect failed at %p", p);
            continue;
        }
        const int32_t rel = static_cast<int32_t>(reinterpret_cast<uintptr_t>(&PacedUpdate) -
                                                 (reinterpret_cast<uintptr_t>(p) + 5));
        memcpy(p + 1, &rel, sizeof(rel));
        VirtualProtect(p, 5, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), p, 5);
        Log("Patched call site at %p", p);
    }
    return true;
}

void Init(HMODULE self) {
    GetModuleFileNameA(self, g_iniPath, MAX_PATH);
    strcpy_s(g_logPath, g_iniPath);
    char* dot = strrchr(g_iniPath, '.');
    if (dot) strcpy_s(dot, MAX_PATH - static_cast<size_t>(dot - g_iniPath), ".ini");
    dot = strrchr(g_logPath, '.');
    if (dot) strcpy_s(dot, MAX_PATH - static_cast<size_t>(dot - g_logPath), ".log");

    LoadConfig();
    if (!g_cfg.enabled) { Log("Disabled in INI."); return; }

    QueryPerformanceFrequency(&g_freq);
    timeBeginPeriod(1);

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif
    g_timer = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    if (!g_timer) g_timer = CreateWaitableTimerW(nullptr, FALSE, nullptr);

    Log("FramePacer starting. TargetFrameMs=%g EpsilonMs=%g SpinMs=%g", g_cfg.targetMs, g_cfg.epsilonMs,
        g_cfg.spinMs);
    if (InstallHook())
        Log("Hook installed. Pacing at ~%.1f FPS.", 1000.0 / g_cfg.targetMs);
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        Init(hModule);
    }
    return TRUE;
}
