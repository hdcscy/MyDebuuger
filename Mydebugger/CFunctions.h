#pragma once

#include <windows.h>
#include <iostream>
#include <Psapi.h>
#include <iomanip>
#include <stdarg.h>
#include <stdlib.h>
#include <inttypes.h>
#include <Zydis/Zydis.h>

#pragma comment (lib, "Psapi.lib")
#pragma comment (lib, "Zydis.lib")

class CFunctions
{
public:
    CFunctions();
    ~CFunctions();

    DWORD ExceptionDebugEvent(DEBUG_EVENT& Event);

    DWORD CreateThreadDebugEvent(DEBUG_EVENT& Event);

    DWORD CreateProcessDebugEvent(DEBUG_EVENT& Event);

    DWORD ExitThreadDebugEvent(DEBUG_EVENT& Event);

    DWORD ExitProcessDebugEvent(DEBUG_EVENT& Event);

    DWORD LoadDllDebugEvent(DEBUG_EVENT& Event);

    DWORD UnloadDllDebugEvent(DEBUG_EVENT& Event);

    DWORD OutputDebugStringEvent(DEBUG_EVENT& Event);

    DWORD RipEvent(DEBUG_EVENT& Event);

    void ShowRegisters(DEBUG_EVENT& Event);

    void ShowMemory(DEBUG_EVENT& Event);

    void SetStep(DEBUG_EVENT& Event);

    void GetCmd(DEBUG_EVENT& Event);

    bool GetNameOrPath(char* szString);

    bool MainDebugger(char* szString);

    DWORD HandlerEvent(DEBUG_EVENT& Event);

private:
    char m_szNameOrPath[256];
    STARTUPINFO m_si;
    PROCESS_INFORMATION m_pi;
    HANDLE m_hProcess;
    DWORD m_GlobalEip;
};

