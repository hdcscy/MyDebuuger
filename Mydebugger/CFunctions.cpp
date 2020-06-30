#include "CFunctions.h"

ZYDIS_INLINE ZydisStatus ZydisStringAppendFormatC(ZydisString* string, const char* format, ...)
{
    if (!string || !string->buffer || !format)
    {
        return ZYDIS_STATUS_INVALID_PARAMETER;
    }

    va_list arglist;
    va_start(arglist, format);
    const int w = vsnprintf(string->buffer + string->length, string->capacity - string->length,
        format, arglist);
    if ((w < 0) || ((size_t)w > string->capacity - string->length))
    {
        va_end(arglist);
        return ZYDIS_STATUS_INSUFFICIENT_BUFFER_SIZE;
    }
    string->length += w;
    va_end(arglist);
    return ZYDIS_STATUS_SUCCESS;
}

static const char* conditionCodeStrings[0x20] =
{
    /*00*/ "eq",
    /*01*/ "lt",
    /*02*/ "le",
    /*03*/ "unord",
    /*04*/ "neq",
    /*05*/ "nlt",
    /*06*/ "nle",
    /*07*/ "ord",
    /*08*/ "eq_uq",
    /*09*/ "nge",
    /*0A*/ "ngt",
    /*0B*/ "false",
    /*0C*/ "oq",
    /*0D*/ "ge",
    /*0E*/ "gt",
    /*0F*/ "true",
    /*10*/ "eq_os",
    /*11*/ "lt_oq",
    /*12*/ "le_oq",
    /*13*/ "unord_s",
    /*14*/ "neq_us",
    /*15*/ "nlt_uq",
    /*16*/ "nle_uq",
    /*17*/ "ord_s",
    /*18*/ "eq_us",
    /*19*/ "nge_uq",
    /*1A*/ "ngt_uq",
    /*1B*/ "false_os",
    /*1C*/ "neq_os",
    /*1D*/ "ge_oq",
    /*1E*/ "gt_oq",
    /*1F*/ "true_us"
};

typedef struct ZydisCustomUserData_
{
    ZydisBool ommitImmediate;
} ZydisCustomUserData;

ZydisFormatterFunc defaultPrintMnemonic;

static ZydisStatus ZydisFormatterPrintMnemonic(const ZydisFormatter* formatter,
    ZydisString* string, const ZydisDecodedInstruction* instruction, ZydisCustomUserData* userData)
{
    // We use the user-data to pass data to the @c ZydisFormatterFormatOperandImm function
    userData->ommitImmediate = ZYDIS_TRUE;

    // Rewrite the instruction-mnemonic for the given instructions
    if (instruction->operandCount &&
        instruction->operands[instruction->operandCount - 1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
    {
        const ZydisU8 conditionCode =
            (ZydisU8)instruction->operands[instruction->operandCount - 1].imm.value.u;
        switch (instruction->mnemonic)
        {
        case ZYDIS_MNEMONIC_CMPPS:
            if (conditionCode < 0x08)
            {
                return ZydisStringAppendFormatC(
                    string, "cmp%sps", conditionCodeStrings[conditionCode]);
            }
            break;
        case ZYDIS_MNEMONIC_CMPPD:
            if (conditionCode < 0x08)
            {
                return ZydisStringAppendFormatC(
                    string, "cmp%spd", conditionCodeStrings[conditionCode]);
            }
            break;
        case ZYDIS_MNEMONIC_VCMPPS:
            if (conditionCode < 0x20)
            {
                return ZydisStringAppendFormatC(
                    string, "vcmp%sps", conditionCodeStrings[conditionCode]);
            }
            break;
        case ZYDIS_MNEMONIC_VCMPPD:
            if (conditionCode < 0x20)
            {
                return ZydisStringAppendFormatC(
                    string, "vcmp%spd", conditionCodeStrings[conditionCode]);
            }
            break;
        default:
            break;
        }
    }

    // We did not rewrite the instruction-mnemonic. Signal the @c ZydisFormatterFormatOperandImm
    // function not to omit the operand
    userData->ommitImmediate = ZYDIS_FALSE;

    // Default mnemonic printing
    return defaultPrintMnemonic(formatter, string, instruction, userData);
}

ZydisFormatterOperandFunc defaultFormatOperandImm;

static ZydisStatus ZydisFormatterFormatOperandImm(const ZydisFormatter* formatter,
    ZydisString* string, const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operand, ZydisCustomUserData* userData)
{
    // The @c ZydisFormatterFormatMnemonic sinals us to omit the immediate (condition-code)
    // operand, because it got replaced by the alias-mnemonic
    if (userData->ommitImmediate)
    {
        return ZYDIS_STATUS_SKIP_OPERAND;
    }

    // Default immediate formatting
    return defaultFormatOperandImm(formatter, string, instruction, operand, userData);
}

void disassembleBuffer(ZydisDecoder* decoder, ZydisU8* data, ZydisUSize length,
    ZydisBool installHooks, DWORD dwDstAddr)
{
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_MEMSEG, ZYDIS_TRUE);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_MEMSIZE, ZYDIS_TRUE);

    if (installHooks)
    {
        defaultPrintMnemonic = (ZydisFormatterFunc)&ZydisFormatterPrintMnemonic;
        ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_HOOK_PRINT_MNEMONIC,
            (const void**)&defaultPrintMnemonic);
        defaultFormatOperandImm = (ZydisFormatterOperandFunc)&ZydisFormatterFormatOperandImm;
        ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_HOOK_FORMAT_OPERAND_IMM,
            (const void**)&defaultFormatOperandImm);
    }

    ZydisU32 instructionPointer = dwDstAddr;

    ZydisDecodedInstruction instruction;
    ZydisCustomUserData userData;
    char buffer[256];
    while (ZYDIS_SUCCESS(
        ZydisDecoderDecodeBuffer(decoder, data, length, instructionPointer, &instruction)))
    {
        data += instruction.length;
        length -= instruction.length;
        instructionPointer += instruction.length;
        printf("%08" PRIX64 "  ", instruction.instrAddress);
        ZydisFormatterFormatInstructionEx(
            &formatter, &instruction, &buffer[0], sizeof(buffer), &userData);
        printf(" %s\n", &buffer[0]);
    }
}

CFunctions::CFunctions()
{
    memset(m_szNameOrPath, 0, sizeof(m_szNameOrPath));

    memset(&m_si, 0, sizeof(m_si));
    m_si.cb = sizeof(m_si);

    m_hProcess = nullptr;
}


CFunctions::~CFunctions()
{
}

DWORD CFunctions::ExceptionDebugEvent(DEBUG_EVENT & Event)
{
    //如果是单步异常应该做的一些处理
    if (Event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        std::cout << "<-- EXCEPTION_SINGLE_STEP -->" << std::endl;
        //ShowMemory(Event);
        ShowRegisters(Event);
    }

    GetCmd(Event);

    return DBG_CONTINUE;
}

DWORD CFunctions::CreateThreadDebugEvent(DEBUG_EVENT & Event)
{
    std::cout << "Thread ID(hex): " << std::hex << Event.dwThreadId 
              << " Thread Handle(hex): " << std::hex << Event.u.CreateThread.hThread;
    std::cout << std::endl;
    return DBG_CONTINUE;
}

DWORD CFunctions::CreateProcessDebugEvent(DEBUG_EVENT & Event)
{
    std::cout << "Process baseImage(hex): " << std::hex << Event.u.CreateProcessInfo.lpBaseOfImage;
    std::cout << std::endl;
    return DBG_CONTINUE;
}

DWORD CFunctions::ExitThreadDebugEvent(DEBUG_EVENT & Event)
{
    std::cout << "Thread exit!";
    std::cout << std::endl;
    return DBG_CONTINUE;
}

DWORD CFunctions::ExitProcessDebugEvent(DEBUG_EVENT & Event)
{
    std::cout << "Process exit!";
    std::cout << std::endl;
    return DBG_CONTINUE;
}

DWORD CFunctions::LoadDllDebugEvent(DEBUG_EVENT & Event)
{
    LOAD_DLL_DEBUG_INFO* pInfo = nullptr;
    DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
    char szBuf[MAX_PATH] = { '\0' };
    SIZE_T nNumberOfBytesRead = 0;
    DWORD dwAddrImageName = 0;

    pInfo = &Event.u.LoadDll;
    if ((nullptr != pInfo) && (nullptr != pInfo->lpImageName))
    {
        do 
        {
            if (!ReadProcessMemory(m_hProcess, pInfo->lpImageName, &dwAddrImageName, sizeof(dwAddrImageName), &nNumberOfBytesRead)) 
                break;

            if (0 == dwAddrImageName) 
                break;

            if (!ReadProcessMemory(m_hProcess, (void*)dwAddrImageName, &szBuf, sizeof(szBuf), &nNumberOfBytesRead)) 
                break;

            if (0 == pInfo->fUnicode) 
                // ansi
                printf("DLLBase: %p Name: %s\n", Event.u.LoadDll.lpBaseOfDll, szBuf);

            else 
                // unicode
                wprintf(L"DLLBase: %p Name: %s\n", Event.u.LoadDll.lpBaseOfDll, szBuf);
        } 
        while (0);
    }

    return DBG_CONTINUE;
}

DWORD CFunctions::UnloadDllDebugEvent(DEBUG_EVENT & Event)
{
    std::cout << "DLL unload!";
    std::cout << std::endl;
    return DBG_CONTINUE;
}

DWORD CFunctions::OutputDebugStringEvent(DEBUG_EVENT & Event)
{
    std::cout << "OutputDebugStringEvent!";
    std::cout << std::endl;
    return DBG_CONTINUE;
}

DWORD CFunctions::RipEvent(DEBUG_EVENT & Event)
{
    return DBG_CONTINUE;
}

void CFunctions::ShowRegisters(DEBUG_EVENT & Event)
{
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, Event.dwThreadId);
    if (hThread == nullptr)
    {
        return;
    }

    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    bool bFlag = GetThreadContext(hThread, &context);
    if (!bFlag)
    {
        return;
    }

    //std::cout.fill('0');
    printf("EAX=%p EBX=%p ECX=%p EDX=%p\n"
           "EBP=%p ESP=%p ESI=%p EDI=%p\n"
           "EIP=%p EFLAG=%p\n",
           context.Eax,
           context.Ebx,
           context.Ecx,
           context.Edx,
           context.Ebp,
           context.Esp,
           context.Esi,
           context.Edi,
           context.Eip,
           context.EFlags);

    if (hThread != nullptr)
    {
        CloseHandle(hThread);
    }

    return;
}

void CFunctions::ShowMemory(DEBUG_EVENT & Event)
{
    if (ZydisGetVersion() != ZYDIS_VERSION)
    {
        fputs("Invalid zydis version\n", stderr);
        return;
    }

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, Event.dwThreadId);
    if (hThread == nullptr)
    {
        return;
    }

    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    bool bFlag = GetThreadContext(hThread, &context);
    if (!bFlag)
    {
        return;
    }

    ZydisU8 data[16] = { 0 };
    DWORD dwSize = 16;

    bFlag = ReadProcessMemory(m_hProcess, reinterpret_cast<LPCVOID>(context.Eip), data, dwSize, &dwSize);
    if (bFlag == false)
    {
        std::cout << "读取内存数据失败！" << std::endl;
        return;
    }

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);

    disassembleBuffer(&decoder, &data[0], sizeof(data), ZYDIS_FALSE, context.Eip);

    //puts("");
    //disassembleBuffer(&decoder, &data[0], sizeof(data), ZYDIS_TRUE, context.Eip);
}

void CFunctions::SetStep(DEBUG_EVENT & Event)
{
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, Event.dwThreadId);
    if (hThread == nullptr)
    {
        return;
    }

    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    bool bFlag = GetThreadContext(hThread, &context);
    if (!bFlag)
    {
        return;
    }

    //单步步入
    context.EFlags |= 0x100;

    bFlag = SetThreadContext(hThread, &context);
    if (!bFlag)
    {
        return;
    }

    if (hThread != nullptr)
    {      
        CloseHandle(hThread);
    }

    ShowMemory(Event);

    return;
}

void CFunctions::GetCmd(DEBUG_EVENT & Event)
{
    char szString[256] = { 0 };

    do
    {
        std::cout << "Command >> ";
        std::cin >> szString;

        if (szString == nullptr)
        {
            std::cout << std::endl;
            continue;
        }

        //显示寄存器
        if (strcmp(szString, "r") == 0)
        {
            ShowRegisters(Event);
        }

        //运行
        if (strcmp(szString, "g") == 0)
        {
            break;
        }

        //单步步入
        if (strcmp(szString, "t") == 0)
        {
            SetStep(Event);
            break;
        }
    } 
    while (true);

    return;
}

bool CFunctions::GetNameOrPath(char * szString)
{
    if (szString != nullptr)
    {
        memcpy(m_szNameOrPath, szString, sizeof(szString));
        return true;
    }
    
    return false;
}

bool CFunctions::MainDebugger(char * szString)
{
    if (GetNameOrPath(szString))
    {
         if (!CreateProcess(nullptr, m_szNameOrPath, nullptr, nullptr, false, DEBUG_PROCESS, nullptr, nullptr, &m_si, &m_pi))
         {
             std::cout << "Debug Error!";
             return false;
         }

         std::cout << "Debug completed!";
         std::cout << std::endl;

         m_hProcess = m_pi.hProcess;

         do 
         {
             DEBUG_EVENT Event;
             
             bool bFlag = WaitForDebugEvent(&Event, INFINITE);
             if (!bFlag)
             {
                 return false;
             }

             DWORD dwContinueStatus = 0;
             dwContinueStatus = HandlerEvent(Event);

             bFlag = ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, dwContinueStatus);
             if (!bFlag)
             {
                 return false;
             }
         } 
         while (true);
    }

    std::cout << "File or path is error!";
    std::cout << std::endl;
    return false;
}

DWORD CFunctions::HandlerEvent(DEBUG_EVENT & Event)
{
    switch (Event.dwDebugEventCode)
    {
        case EXCEPTION_DEBUG_EVENT:
            return ExceptionDebugEvent(Event);
        break;

        case CREATE_THREAD_DEBUG_EVENT:
            return CreateThreadDebugEvent(Event);
        break;

        case CREATE_PROCESS_DEBUG_EVENT:
            return CreateProcessDebugEvent(Event);
        break;

        case EXIT_THREAD_DEBUG_EVENT:
            return ExitThreadDebugEvent(Event);
        break;

        case EXIT_PROCESS_DEBUG_EVENT:
            return ExitProcessDebugEvent(Event);
        break;

        case LOAD_DLL_DEBUG_EVENT:
            return LoadDllDebugEvent(Event);
        break;

        case UNLOAD_DLL_DEBUG_EVENT:
            return UnloadDllDebugEvent(Event);
        break;

        case OUTPUT_DEBUG_STRING_EVENT:
            return OutputDebugStringEvent(Event);
        break;
    }

    //return DBG_CONTINUE;
}
