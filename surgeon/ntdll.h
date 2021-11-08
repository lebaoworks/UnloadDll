#pragma once

#include "windows.h"
typedef LONG KPRIORITY;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,                // 0x00
    ProcessQuotaLimits,                     // 0x01
    ProcessIoCounters,                      // 0x02
    ProcessVmCounters,                      // 0x03
    ProcessTimes,                           // 0x04
    ProcessBasePriority,                    // 0x05
    ProcessRaisePriority,                   // 0x06
    ProcessDebugPort,                       // 0x07
    ProcessExceptionPort,                   // 0x08
    ProcessAccessToken,                     // 0x09
    ProcessLdtInformation,                  // 0x0A
    ProcessLdtSize,                         // 0x0B
    ProcessDefaultHardErrorMode,            // 0x0C
    ProcessIoPortHandlers,                  // 0x0D Note: this is kernel mode only
    ProcessPooledUsageAndLimits,            // 0x0E
    ProcessWorkingSetWatch,                 // 0x0F
    ProcessUserModeIOPL,                    // 0x10
    ProcessEnableAlignmentFaultFixup,       // 0x11
    ProcessPriorityClass,                   // 0x12
    ProcessWx86Information,                 // 0x13
    ProcessHandleCount,                     // 0x14
    ProcessAffinityMask,                    // 0x15
    ProcessPriorityBoost,                   // 0x16
    ProcessDeviceMap,                       // 0x17
    ProcessSessionInformation,              // 0x18
    ProcessForegroundInformation,           // 0x19
    ProcessWow64Information,                // 0x1A
    ProcessImageFileName,                   // 0x1B
    ProcessLUIDDeviceMapsEnabled,           // 0x1C
    ProcessBreakOnTermination,              // 0x1D
    ProcessDebugObjectHandle,               // 0x1E
    ProcessDebugFlags,                      // 0x1F
    ProcessHandleTracing,                   // 0x20
    ProcessIoPriority,                      // 0x21
    ProcessExecuteFlags,                    // 0x22
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    ProcessGroupInformation,
    ProcessTokenVirtualizationEnabled,
    ProcessConsoleHostProcess,
    ProcessWindowInformation,
    MaxProcessInfoClass                     // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

__kernel_entry NTSTATUS NtQueryInformationProcess(
    _In_            HANDLE           ProcessHandle,
    _In_            PROCESSINFOCLASS ProcessInformationClass,
    _Out_           PVOID            ProcessInformation,
    _In_            ULONG            ProcessInformationLength,
    _Out_opt_       PULONG           ReturnLength
);

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    UCHAR Initialized;
    BYTE  Reversed[3];
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;