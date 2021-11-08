#pragma once

#include <windows.h>
#include <windef.h>

#include "tebpeb64.h"

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

typedef struct _LDR_MODULE {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    /*union {
        ULONG CheckSum;
        PVOID Reserved6;
    };*/
    ULONG TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct PEB64
{
    union
    {
        struct
        {
            BYTE InheritedAddressSpace;                                 //0x000
            BYTE ReadImageFileExecOptions;                              //0x001
            BYTE BeingDebugged;                                         //0x002
            BYTE _SYSTEM_DEPENDENT_01;                                  //0x003
        } flags;
        BYTE dummyalign[8];
    } dword0;
    PVOID                           Mutant;                             //0x0008
    PVOID                           ImageBaseAddress;                   //0x0010
    PPEB_LDR_DATA                   Ldr;                                //0x0018
    PVOID                           ProcessParameters;                  //0x0020 / pointer to RTL_USER_PROCESS_PARAMETERS64
    PVOID                           SubSystemData;                      //0x0028
    PVOID                           ProcessHeap;                        //0x0030
    PVOID                           FastPebLock;                        //0x0038
    PVOID                           _SYSTEM_DEPENDENT_02;               //0x0040
    PVOID                           _SYSTEM_DEPENDENT_03;               //0x0048
    PVOID                           _SYSTEM_DEPENDENT_04;               //0x0050
    union
    {
        PVOID                       KernelCallbackTable;                //0x0058
        PVOID                       UserSharedInfoPtr;                  //0x0058
    };
    DWORD                           SystemReserved;                     //0x0060
    DWORD                           _SYSTEM_DEPENDENT_05;               //0x0064
    PVOID                           _SYSTEM_DEPENDENT_06;               //0x0068
    PVOID                           TlsExpansionCounter;                //0x0070
    PVOID                           TlsBitmap;                          //0x0078
    DWORD                           TlsBitmapBits[2];                   //0x0080
    PVOID                           ReadOnlySharedMemoryBase;           //0x0088
    PVOID                           _SYSTEM_DEPENDENT_07;               //0x0090
    PVOID                           ReadOnlyStaticServerData;           //0x0098
    PVOID                           AnsiCodePageData;                   //0x00A0
    PVOID                           OemCodePageData;                    //0x00A8
    PVOID                           UnicodeCaseTableData;               //0x00B0
    DWORD                           NumberOfProcessors;                 //0x00B8
    union
    {
        DWORD                       NtGlobalFlag;                       //0x00BC
        DWORD                       dummy02;                            //0x00BC
    };
    LARGE_INTEGER                   CriticalSectionTimeout;             //0x00C0
    PVOID                           HeapSegmentReserve;                 //0x00C8
    PVOID                           HeapSegmentCommit;                  //0x00D0
    PVOID                           HeapDeCommitTotalFreeThreshold;     //0x00D8
    PVOID                           HeapDeCommitFreeBlockThreshold;     //0x00E0
    DWORD                           NumberOfHeaps;                      //0x00E8
    DWORD                           MaximumNumberOfHeaps;               //0x00EC
    PVOID                           ProcessHeaps;                       //0x00F0
    PVOID                           GdiSharedHandleTable;               //0x00F8
    PVOID                           ProcessStarterHelper;               //0x0100
    PVOID                           GdiDCAttributeList;                 //0x0108
    PVOID                           LoaderLock;                         //0x0110
    DWORD                           OSMajorVersion;                     //0x0118
    DWORD                           OSMinorVersion;                     //0x011C
    WORD                            OSBuildNumber;                      //0x0120
    WORD                            OSCSDVersion;                       //0x0122
    DWORD                           OSPlatformId;                       //0x0124
    DWORD                           ImageSubsystem;                     //0x0128
    DWORD                           ImageSubsystemMajorVersion;         //0x012C
    PVOID                           ImageSubsystemMinorVersion;         //0x0130
    union
    {
        PVOID                       ImageProcessAffinityMask;           //0x0138
        PVOID                       ActiveProcessAffinityMask;          //0x0138
    };
    PVOID                           GdiHandleBuffer[30];                //0x0140
    PVOID                           PostProcessInitRoutine;             //0x0230
    PVOID                           TlsExpansionBitmap;                 //0x0238
    DWORD                           TlsExpansionBitmapBits[32];         //0x0240
    PVOID                           SessionId;                          //0x02C0
    ULARGE_INTEGER                  AppCompatFlags;                     //0x02C8
    ULARGE_INTEGER                  AppCompatFlagsUser;                 //0x02D0
    PVOID                           pShimData;                          //0x02D8
    PVOID                           AppCompatInfo;                      //0x02E0
    UNICODE_STRING64                CSDVersion;                         //0x02E8
    PVOID                           ActivationContextData;              //0x02F8
    PVOID                           ProcessAssemblyStorageMap;          //0x0300
    PVOID                           SystemDefaultActivationContextData; //0x0308
    PVOID                           SystemAssemblyStorageMap;           //0x0310
    PVOID                           MinimumStackCommit;                 //0x0318

} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;


__kernel_entry NTSTATUS NtQueryInformationProcess(
    _In_            HANDLE           ProcessHandle,
    _In_            PROCESSINFOCLASS ProcessInformationClass,
    _Out_           PVOID            ProcessInformation,
    _In_            ULONG            ProcessInformationLength,
    _Out_opt_       PULONG           ReturnLength
);
