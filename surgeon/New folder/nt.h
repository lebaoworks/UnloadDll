#pragma once

#include <Windows.h>
#include <ntdef.h>

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	PVOID Handle;
} CURDIR, * PCURDIR;

typedef struct RTL_DRIVE_LETTER_CURDIR
{
	USHORT              Flags;
	USHORT              Length;
	ULONG               TimeStamp;
	UNICODE_STRING      DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG               AllocationSize;
	ULONG               Size;
	ULONG               Flags;
	ULONG               DebugFlags;
	HANDLE              ConsoleHandle;
	ULONG               ConsoleFlags;
	HANDLE              hStdInput;
	HANDLE              hStdOutput;
	HANDLE              hStdError;
	CURDIR              CurrentDirectory;
	UNICODE_STRING      DllPath;
	UNICODE_STRING      ImagePathName;
	UNICODE_STRING      CommandLine;
	PWSTR               Environment;
	ULONG               dwX;
	ULONG               dwY;
	ULONG               dwXSize;
	ULONG               dwYSize;
	ULONG               dwXCountChars;
	ULONG               dwYCountChars;
	ULONG               dwFillAttribute;
	ULONG               dwFlags;
	ULONG               wShowWindow;
	UNICODE_STRING      WindowTitle;
	UNICODE_STRING      Desktop;
	UNICODE_STRING      ShellInfo;
	UNICODE_STRING      RuntimeInfo;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
	ULONG_PTR           EnvironmentSize;
	ULONG_PTR           EnvironmentVersion;
	PVOID               PackageDependencyData;
	ULONG               ProcessGroupId;
	ULONG               LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef union _PROCESSINFOCLASS {
	PROCESS_BASIC_INFORMATION basic_info;
} PROCESSINFOCLASS;

__kernel_entry NTSTATUS NtQueryInformationProcess(
	[in]            HANDLE           ProcessHandle,
	[in]            PROCESSINFOCLASS ProcessInformationClass,
	[out]           PVOID            ProcessInformation,
	[in]            ULONG            ProcessInformationLength,
	[out, optional] PULONG           ReturnLength
);