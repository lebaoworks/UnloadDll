#pragma once

#include <windows.h>
#include <windef.h>
#include <winnt.h>

#include "ntdef.h"
//#include <ntdef.h>
// 
//
// [TEB/PEB UNDER 64-BIT WINDOWS]
// This file represents the 64-bit PEB and associated data structures for 64-bit Windows
// This PEB is allegedly valid between XP thru [at least] Windows 8
//
// [REFERENCES]
//      http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_x64.html
//      http://terminus.rewolf.pl/terminus/structures/ntdll/_TEB64_x86.html
//      https://github.com/giampaolo/psutil/commit/babd2b73538fcb6f3931f0ab6d9c100df6f37bcb     (RTL_USER_PROCESS_PARAMETERS)
//      https://redplait.blogspot.com/2011/09/w8-64bit-teb-peb.html                             (TEB)
//
// [CHANGELIST]
//    2018-05-02:   -now can be compiled alongside windows.h (without changes) or by defining WANT_ALL_WINDOWS_H_DEFINITIONS so this file can be used standalone
//                  -this file may also be included alongside tebpeb32.h which can be found at http://bytepointer.com/resources/tebpeb32.h
//                  -64-bit types no longer clash with the 32-bit ones; e.g. UNICODE_STRING64, RTL_USER_PROCESS_PARAMETERS64, PEB64 (same result whether 32 or 64-bit compiler is used)
//                  -added more QWORD aliases (i.e. HANDLE64 and PTR64) so underlying types are clearer, however most PEB members remain generic QWORD placeholders for now
//                  -fixed missing semicolon bug in UNICODE_STRING64
//                  -added prliminary RTL_USER_PROCESS_PARAMETERS64 and TEB64 with offsets
//                  -included byte offsets for PEB64
//
//    2017-08-25:   initial public release
//


//
// PEB64 structure - TODO: comb more through http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_x64.html and add OS delineations and Windows 10 updates
//
// The structure represented here is a work-in-progress as only members thru offset 0x320 are listed; the actual sizes per OS are:
//    0x0358    XP/WS03
//    0x0368    Vista
//    0x037C    Windows 7
//    0x0388    Windows 8
//    0x07A0    Windows 10
//

//
////
//// TEB64 structure - preliminary structure; the portion listed current at least as of Windows 8
////
//typedef struct TEB64
//{
//    BYTE                            NtTib[56];                          //0x0000 / NT_TIB64 structure
//    PTR64                           EnvironmentPointer;                 //0x0038
//    CLIENT_ID64                     ClientId;                           //0x0040
//    PTR64                           ActiveRpcHandle;                    //0x0050
//    PTR64                           ThreadLocalStoragePointer;          //0x0058
//    PTR64                           ProcessEnvironmentBlock;            //0x0060 / ptr to PEB64
//    DWORD                           LastErrorValue;                     //0x0068
//    DWORD                           CountOfOwnedCriticalSections;       //0x006C
//    PTR64                           CsrClientThread;                    //0x0070
//    PTR64                           Win32ThreadInfo;                    //0x0078
//    DWORD                           User32Reserved[26];                 //0x0080
//    DWORD                           UserReserved[6];                    //0x00E8
//    PTR64                           WOW32Reserved;                      //0x0100
//    DWORD                           CurrentLocale;                      //0x0108
//    DWORD                           FpSoftwareStatusRegister;           //0x010C
//    PTR64                           SystemReserved1[54];                //0x0110
//    DWORD                           ExceptionCode;                      //0x02C0
//    PTR64                           ActivationContextStackPointer;      //0x02C8
//
//} TEB, * PTEB;; //struct TEB64
