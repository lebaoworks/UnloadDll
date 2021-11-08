#pragma once

#include <Windows.h>


//
// base types
//

//always declare 64-bit types
#ifdef _MSC_VER
    //Visual C++
typedef unsigned __int64    QWORD;
typedef __int64             INT64;
#else
    //GCC
typedef unsigned long long  QWORD;
typedef long long           INT64;
#endif
typedef QWORD                   PTR64;
typedef QWORD                   HANDLE64;

typedef struct _CLIENT_ID64
{
    QWORD  ProcessId;
    QWORD  ThreadId;
} CLIENT_ID64;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

struct UNICODE_STRING64
{
    union
    {
        struct
        {
            WORD Length;
            WORD MaximumLength;
        } u;
        QWORD dummyalign;
    };
    QWORD Buffer;
};


//NOTE: the members of this structure are not yet complete
typedef struct _RTL_USER_PROCESS_PARAMETERS64
{
    BYTE                    Reserved1[16];                 //0x00
    QWORD                   Reserved2[5];                  //0x10
    UNICODE_STRING64        CurrentDirectoryPath;          //0x38
    HANDLE64                CurrentDirectoryHandle;        //0x48
    UNICODE_STRING64        DllPath;                       //0x50 
    UNICODE_STRING64        ImagePathName;                 //0x60 
    UNICODE_STRING64        CommandLine;                   //0x70 
    PTR64                   Environment;                   //0x80
} RTL_USER_PROCESS_PARAMETERS64;