// PEB http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html
// LDR http://sandsprite.com/CodeStuff/Understanding_the_Peb_Loader_Data_List.html

#undef UNICODE
#undef _UNICODE_

#include "windows.h"
#include <iostream>

using namespace std;
#include "dllhelper.h"
#include "ntdll.h"
#include "tebpeb64.h"


string GetLastErrorAsString()
{
    DWORD errorMessageID = GetLastError();
    if (errorMessageID == 0) {
        return string("");
    }

    LPSTR messageBuffer = NULL;
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    string message(messageBuffer, size);
    LocalFree(messageBuffer);
    return message;
}
void ExitError()
{
    cout << "[!] Err: " << GetLastErrorAsString() << endl;
    ExitProcess(1);
}


class NTDLL_API{
    DllHelper _dll{ "NtDLL.dll" };

public:
    decltype(NtQueryInformationProcess)* _NtQueryInformationProcess = _dll["NtQueryInformationProcess"];
};

int main()
{
    NTDLL_API NtDLL;
    DWORD PID;
    printf("Input PID: ");
    scanf_s("%d", &PID);
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, PID);
    if (hProcess == NULL)
        ExitError();

    // Query PEB address
    PROCESS_BASIC_INFORMATION pbi;
    DWORD outLength = 0;
    printf("Getting PEB addr... ");
    if (NtDLL._NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &outLength
    ) != 0)
        ExitError();
    printf("=> %p\n", pbi.PebBaseAddress);

    // Read PEB
    SIZE_T size;
    PEB peb;
    printf("Reading PEB... ");
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &size))
        ExitError();
    printf("=> Done.\n");

    // Read Loaded DLLs
    // Read LDR
    printf("Reading LDR in (%p)... ", peb.Ldr);
    PEB_LDR_DATA ldr;
    if (!ReadProcessMemory(hProcess, (LPCVOID) peb.Ldr, &ldr, sizeof(ldr), &size))
        ExitError();
    printf("=> Length: %d, Init: %d\n", ldr.Length, ldr.Initialized);
    // Read LDR entries
    PVOID pointer = ldr.InMemoryOrderModuleList.Flink;
    LDR_DATA_TABLE_ENTRY entry;
    do {
        if (!ReadProcessMemory(hProcess, pointer, &entry, sizeof(entry), &size))
            ExitError();
        printf("Module_base: %p\n", entry.DllBase);
    } while (pointer != NULL);
    return 0;
    
}
