// PEB http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html
// LDR http://sandsprite.com/CodeStuff/Understanding_the_Peb_Loader_Data_List.html

#undef UNICODE
#undef _UNICODE_

#include <iostream>
#include <vector>
#include <tuple>

#include <Windows.h>
#include <TlHelp32.h>

#include <stddef.h>
#include "dllhelper.h"
#include "ntdll.h"


using namespace std;


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


class NTDLL_API {
    DllHelper _dll{ "ntdll.dll" };
public:
    decltype(NtQueryInformationProcess)* _NtQueryInformationProcess = _dll["NtQueryInformationProcess"];
    decltype(NtQueryInformationThread)* _NtQueryInformationThread = _dll["NtQueryInformationThread"];
};
NTDLL_API NtDll;

vector<DWORD> GetThreadsId(DWORD PID)
{
    vector<DWORD> ret;

    THREADENTRY32 te32;
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return ret;

    te32.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(hThreadSnap, &te32))
    {
        cout << "Thread32First -> " << GetLastErrorAsString() << endl;
        CloseHandle(hThreadSnap);
        return ret;
    }

    do
    {
        if (te32.th32OwnerProcessID == PID)
            ret.push_back(te32.th32ThreadID);
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return ret;
}

vector<LDR_DATA_TABLE_ENTRY> get_modules(HANDLE hProcess)
{
    vector< LDR_DATA_TABLE_ENTRY> ret;

    // Query PEB address
    PROCESS_BASIC_INFORMATION pbi;
    DWORD outLength = 0;
    printf("Getting PEB addr... ");
    if (NtDll._NtQueryInformationProcess(
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
    if (!ReadProcessMemory(hProcess, (LPCVOID)peb.Ldr, &ldr, sizeof(ldr), &size))
        ExitError();
    // Read LDR entries
    LDR_DATA_TABLE_ENTRY module;
    PLIST_ENTRY entry = ldr.InLoadOrderModuleList.Flink;
    WCHAR* module_fullname;
    while (entry != (PVOID)((UINT64)peb.Ldr + offsetof(PEB_LDR_DATA, InLoadOrderModuleList)))
    {
        if (!ReadProcessMemory(hProcess, entry, &module, sizeof(module), &size))
            ExitError();
        printf("[+] LDR_MODULE size: %llu\tModule_base: %p\t Module_ref: %lu\n", size, module.DllBase, module.ReferenceCount);

        module_fullname = (WCHAR*)calloc(module.FullDllName.Length + 1, sizeof(WCHAR));
        if (ReadProcessMemory(hProcess, module.FullDllName.Buffer, module_fullname, module.FullDllName.Length, &size))
            wprintf(L"Module_name: %s\n", module_fullname);
        free(module_fullname);

        ret.push_back(module);
        entry = module.InLoadOrderLinks.Flink;
    }
    return ret;
}

vector<tuple<DWORD, PVOID>> get_threads(HANDLE hProcess)
{
    vector<tuple<DWORD, PVOID>> ret;
    vector<DWORD> threads_id = GetThreadsId(GetProcessId(hProcess));
    for (int i = 0; i < threads_id.size(); i++)
    {
        DWORD TID = threads_id[i];
        // Query TEB address
        HANDLE hThread= OpenThread(THREAD_QUERY_INFORMATION | THREAD_TERMINATE, false, TID);
        if (hThread == NULL)
        {
            cout << "OpenThread %i -> " << GetLastErrorAsString() << endl;
        }
        PVOID start_address;
        DWORD outLength = 0;
        printf("[Thread %d] Getting start addr... ", threads_id[i]);
        if (NtDll._NtQueryInformationThread(
            hThread,
            ThreadQuerySetWin32StartAddress,
            &start_address,
            sizeof(start_address),
            &outLength
        ) != 0)
            ExitError();
        printf("=> %p\n", start_address);
        
        ret.push_back( tuple<DWORD, PVOID>(threads_id[i], start_address) );
        CloseHandle(hThread);
    }
    return ret;
}

int main()
{
    DWORD PID;
    printf("Input PID: ");
    scanf_s("%d", &PID);
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, PID);
    if (hProcess == NULL)
        ExitError();

    vector<LDR_DATA_TABLE_ENTRY> modules = get_modules(hProcess);
    vector<tuple<DWORD, PVOID>> tebs = get_threads(hProcess);

    return 0;
    
}
