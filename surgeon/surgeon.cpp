// PEB http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html
// LDR http://sandsprite.com/CodeStuff/Understanding_the_Peb_Loader_Data_List.html

#undef UNICODE
#undef _UNICODE_

#include <iostream>
#include <vector>
#include <codecvt>

#include <Windows.h>
#include <TlHelp32.h>

#include <stddef.h>
#include "dllhelper.h"
#include "ntdll.h"


using namespace std;

#define DEBUG 1
#define debug_print(fmt, ...) do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)
#define debug_wprint(fmt, ...) do { if (DEBUG) fwprintf(stderr, fmt, __VA_ARGS__); } while (0)

string GetLastErrorAsString()
{
    DWORD errorMessageID = GetLastError();
    if (errorMessageID == 0)
        return string("");

    LPSTR messageBuffer = NULL;
    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), messageBuffer, 0, NULL);

    string message(messageBuffer, size);
    LocalFree(messageBuffer);
    return message;
}

class NTDLL_API {
    DllHelper _dll{ "ntdll.dll" };
public:
    decltype(NtQueryInformationProcess)* _NtQueryInformationProcess = _dll["NtQueryInformationProcess"];
    decltype(NtQueryInformationThread)* _NtQueryInformationThread = _dll["NtQueryInformationThread"];
};
NTDLL_API NTDLL;

typedef struct {
    wstring name;
    LDR_DATA_TABLE_ENTRY info;
} MODULE_INFO;
/*
 * @brief Get all loaded module of process
 * 
 * @param hProcess Handle to process, must have PROCESS_VM_READ and PROCESS_QUERY_INFORMATION access rights
 * 
 * @return success -> list of MODULE_INFO, which alway haves more than 3 elements: kernel32.dll, kernelbase.dll, ntdll.dll and the process image it self
 * @return failure -> empty list
 */
vector<MODULE_INFO> get_modules(HANDLE hProcess)
{
    vector<MODULE_INFO> ret;
    SIZE_T size;

    // Query PEB address
    PROCESS_BASIC_INFORMATION pbi;
    DWORD outLength = 0;
    debug_print("[*] Query PEB addr... ");
    if (NTDLL._NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi, sizeof(pbi), &outLength) != 0)
    {
        debug_print("[!] ERROR\n");
        return vector<MODULE_INFO>();
    }
    debug_print("=> Base: %p\n", pbi.PebBaseAddress);

    // Read PEB
    PEB peb;
    debug_print("[*] Read PEB... ");
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &size))
    {
        debug_print("[!] %s\n", GetLastErrorAsString().c_str());
        return vector<MODULE_INFO>();
    }
    debug_print("=> Done.\n");

    // Read LDR to get address of double-linked list to modules info
    debug_print("[*] Read LDR in (%p)... ", peb.Ldr);
    PEB_LDR_DATA ldr;
    if (!ReadProcessMemory(hProcess, (LPCVOID)peb.Ldr, &ldr, sizeof(ldr), &size))
    {
        debug_print("[!] %s\n", GetLastErrorAsString().c_str());
        return vector<MODULE_INFO>();
    }
    debug_print("\n");

    // Walk through double-linkeed list to read modules info
    LDR_DATA_TABLE_ENTRY module;
    for (
        PLIST_ENTRY entry = ldr.InLoadOrderModuleList.Flink;
        entry != (PVOID)((UINT64)peb.Ldr + offsetof(PEB_LDR_DATA, InLoadOrderModuleList)); // stop when got back to the first element
        entry = module.InLoadOrderLinks.Flink)
    {
        // Read module info
        if (!ReadProcessMemory(hProcess, entry, &module, sizeof(module), &size))
        {
            debug_print("[!] ERROR read at %p\n", entry);
            return vector<MODULE_INFO>();
        }
        
        // Read module name
        WCHAR *module_name = (WCHAR*) calloc(module.FullDllName.Length + 1, sizeof(WCHAR));
        if (!ReadProcessMemory(hProcess, module.FullDllName.Buffer, module_name, module.FullDllName.Length, &size))
        {
            debug_print("[!] ERROR read at %p\n", module.FullDllName.Buffer);
            return vector<MODULE_INFO>();
        }
        debug_wprint(L"\t[+] Module Base: %p\tSize: %lu\tModule Name: %s\n", module.DllBase, module.SizeOfImage, module_name);

        MODULE_INFO info = {wstring(module_name), module};
        ret.push_back(info);
        free(module_name);
    }
    return ret;
}

typedef struct {
    DWORD id;
    PVOID start_address;
} THREAD_INFO;
/*
 * @brief Get all threads of process
 *
 * @param hProcess Handle to process
 *
 * @return success -> list of THREAD_INFO, which alway haves at least 1 element: main thread
 * @return failure -> empty list
 */
vector<THREAD_INFO> get_threads(HANDLE hProcess)
{
    DWORD PID = GetProcessId(hProcess);

    // Snap to get list of threads
    vector<DWORD> tids;
    debug_print("[*] Snapshot... ");
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
    {
        debug_print("[!] %s\n", GetLastErrorAsString().c_str());
        return vector<THREAD_INFO>();
    }
    debug_print("=> Done.\n");

    // Walk through snapshot to get threads id
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    debug_print("[*] Walk through snapshot... ");
    if (!Thread32First(hThreadSnap, &te32))
    {
        debug_print("[!] %s\n", GetLastErrorAsString().c_str());
        CloseHandle(hThreadSnap);
        return vector<THREAD_INFO>();
    }
    do
    {
        if (te32.th32OwnerProcessID == PID)
            tids.push_back(te32.th32ThreadID);
    } while (Thread32Next(hThreadSnap, &te32));
    CloseHandle(hThreadSnap);
    debug_print("=> Done\n");

    // Query threads' start_address
    debug_print("[*] Query threads' start_address...\n");
    vector<THREAD_INFO> ret;
    for (int i = 0; i < tids.size(); i++)
    {
        DWORD TID = tids[i];
        // Query TEB address
        HANDLE hThread= OpenThread(THREAD_QUERY_INFORMATION | THREAD_TERMINATE, false, TID);
        if (hThread == NULL)
        {
            debug_print("[!] thread %lu %s\n", tids[i], GetLastErrorAsString());
            return vector<THREAD_INFO>();
        }
        PVOID start_address;
        DWORD outLength = 0;
        debug_print("\t[*] Thread %d: start_address... ", tids[i]);
        if (NTDLL._NtQueryInformationThread(
            hThread,
            ThreadQuerySetWin32StartAddress,
            &start_address, sizeof(start_address), &outLength
        ) != 0)
        {
            debug_print("[!] ERR\n");
            return vector<THREAD_INFO>();
        }
        debug_print("=> %p\n", start_address);
        
        THREAD_INFO info = { tids[i], start_address };
        ret.push_back(info);
        CloseHandle(hThread);
    }
    return ret;
}

/*
 * @brief Unload library if it is loaded in process
 * 
 * @param pid PID of target process
 * @param library_path path to library
 * 
 * @return true if library is no longer in process memory
 * @return false if library is still in process memory
 */
bool PurgeLibrary(DWORD pid, wstring library_path)
{
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ , false, pid);
    if (hProcess == NULL)
        return false;

    // First, we have to read process memory to get modules information:
    //      Module Base: as the same value as HMODULE when use LoadLibrary(), which used for FreeLibrary() later.
    //      Module Image Size: calculate module memory range, which helps detect if thread started within the module.
    vector<MODULE_INFO> modules = get_modules(hProcess);
    if (modules.empty())
        return false;
    // Check if target module is loaded
    MODULE_INFO *module = NULL;
    for (int i = 0; i < modules.size(); i++)
        if (library_path.compare(modules[i].name) == 0)
        {
            module = &modules[i];
            break;
        }
    if (module == NULL)
        return true;

    // Second, we have to get threads infomation of the process:
    //      Thread ID: parameter for TerminateThread()
    //      Thread Start Address: helps detect if thread started within the module
    vector<THREAD_INFO> threads = get_threads(hProcess);
    if (threads.empty())
        return false;

    // Third, find which thread started within the module memory, will be killed later
    vector<THREAD_INFO> threads_to_kill;
    for (int i = 0; i < threads.size(); i++)
        if (threads[i].start_address >= module->info.DllBase &&
            (ULONG_PTR) threads[i].start_address <= (ULONG_PTR) module->info.DllBase + module->info.SizeOfImage)
            threads_to_kill.push_back(threads[i]);

    // Fourth, kill the threads
    vector<HANDLE> hThreads;
    for (int i = 0; i < threads_to_kill.size(); i++)
    {
        HANDLE hThread = OpenThread(THREAD_TERMINATE, false, threads_to_kill[i].id);
        if (hThread == NULL)
        {
            for (int j = 0; j < hThreads.size(); j++)
                CloseHandle(hThreads[i]);
            return false;
        }
        hThreads.push_back(hThread);
    }
    for (int i = 0; i < hThreads.size(); i++)
    {
        debug_print("[*] Kill thread %d\n", hThreads[i]);
        TerminateThread(hThreads[i], 0);
        CloseHandle(hThreads[i]);
    }

    // Fifth, write library's entry point to return
    //      => prevent library from creating new thread on THREAD_ATTACH when we create remote thread later


    // Sixth, create remote thread to free library from process
    DWORD remotethread_pid;
    debug_print("[*] Create remote thread to FreeLibrary... ");
    HANDLE hRemoteThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)FreeLibrary,
        module->info.DllBase,
        0,
        &remotethread_pid
    );
    CloseHandle(hRemoteThread);
    debug_print("=> Done.\n");
    return true;
}

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        cout << "Usage: %s <PID> <DLL_PATH>" << endl;
        return 1;
    }

    DWORD PID = atoi(argv[1]);
    wstring_convert<codecvt_utf8<wchar_t>, wchar_t> converter;
    wstring target_dll = converter.from_bytes(argv[2]);
    
    cout << "PID: " << PID << endl;
    wcout << "DLL: " << target_dll << endl;

    printf("Purge: %d", PurgeLibrary(PID, target_dll));
    return 0;
    
}
