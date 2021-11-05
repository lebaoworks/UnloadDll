// surgeon.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#pragma comment(linker,"/defaultlib:winternl.lib")
#pragma warning(error:0144)

#include <windows.h>
#include <iostream>
//#include "nt.h"
using namespace std;


string GetLastErrorAsString()
{
    DWORD errorMessageID = GetLastError();
    if (errorMessageID == 0) {
        return NULL;
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



PVOID get_func(char* module_name, char* func_name)
{
    HMODULE hModule = LoadLibraryA(module_name);
    if (hModule == NULL)
        return NULL;
    return GetProcAddress(hModule, func_name);
}
int main()
{
    DWORD iPID;
    printf("Input PID: ");
    scanf_s("%d", &iPID);
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, false, iPID);
    if (hProcess == NULL)
        ExitError();


    NTSTATUS(*hello)(void) = get_func((char*)"ntdll.dll", (char*)"ZwQueryInformationProcess");
    

    cout << "Open Process Success" << endl;
    return 0;
    
}
