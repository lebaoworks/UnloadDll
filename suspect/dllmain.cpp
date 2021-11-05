// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include <thread>

DWORD WINAPI suspect_func(__in  LPVOID lpParameter)
{
    while (true)
    {
        std::cout << "Do I look suspect?" << std::endl;
        Sleep(1000);
    }
    return 0;
}

int pa_count = 0;
int ta_count = 0;
int pd_count = 0;
int td_count = 0;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        printf("[PID: %d][TID: %d] PROCESS_ATTACH -> %d\n", GetCurrentProcessId(), GetCurrentThreadId(), ++pa_count);
        CreateThread(NULL, 0, suspect_func, NULL, 0, NULL);
        break; }
    case DLL_PROCESS_DETACH:
        printf("[PID: %d][TID: %d] PROCESS_DETACH -> %d\n", GetCurrentProcessId(), GetCurrentThreadId(), ++td_count);
        break;
    case DLL_THREAD_ATTACH:
        printf("[PID: %d][TID: %d] THREAD_ATTACH -> %d\n", GetCurrentProcessId(), GetCurrentThreadId(), ++ta_count);
        break;
    case DLL_THREAD_DETACH:
        printf("[PID: %d][TID: %d] THREAD_DETACH -> %d\n", GetCurrentProcessId(), GetCurrentThreadId(), ++pd_count);
        break;
    }
    return TRUE;
}

