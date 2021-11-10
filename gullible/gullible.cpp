// gullible.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <windows.h>
#include <iostream>
#include <string>

using namespace std;

string GetLastErrorAsString()
{
    DWORD errorMessageID = GetLastError();
    if (errorMessageID == 0) {
        printf("Error non!\n");
        return string("");
    }

    LPSTR messageBuffer = NULL;
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    string message(messageBuffer, size);
    LocalFree(messageBuffer);
    return message;
}

void test_loadlib(const char* name)
{
    HMODULE hModule = LoadLibraryA(name);
    if (hModule == NULL)
    {
        cout << "[!] Load library error << " << endl;
        ExitProcess(1);
    }
}

int main()
{
    test_loadlib("suspect.dll");
    HANDLE hThread;
    while (true)
    {
        printf("main is still here!\n");
        Sleep(2000);
    }
    return 0;
}
