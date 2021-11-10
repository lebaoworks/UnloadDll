// gullible.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <windows.h>
#include <iostream>
#include <string>

using namespace std;

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
    while (true)
    {
        printf("main is still here!\n");
        Sleep(2000);
    }
    return 0;
}
