// gullible.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <windows.h>
#include <iostream>

using namespace std;

int main()
{
    HMODULE hModule= LoadLibraryA("suspect.dll");
    if (hModule == NULL)
    {
        cout << "[!] Load library error << " << endl;
        return 1;
    }

    void (*hello)(void) = (void (*)(void)) GetProcAddress(hModule, "hello");
    if (hello == NULL)
    {
        cout << "[!] Get hello() func address fail << " << endl;
        return 1;
    }
    while (true)
    {
        hello();
        Sleep(2000);
    }
    return 0;
}
