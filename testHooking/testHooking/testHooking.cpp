// this program is meant to test the dll "api hooking iat.dll"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <winnt.h>

int main(int argc, char* argv[]) {
    DWORD currentProcessID;
    while (true)
    {
        currentProcessID = GetCurrentProcessId();
        printf("\nthe current process id is: %d\n", currentProcessID);
        Sleep(5000);
    }
    return 0;
}