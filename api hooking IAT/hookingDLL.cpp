#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <iostream>
#include <winnt.h>

typedef DWORD(WINAPI* GetCurrentProcessId_t)();

DWORD ModifiedGetCurrentProcessId()
{
    return 0;
}

BOOL analyzeImportDescriptor(IMAGE_IMPORT_DESCRIPTOR importDescriptor, IMAGE_NT_HEADERS64* peHeader,
    HMODULE baseAddress, const char* nameOfAPI)
{
    IMAGE_THUNK_DATA64* thunkILT;
    IMAGE_THUNK_DATA64* thunkIAT;
    IMAGE_IMPORT_BY_NAME* nameData;

    int numberOfFuncs;
    int numberOfOrdinalFuncs;

    // declare the function ptr that will point to our own function
    // used to replace the target API specified by apiName
    DWORD(WINAPI * procPtr)();

    // gets the RVAs of OriginalFirstThunk &amp; FirstThunk
    thunkILT = (IMAGE_THUNK_DATA64*)importDescriptor.OriginalFirstThunk;
    thunkIAT = (IMAGE_THUNK_DATA64*)importDescriptor.FirstThunk;

    // in the following there is a bunch of code to check for
    // empty ILTs &amp; empty IATs
    if (thunkILT == NULL) {
        // Logging
        return false;
    }
    if (thunkIAT == NULL) {
        // Logging
        return false;
    }
    // getting lin. addr. of thunkILT
    thunkILT = (IMAGE_THUNK_DATA*)((DWORD_PTR)baseAddress + (DWORD)thunkILT);
    //std::cout << "thunk data function   is: " << thunkILT->u1.Ordinal << "\n";

    // getting lin. addr. of thunkIAT
    thunkIAT = (IMAGE_THUNK_DATA*)((DWORD_PTR)baseAddress + (DWORD)thunkIAT);

    // loop as long as RVA of imported function (u1.function) is not 0
    while (thunkILT->u1.Function)
    {
        // if the function has been imported by ordinal instead of name
        if ((thunkILT->u1.Ordinal && IMAGE_ORDINAL_FLAG))
        {
            // get the RVA of imported function's name
            nameData = (PIMAGE_IMPORT_BY_NAME)(thunkILT->u1.AddressOfData);

            // add base address to RVA of imported function's name to get the location of it
            nameData = (PIMAGE_IMPORT_BY_NAME)
                ((DWORD_PTR)baseAddress + (DWORD)nameData);
            // we compare names in descriptor's ILT against name of the fct.
             // that we want to supplant
             // if we find a match
             // then we swap in the addr. of a hook routine
            if (!strcmp(nameOfAPI, (char*)(*nameData).Name))
            {
                // Change the memory protection of the IAT to allow writing
                DWORD dwOldProtection;
                if (!VirtualProtect((LPVOID)&thunkIAT->u1.Function, sizeof(DWORD_PTR), PAGE_EXECUTE_READWRITE, &dwOldProtection))
                {
                    std::cerr << "Failed to change memory protection!" << std::endl;
                    return false;
                }
                else
                {
                    // here, the overwriting the address occurs
                    thunkIAT->u1.Function = (DWORD_PTR)ModifiedGetCurrentProcessId;
                    return true;
                }
            }
        }
        thunkILT++;
        thunkIAT++;
    } // end of while-loop
    return false;
} // end of analyzeImportDescriptor() -----------------------------------------------


BOOL parsingImports(HMODULE baseAddress, const char* nameOfAPI)
{
    IMAGE_DOS_HEADER* dosHeader;
    IMAGE_NT_HEADERS64* ntHeader;
    IMAGE_OPTIONAL_HEADER64 optionalHeader;
    IMAGE_DATA_DIRECTORY importDirectory;
    DWORD descriptorStartRVA;
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor;
    int index = 0;
    bool functionFound = false;

    // here, the sanity checks start
    dosHeader = (IMAGE_DOS_HEADER*)baseAddress;

    // Check "PE" in magic var
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {

        // Logging if you want for debugging purposes
        return false;
    }

    // check PE signature
    ntHeader = (IMAGE_NT_HEADERS64*)((BYTE*)baseAddress + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }

    optionalHeader = ntHeader->OptionalHeader;

    // Validate optional header Magic
    if (optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        return false;
    }
    // here, the sanity checks end

    // now we parse through import descriptors
    importDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    // get the RVA of the import descriptor
    descriptorStartRVA = importDirectory.VirtualAddress;
    importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(descriptorStartRVA + (DWORD_PTR)baseAddress);

    // also working: while importDescriptor[index].Name !=0
    while (importDescriptor[index].Characteristics != 0 && !functionFound)
    {
        char* nameOfDLL;
        nameOfDLL = (char*)(importDescriptor[index].Name + (DWORD_PTR)baseAddress);
        functionFound = analyzeImportDescriptor(importDescriptor[index], ntHeader, baseAddress, nameOfAPI);
        index++;
    }
}

BOOL hooking(const char* nameOfAPI) {

    HMODULE addrOfModule;
    BOOL resultOfParsing;
    // according to MSDN:
    // passing NULL to GetModuleHandle() gives us base address
    addrOfModule = GetModuleHandleA(NULL);
    resultOfParsing = parsingImports(addrOfModule, nameOfAPI);
    return resultOfParsing;
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved)  // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            bool hook = hooking("GetCurrentProcessId");

            //// For test Purposes
            //if (hook == TRUE) {
            //    // print out a msg. that the hooking has failed
            //    MessageBoxA(NULL, "success", "returned true", MB_OK);
            //}
        }
            break;
        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;

        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
