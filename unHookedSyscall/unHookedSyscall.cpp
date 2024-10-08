#include <iostream>
#include <Windows.h>

bool IsHookedFunction(PVOID functionAddress)
{
    // Syscall stubs start with these bytes in ntdll
    unsigned char syscallPrologue[4] = { 0x4c, 0x8b, 0xd1, 0xb8 };

    // Check if the first few bytes match the expected prologue
    if (memcmp(functionAddress, syscallPrologue, sizeof(syscallPrologue)) == 0)
    {
        return false; // Function is not hooked, matches syscall stub
    }

    // If it's a JMP instruction, likely a hook
    if (*(unsigned char*)functionAddress == 0xE9 || *(unsigned char*)functionAddress == 0xE8)
    {
        return true; // Function appears to be hooked
    }

    return true; // If it doesn't match the prologue or has an unexpected instruction, it's potentially hooked
}

int main()
{
    PDWORD functionAddress = nullptr;

    // Get ntdll base address
    HMODULE libraryBase = LoadLibraryA("ntdll");

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

    // Locate export address table
    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

    // Offsets to list of exported functions and their names
    PDWORD addressOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

    // Iterate through exported functions of ntdll
    for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++)
    {
        // Resolve exported function name
        DWORD functionNameRVA = addressOfNamesRVA[i];
        DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
        char* functionName = (char*)functionNameVA;

        // Resolve exported function address
        DWORD_PTR functionAddressRVA = addressOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
        functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);

        // Only interested in Nt|Zw functions
        if (strncmp(functionName, "Nt", 2) == 0 || strncmp(functionName, "Zw", 2) == 0)
        {
            if (IsHookedFunction(functionAddress))
            {
                printf("Hooked or modified: %s : %p\n", functionName, functionAddress);
            }
            else
            {
                printf("Not hooked: %s : %p\n", functionName, functionAddress);
            }
        }
    }

    return 0;
}
