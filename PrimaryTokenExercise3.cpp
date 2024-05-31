#include <windows.h>
#include <iostream>
#include <string>
#include <psapi.h>

// Link with the necessary libraries
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

// Function to enable a specific privilege for a given token
bool EnablePrivilege(HANDLE tokenHandle, LPCTSTR privilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    // Lookup the LUID for the specified privilege
    if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
        std::cerr << "LookupPrivilegeValue error: " << GetLastError() << std::endl;
        return false;
    }

    // Set up the TOKEN_PRIVILEGES structure
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Adjust the token privileges to enable the specified privilege
    if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges error: " << GetLastError() << std::endl;
        return false;
    }

    // Check if the privilege adjustment was successful
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "The token does not have the specified privilege." << std::endl;
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    // Check if the correct number of arguments is provided
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <PID>" << std::endl;
        return 1;
    }

    // Convert the argument to a PID (Process ID)
    DWORD targetPID = std::stoul(argv[1]);

    HANDLE tokenHandle = NULL;
    HANDLE duplicateTokenHandle = NULL;
    STARTUPINFOW startupInfo;
    PROCESS_INFORMATION processInfo;
    WCHAR executablePath[MAX_PATH];

    // Open the target process
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (processHandle == NULL) {
        std::cerr << "Failed to open process with PID " << targetPID << " - Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Get the executable path of the target process
    if (!GetModuleFileNameExW(processHandle, NULL, executablePath, MAX_PATH)) {
        std::cerr << "Failed to get executable path - Error: " << GetLastError() << std::endl;
        CloseHandle(processHandle);
        return 1;
    }

    // Get a handle to the access token of the target process
    if (!OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle)) {
        std::cerr << "Failed to open process token - Error: " << GetLastError() << std::endl;
        CloseHandle(processHandle);
        return 1;
    }

    // Duplicate the access token
    if (!DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle)) {
        std::cerr << "Failed to duplicate token - Error: " << GetLastError() << std::endl;
        CloseHandle(tokenHandle);
        CloseHandle(processHandle);
        return 1;
    }

    // Enable SeDebugPrivilege in the duplicated token
    if (!EnablePrivilege(duplicateTokenHandle, SE_DEBUG_NAME)) {
        std::cerr << "Failed to enable SeDebugPrivilege - Error: " << GetLastError() << std::endl;
        CloseHandle(duplicateTokenHandle);
        CloseHandle(tokenHandle);
        CloseHandle(processHandle);
        return 1;
    }

    // Initialize the STARTUPINFOW structure
    ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
    ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
    startupInfo.cb = sizeof(STARTUPINFOW);

    // Create a new process with the duplicated access token
    if (!CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, NULL, executablePath, CREATE_NEW_CONSOLE, NULL, NULL, &startupInfo, &processInfo)) {
        std::cerr << "Failed to create process with token - Error: " << GetLastError() << std::endl;
        CloseHandle(duplicateTokenHandle);
        CloseHandle(tokenHandle);
        CloseHandle(processHandle);
        return 1;
    }

    // Wait for the new process to exit
    WaitForSingleObject(processInfo.hProcess, INFINITE);

    // Clean up handles
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);
    CloseHandle(duplicateTokenHandle);
    CloseHandle(tokenHandle);
    CloseHandle(processHandle);

    return 0;
}

