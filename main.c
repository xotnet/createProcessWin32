#include <windows.h>
#include <stdio.h>
#include <stdint.h>

typedef BOOL (WINAPI *CREATEPROCESSA)(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPVOID lpProcessAttributes,
    LPVOID lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

void secureRun(char* exePath) {
    HMODULE kernel = LoadLibrary("kernel32.dll");
    void* funcAddress = NULL;
    DWORD old;
    VirtualProtect(funcAddress, 10, PAGE_EXECUTE_WRITECOPY, &old);
    funcAddress = GetProcAddress(kernel, "CreateProcessA");
    FreeLibrary(kernel);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    ((CREATEPROCESSA)funcAddress)(exePath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}


int main() {
    uint8_t path[] = "C:\\Windows\\System32\\notepad.exe";
    secureRun(path);
}
