#include "patch.h"
#include <tlhelp32.h>
#include <winsvc.h>
#include <cstdio>

bool AtivarSeDebugPrivilege() {
    printf("\n [+] Ativando SeDebugPrivilege...\n");
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        printf(" [-] Falha ao abrir token do processo.\n");
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(token);
    if (!ok || GetLastError() != ERROR_SUCCESS) {
        printf(" [-] Falha ao ajustar privilegios.\n");
        return false;
    }
    printf(" [+] SeDebugPrivilege ativado com sucesso!\n");
    return true;
}

DWORD ObterPidServico(const wchar_t* nomeServico) {
    printf(" [+] Procurando PID do servico %ls...\n", nomeServico);
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        printf(" [-] Falha ao abrir o SCM (Service Control Manager).\n");
        return 0;
    }
    SC_HANDLE svc = OpenServiceW(scm, nomeServico, SERVICE_QUERY_STATUS);
    if (!svc) {
        printf(" [-] Servico %ls nao encontrado.\n", nomeServico);
        CloseServiceHandle(scm);
        return 0;
    }
    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed;
    if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed)) {
        printf(" [-] Falha ao consultar status do servico.\n");
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return 0;
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    printf(" [+] PID do SysMain: %lu\n", ssp.dwProcessId);
    return ssp.dwProcessId;
}

HMODULE ObterBaseNtdllRemota(DWORD pid) {
    printf(" [+] Procurando ntdll.dll no processo %lu...\n", pid);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        printf(" [-] Falha ao criar snapshot de modulos.\n");
        return nullptr;
    }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, L"ntdll.dll") == 0) {
                printf(" [+] ntdll.dll encontrado! Base remota: %p\n", me.hModule);
                CloseHandle(snap);
                return me.hModule;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    printf(" [-] ntdll.dll nao encontrado no processo alvo.\n");
    return nullptr;
}

void* ObterNtCreateFileRemoto(DWORD pid) {
    HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC localFunc = GetProcAddress(localNtdll, "NtCreateFile");
    if (!localFunc) {
        printf(" [-] NtCreateFile nao encontrado localmente.\n");
        return nullptr;
    }
    HMODULE remoteNtdll = ObterBaseNtdllRemota(pid);
    if (!remoteNtdll) return nullptr;

    printf(" [+] Base local ntdll.dll: %p\n", localNtdll);
    printf(" [+] NtCreateFile local: %p\n", localFunc);

    uintptr_t offset = (uintptr_t)localFunc - (uintptr_t)localNtdll;
    printf(" [+] Offset calculado: 0x%zX\n", offset);

    void* remoto = (BYTE*)remoteNtdll + offset;
    printf(" [+] Endereco remoto de NtCreateFile: %p\n", remoto);
    return remoto;
}

bool AplicarPatchNtCreateFile(DWORD pid, void* enderecoRemoto) {
    printf(" [+] Abrindo processo SysMain (PID %lu) para escrita...\n", pid);
    HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        printf(" [-] Falha ao abrir processo (acesso negado ou PID invalido).\n");
        return false;
    }

    BYTE patch[] = { 0xB8, 0x22, 0x00, 0x00, 0xC0, 0xC3 };

    DWORD oldProtect;
    if (!VirtualProtectEx(hProc, enderecoRemoto, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf(" [-] Falha ao alterar protecao de memoria.\n");
        CloseHandle(hProc);
        return false;
    }

    SIZE_T escrito;
    if (!WriteProcessMemory(hProc, enderecoRemoto, patch, sizeof(patch), &escrito) || escrito != sizeof(patch)) {
        printf(" [-] Falha ao escrever o patch na memoria remota.\n");
        VirtualProtectEx(hProc, enderecoRemoto, sizeof(patch), oldProtect, &oldProtect);
        CloseHandle(hProc);
        return false;
    }

    VirtualProtectEx(hProc, enderecoRemoto, sizeof(patch), oldProtect, &oldProtect);
    CloseHandle(hProc);
    return true;
}