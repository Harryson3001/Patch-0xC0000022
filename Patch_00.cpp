#include "patch.h"
#include <cstdio>

int main() {
    if (!AtivarSeDebugPrivilege()) {
        system("pause");
        return 1;
    }

    DWORD pid = ObterPidServico(L"SysMain");
    if (!pid) {
        system("pause");
        return 1;
    }

    void* endereco = ObterNtCreateFileRemoto(pid);
    if (!endereco) {
        system("pause");
        return 1;
    }

    printf("\n Voce Deseja Aplicar Um Patch No Endereco %p ? (s/n): ", endereco);
    char op = 'n';
    scanf_s(" %c", &op, 1);

    if (op != 's' && op != 'S') {
        printf("\n [-] Operacao cancelada pelo usuario.\n");
        system("pause");
        return 0;
    }

    printf("\n[+] Aplicando patch...\n");
    if (AplicarPatchNtCreateFile(pid, endereco)) {
        printf("\n [+] NtCreateFile no SysMain agora sempre retorna STATUS_ACCESS_DENIED (0xC0000022)\n");
    }
    else {
        printf("\n[-] Falha critica ao aplicar o patch.\n");
    }

    printf("\n");
    system("pause");
    return 0;
}