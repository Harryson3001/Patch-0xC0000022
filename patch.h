#pragma once
#include <windows.h>

bool AtivarSeDebugPrivilege();
DWORD ObterPidServico(const wchar_t* nomeServico);
HMODULE ObterBaseNtdllRemota(DWORD pid);
void* ObterNtCreateFileRemoto(DWORD pid);
bool AplicarPatchNtCreateFile(DWORD pid, void* enderecoRemoto);