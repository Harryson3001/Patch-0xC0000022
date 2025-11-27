# Patch-0xC0000022
Patch direto no NtCreateFile do SysMain (Superfetch). Força retorno 0xC0000022 (ACCESS_DENIED) com 6 bytes, bloqueando criação de arquivos e desativando o prefetch na prática. Windows 10/11 x64. Executar como Admin. Confirma antes de aplicar. Código limpo em C++ (patch.h + patch.cpp + main). Zero dependências.
