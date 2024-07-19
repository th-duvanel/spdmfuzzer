# Pasta files

A pasta ``files`` é uma parte importante do ``spdmfuzzer`` porque contém todos os arquivos necessários para a compilação automática do ``openspdm`` e do fuzzer.

Você pode verificar a explicação sobre tais arquivos no script ``compile.sh`` que possui comentários em cada comando ``mv`` ou ``cp`` executado.

## Pasta openspdm
Ela contém todos os arquivos de emulação e teste do ``openspdm``. Como estamos verificando uma versão antiga, há alguns certificados expirados necessários para a autenticação. Além disso, a versão original que estamos testando não possui uma emulação bem projetada (sem compatibilidade com versões atuais), então, esses arquivos são parte de uma emulação mais recente, que possui compatibilidade com versões antigas.

## spdm-wid
O dissociador SPDM escrito por mim. Você pode verificá-lo em [spdm-wid](https://github.com/th-duvanel/spdm-wid).
