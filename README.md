# Aplicação da Técnica Fuzzing em Testes da Implementação de Referência do SPDM

Esse README foi feito para o WTICG do SBSeg 2024. Caso deseje ler o README original, acesse a branch main ou a branch dev, que possuem versões atualizadas constantemente. Nesse caso, o foco é a reprodutibilidade de experimentos e facilidade de explicação com foco em um artigo científico, além dos experimentos relatados no próprio artigo científico.

## Resumo
Testes automatizados realizados durante o desenvolvimento de software podem encontrar falhas antecipadamente, evitando vulnerabilidades que vão desde negação de serviço até escalada de privilégios. Em particular, esses testes automatizados podem ser realizados usando a técnica fuzzing, que coordena o envio de entradas inesperadas para o software sendo testado. Este artigo apresenta os resultados preliminares do spdmfuzzer, um fuzzer que vem sendo desenvolvido para testar a implementação de referência do Security Protocols and Data Models (SPDM), um protocolo voltado para atestação de hardware e firmware. Na sua versão atual disponível publicamente, o spdmfuzzer já foi capaz de encontrar comportamentos inesperados na implementação. 

## O fuzzer

O ``spdmfuzzer``é um fuzzer baseado em gramática orientado a objetos que assume o papel de ``Responder``em uma comunicação do protocolo SPDM. Seu objetivo é enviar mensagens semi-aleatórias para o ``Requester`` de forma a explorar respostas inesperadas para análise.

O binário automaticamente inicia o ``Requester``, já que a comunicação pode ser encerrada em certos momentos caso o ``Requester``não tenha achado a mensagem recebida favorável à continuidade da comunicação. Para isso funcionar, é necessário que todos as pastas e arquivos sejam mantidos da maneira que estão organizadas no repositório.

Como o desejado é reproduzir os experimentos, mesmo que o fuzzer não seja determinístico já que temos o fator aleatório na criação de pacotes, este fuzzer está limitado a gerar mensagens VERSION, as quais são suportadas para recebimento pelo ``Requester``em questão. Logo, não haverá muita diferença no tamanho do VERSION mas sim em seu conteúdo.

Os passos seguidos pelo fuzzer serão os seguintes: recebe o GET_VERSION, cria um VERSION e responde. Caso seja recusado, o ``Requester``encerra a conexão e o fuzzer inicia outro ``Requester``, caso contrário, ele atesta que a mensagem foi aceita e começa a enviar mensagens mockadas (que futuramente serão substituídas por mensagens fuzzificadas). Essa conexão perdura até a checagem de certificados.

## Compilação e execução

**A partir de agora, é considerado que você possua um sistema Linux bem atualizado. De preferência, uma distribuição com gerenciador de pacotes apt**

Recomendamos fortemente que utilize o ``spdm-wid`` listado na seção de Projetos Relacionados abaixo, que é um dissecador para entender os pacotes no tcpdump ou Wireshark.

Vale ressaltar que o fuzzer envia mensagens de forma individual (header, command, buffer, size), então, talvez haja diferença no envio dependendo da forma que o protocolo TCP resolva unir os pacotes enviados em um só, deixando o ``spdm-wid`` difícil de se utilizar pois os bytes não são formatados exatamente como em uma comunicação real, já que se trata de uma emulação, com erros como falta de tamanho, etc. Caso isso aconteça, basta executá-lo novamente ou esperar para outro pacote bem montado surgir.

Basta colocar o filtro de pacotes:
```
tcp.port == 2323 && tcp.flags.push == 1
```

Aqui é possível seguir dois caminhos:
1. Compilar na sua própria máquina
2. Compilar automaticamente em contêiner docker

Independente do processo, é necessário clonar o repositório e acessar a branch correta. Para isso, basta:
```console
foo@<pasta-atual>: ~$ git clone https://github.com/th-duvanel/spdmfuzzer.git
    https://github.com/th-duvanel/spdmfuzzer.git
foo@<pasta-atual>: ~$ cd spdmfuzzer
foo@spdmfuzzer: ~$ git checkout sbseg24
    Branch 'sbseg24' set up to track remote branch 'sbseg24' from 'origin'.
    Switched to a new branch 'sbseg24'
```
Agora você pode escolher um dos caminhos descritos acima. 
**Atenção para a branch de acesso, é muito importante que você esteja na branch ``sbseg24``.**

### Compilar na sua própria máquina

Caso a instalação de bibliotecas e dependências não seja um problema para você, sinta-se livre para instalar localmente em sua máquina. Não será necessário executar nada com privilégios elevados, apenas dar permissão de execução ao bash script.

Ele vai executar e checar algumas dependências em seu sistema (não são muitas), listar e pedir para instalar. Para não ter necessidade de executar sudo com um script, ele não instala automaticamente. Caso não deseje executar o script, abaixo estão as dependências necessárias e suas versões.

Não é necessário seguir a versão específica utilizada. De preferência utilize a versão mais recente que o gerenciador de pacotes do seu sistema possui ou utilize o tutorial automatizado em contêiner.

```
g++ 11.4.0
gawk 5.1.0
tar 1.34
gcc 11.4.0
git 2.34.1
wget 1.21.2
make 4.3
cmake 3.22.1
moreutils 0.66-1 # sponge
xz-utils 5.2.5
```

Para isso, basta executar na pasta atual:
```console
foo@spdmfuzzer:~$ sudo +x compile.sh

foo@spdmfuzzer:~$ ./compile.sh
```
Se quiser acompanhar a troca de mensagens, execute seu sniffer de preferência agora (de preferência com o ``spdm-wid``).

Para executar, basta:
```console
foo@spdmfuzzer:~$ ./spdmfuzzer
```

Todas as informações necessárias para entendimento serão exibidas em seu terminal.

### Compilar automaticamente em contêiner docker

**A depêndencia mais importante nesse caso é possuir o ``docker`` instalado em seu sistema**

Essa forma é mais automática, com menos passos e mais visualização. Além de ser instalado e executado em um ambiente virtual, será gerado um .pcapng para estudo dos pacotes trocados automaticamente, diferente do passo anterior, que necessita que seja executado o sniffer de forma manual.

```console
foo@spdmfuzzer:~$ docker build -t spdmfuzzer .      # montar a imagem

foo@spdmfuzzer:~$ docker run -ti spdmfuzzer         # executá-la por meio do contêiner
```

O fuzzer vai rodar automaticamente e não vai parar até que você pressione ctrl e c. Após pressionar ambas teclas, o contêiner será fechado. Nos arquivos do contêiner, terá um .pcapng coletado com todos os pacotes trocados. Para recuperá-lo, basta:

```console
foo@spdmfuzzer:~$ docker ps -a   # para capturar o id do contêiner
container ID        IMAGE        NAMES      ...
<container-id>      spdmfuzzer   <name>     ...

foo@spdmfuzzer:~$ docker cp <container-id>:/home/spdmfuzzer/spdmfuzzer.pcapng .     # copiar o .pcapng na pasta atual
```
Ao aplicar esse .pcapng no Wireshark, você terá a visualização completa da troca de pacotes. Recomenda-se novamente usar o ``spdm-wid``e o filtro de pacotes listado acima para melhor visualização.

## Execução (ajuda)

O ``spdmfuzzer``possui algumas funções passadas por argumento de linha de comando. Uma delas é, quando você encontra uma resposta inesperada, ele pode aguardar alguns segundos para o utilizador observar o que aconteceu. Por padrão, é usado 3 segundos. Para setar a flag, basta:

```console
foo@spdmfuzzer:~$ ./spdmfuzzer -t <tempo(s)>
```
### Exemplo

```console
foo@spdmfuzzer:~$ ./spdmfuzzer
# [+] => Responder (server) listening on port 2323
# [+] => Requester (client) started in the background
# [+] => Requester (client) connected

# [+] => Received command: 00 00 00 01 
# [+] => Received transport type: 00 00 00 01 
# [+] => Received buffer size: 00 00 00 05 
# [+] => Received buffer: 05 10 84 00 00 

# [+] => Sent command: 00 00 00 01 
# [+] => Sent transport type: 00 00 00 01 
# [+] => Sent buffer size: 00 00 00 0b 
# [+] => Sent buffer: 05 50 04 00 05 00 02 07 b7 0c 65 

# [+] => Received command: 00 00 00 01 
# [+] => Received transport type: 00 00 00 01 
# [+] => Received buffer size: 00 00 00 05 
# [+] => Received buffer: 05 10 e1 00 00 
# [+] => wow! this is not expected.
```

Nessa execução, é possível observar que o fuzzer recebeu uma resposta inesperada. Como não foi informada nenhuma flag de tempo, a cada resposta inesperada são dados 3 segundos para o usuário observar a resposta inesperada.

## Geração de Documentação
São necessárias duas dependências para visualização completa:
```console
doxygen
graphviz
```

Esse repositório tem suporte à documentação a partir do doxygen. Caso deseje, basta executar:
```console
foo@spdmfuzzer:~$ make doxygen
```

Acesse o ``index.html`` em seu navegador dentro da pasta ``doxygen`` que toda documentação estará disponível. Caso deseje, é possível acessá-la em latex também. Vale ressaltar que a documentação está em inglês.

## Especificações do ambiente utilizado
```console
OS: Ubuntu 22.04.4 LTS x86_64
Kernel: 6.5.0-41-generic
Shell: zsh 5.8.1
CPU: AMD Ryzen 7 5800H with Radeon Graphics (16) @ 4.463GHz 
GPU: AMD ATI 05:00.0 Cezanne 
GPU: NVIDIA GeForce RTX 3060 Mobile / Max-Q 
Memory: 15328MiB 
```

## Projetos relacionados
* **SPDM-WID** - [GitHub](https://github.com/th-duvanel/spdm-wid)
* **RISCV-SPDM** - [GitHub](https://github.com/th-duvanel/riscv-spdm)
* **TLS fuzzers for SPDM** - [GitHub](https://github.com/th-duvanel/fuzzer-tests)

## Autor

* **Thiago Duvanel Ferreira** - [Linkedin](https://www.linkedin.com/in/thiago-duvanel-ferreira-142028244/) - [GitHub](https://github.com/th-duvanel)
