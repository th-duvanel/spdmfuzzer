# Aplicação da Técnica Fuzzing em Testes da Implementação de Referência do SPDM

Esse README foi feito para o WTICG para o SBSeg 2024. Caso deseje ler o README original, acesse a branch main ou a branch dev, que possuem versões mais atualizadas e destinadas ao fim de utilização e facilidade. Nesse caso, o foco é a reprodutibilidade de experimentos e facilidade de explicação com foco em um artigo científico, além dos experimentos relatados no próprio artigo científico.

## Resumo
Testes automatizados realizados durante o desenvolvimento de software são capazes de encontrar falhas antecipadamente, evitando vulnerabilidades que vão desde negação de serviço até escalada de privilégios. Em particular, esses testes automatizados podem ser realizados usando a técnica fuzzing, que coordena o envio de entradas inesperadas para o software sendo testado. Este artigo apresenta os resultados preliminares do spdmfuzzer, um fuzzer que vem sendo desenvolvido para testar a implementação de referência do protocolo SPDM, um protocolo voltado para autenticação de hardware e firmware. Na sua versão atual disponível publicamente, o spdmfuzzer já foi capaz de encontrar comportamentos inesperados na implementação.

## O fuzzer

O ``spdmfuzzer``é um fuzzer por gramática orientado a objetos que assume o papel de ``Responder``em uma comunicação a partir do protocolo SPDM. Seu objetivo é enviar mensagens semi-aleatórias para o ``Requester`` de forma a explorar respostas inesperadas para análise.

O binário automaticamente inicia o ``Requester``, já que a comunicação pode ser encerrada em certos momentos caso o ``Requester``não tenha achado a mensagem recebida favorável à continuidade da comunicação. Para isso funcionar, é necessário que todos as pastas e arquivos sejam mantido da maneira que estão organizadas no repositório.

Como o desejado é reproduzir os experimentos, mesmo que o fuzzer não seja determinístico já que temos o fator aleatório na criação de pacotes, este fuzzer está limitado a gerar mensagens VERSION, nas quais são suportadas para recebimento pelo ``Requester``em questão, logo, não haverá muita diferença no tamanho do VERSION mas sim em seu conteúdo.

Os passos seguidos pelo fuzzer serão os seguintes: recebe o GET_VERSION, cria um VERSION e responde. Caso seja recusado, o ``Requester``encerra a conexão e o fuzzer inicia outro ``Requester``, caso contrário, ele atesta que a mensagem foi aceita e começa a enviar mensagens mockadas (que futuramente serão substituídas por mensagens fuzzificadas). Essa conexão perdura até a checagem de certificados.

## Compilação e execução

Recomendamos fortemente que utilize o ``spdm-wid`` listado na seção de Projetos Relacinandos abaixo, que é um dissecador para entender os pacotes no tcpdump ou Wireshark.

Vale ressaltar que o fuzzer envia mensagens de forma individual (header, command, buffer, size), então, talvez haja diferença no envio dependendo da forma que o protocolo TCP resolva unir os pacotes enviados em um só, deixando o ``spdm-wid`` difícil de se utilizar pois os bytes não são formatados exatamente como em uma comunicação real, já que se trata de uma emulação, com erros como falta de tamanho, etc. Caso isso aconteça, basta executá-lo novamente ou esperar para outro pacote bem montado surgir.

Basta colocar o filtro de pacotes:
```
tcp.port == 2323 && tcp.flags.push == 1
```

Aqui é possível seguir dois caminhos:
1. Compilar na sua própria máquina
2. Compilar automaticamente em contêiner docker

### Compilar na sua própria máquina

Caso a instalação de bibliotecas e dependências não seja um problema para você, sinta-se livre para instalar localmente em sua máquina. Não será necessário executar nada com privilégios elevados, apenas dar permissão de execução ao bash script.

Ele vai executar e checar algumas dependências em seu sistema (não são muitas), listar e pedir para instalar. Para não ter necessidade de executar sudo com um script, ele não instala automaticamente.

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

Essa forma é mais automática, com menos passos e mais visualização. Além de ser instalado e executado em um ambiente virtual, será gerado um .pcap para estudo dos pacotes trocados automaticamente, diferente do passo anterior, que necessita que seja executado o sniffer de forma manual.

```console
foo@spdmfuzzer:~$ docker build -t spdmfuzzer .      # montar a imagem

foo@spdmfuzzer:~$ docker run -ti spdmfuzzer         # executá-la por meio do contêiner
```

O fuzzer vai rodar automaticamente e não vai parar até que você dê ctrl+c. Logo após você dar ctrl+c, o contêiner será fechado. Nos arquivos do contêiner, terá um .pcap coletado com TODOS os pacotes trocados. Para recuperá-lo, basta:

```console
foo@spdmfuzzer:~$ docker ps -a   # para capturar o id do container
CONTAINER ID        IMAGE        NAMES      ...
<container-id>      spdmfuzzer   <name>     ...

foo@spdmfuzzer:~$ docker cp <container-id>:/home/spdmfuzzer/spdmfuzzer.pcapng .     # copiar o .pcapng na pasta atual
```
Ao aplicar esse .pcap no Wireshark, você terá a visualização completa de troca de pacotes. Recomenda-se novamente usar o ``spdm-wid``e o filtro de pacotes listado acima para melhor visualização.

## Execução (ajuda)

O ``spdmfuzzer``possui algumas funções passadas por argumento de linha de comando. Uma delas é, quando você encontra uma resposta inesperada, ele pode aguardar alguns segundos para o utilizador observar o que aconteceu. Por padrão, é usado 3 segundos. Para setar a flag, basta:

```
foo@spdmfuzzer:~$ ./spdmfuzzer -t <tempo(s)>
```

## Especificações usadas

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



