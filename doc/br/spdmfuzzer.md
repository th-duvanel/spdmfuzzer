# spdmfuzzer

Nesse documento você pode encontrar mais detalhes técnicos sobre o ``spdmfuzzer``.

## Campanha de fuzzing
É possível alterar a campanha de fuzzer facilmente, basta alterar a main do programa e o fuzzing.cpp, que é o kernel do fuzzer. Futuramente, novas funcionalidades serão implementadas com o objetivo de facilitar essa alteração. O objetivo final é fazer com que o fuzzer seja totalmente modular apenas mudando argumentos de funções na main, ou, talvez, entradas de terminal.

Mais detalhes serão colocados na documentação futuramente para facilitar a alteração da campanha facilmente.

## Níveis de fuzzing

Nível de fuzzing é um valor inteiro que caracteriza qual o nível de aleatoridade de um construtor, responsável por criar o pacote desejado. Para cada pacote diferente, são números diferentes. Como existem pacotes maiores e mais diversos, ele possui uma quantidade maior de nível comparado aos outros. Segue abaixo a lista de níveis de fuzzing. Originalmente, o fuzzer possui esses níveis de forma aleatorizada a cada rodada.

0 = pacote mockado (ideal, sempre aceito pelo Requester)
1 = pacote gramatical com campos aleatórios
2 = pacote gramatical com campos e tamanho adicional totalmente aleatório (NÃO UTILIZE-O COM O SPDMREQUESTER TEST).
3 = pacote gramatical com back-tracking, ou seja, a cada resposta inesperada, o pacote que enviado pelo fuzzer que teve resposta é armazenado, e é usado para avançar na conexão até que ela seja completada.


## Arquitetura
O fuzzer foi feito em C++ por ser uma linguagem orientada a objetos. Além disso, como as bibliotecas padrões do SPDM são feitas em C, é possível uma configuração para uni-las de alguma forma no futuro, talvez, quando o fuzzer for colocado em um ambiente emulado, ou seja, ele deixará de ser um binário e passará a ser uma biblioteca.

Cada pacote e cada funcionalidade é um objeto diferente, isso serviu para facilitar e construir a gramática do fuzzer.

## Gramática
A gramática, como dito anteriormente foi feita a partir de objetos. A parte mais interna dos pacotes, como bytes específicos que só podem assumir valores específicos foi feita a partir de dicionários (map em C++), inspirado no fuzzer do Luis Rodriguez, que é possível de se encontrar [aqui](https://gitfront.io/r/luisgar1990/aZXKzGjT1Wzj/mqttgram-h-repo/).

## Geração de números aleatórios
Foi utilizada uma biblioteca do C++ std, que utiliza o mecanismo Marsenne Twister Engine (std::mt19937) para gerar números aleatórios, parte importante do processo de fuzzing.