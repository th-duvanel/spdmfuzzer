# spdmfuzzer

Nesse documento você pode encontrar mais detalhes técnicos sobre o ``spdmfuzzer``.

## Campanha de fuzzing
É possível alterar a campanha de fuzzer facilmente, basta alterar a main do programa e o fuzzing.cpp, que é o kernel do fuzzer. Futuramente, novas funcionalidades serão implementadas com o objetivo de facilitar essa alteração. O objetivo final é fazer com que o fuzzer seja totalmente modular apenas mudando argumentos de funções na main, ou, talvez, entradas de terminal.

Mais detalhes serão colocados na documentação futuramente para facilitar a alteração da campanha facilmente.

## Arquitetura
O fuzzer foi feito em C++ por ser uma linguagem orientada a objetos. Além disso, como as bibliotecas padrões do SPDM são feitas em C, é possível uma configuração para uni-las de alguma forma no futuro, talvez, quando o fuzzer for colocado em um ambiente emulado, ou seja, ele deixará de ser um binário e passará a ser uma biblioteca.

Cada pacote e cada funcionalidade é um objeto diferente, isso serviu para facilitar e construir a gramática do fuzzer.

## Gramática
A gramática, como dito anteriormente foi feita a partir de objetos. A parte mais interna dos pacotes, como bytes específicos que só podem assumir valores específicos foi feita a partir de dicionários (map em C++), inspirado no fuzzer do Luis Rodriguez, que é possível de se encontrar [aqui](https://gitfront.io/r/luisgar1990/aZXKzGjT1Wzj/mqttgram-h-repo/).

## Geração de números aleatórios
Foi utilizada uma biblioteca do C++ std, que utiliza o mecanismo Marsenne Twister Engine (std::mt19937) para gerar números aleatórios, parte importante do processo de fuzzing.