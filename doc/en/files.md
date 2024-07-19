# Files folder

The ``files``folder is an important part of ``spdmfuzzer`` because it has all the necessary files for ``openspdm`` and fuzzer's automatic compilation.

You can check the explanation between these files in the ``compile.sh``script that has comments in each ``mv``or ``cp``commands executed.

## openspdm folder
It has all the ``openspdm``emulation and test files. Since we are checking a old version, there are some expired certificates necessary for authentication. Besides that, the original version that we are testing doesn't have a well designed emulation, so, these files are part from a newer emulation, which has backwards compability.

## spdm-wid
The SPDM dissector written by me. You can check it on [spdm-wid](https://github.com/th-duvanel/spdm-wid).