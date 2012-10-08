You should be able to build this program with the following commands:

`gcc -O3 -Wall -c -fmessage-length=0 -std=c99 -o sbag.o sbag.c`
`gcc -L<path_to_openssl_libs> -static -o sbag sbag.o -lcrypto -lssl`


If I build openssl with the following options, the resulting executable is 2.0 MB (on my x64 system):

    ./config no-threads no-zlib no-shared no-asm no-bf no-cast no-des no-dh no-dsa no-md2 no-mdc2 no-rc2 no-rc4 no-rc5 -no-hw -no-dso no-krb5

