#include <stdio.h>
#include <Windows.h>

DWORD hash_key(char* key)
{
    DWORD hash = 0;
    while (*key) {
        hash = (hash << 5) + hash + *key++;
    }
    return hash;
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        printf("Usage: %s <API Name>\n", argv[0]);
    }
    else {
        printf("#define HASH_%s %0#.8x\n", argv[1], hash_key(argv[1]));
    }
    return 0;
}
