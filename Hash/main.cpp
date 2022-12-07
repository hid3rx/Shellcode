#include <Windows.h>
#include <stdio.h>

DWORD HashKey(char* key) {

    DWORD nHash = 0;
    while (*key) {
        nHash = (nHash << 5) + nHash + *key++;
    }
    return nHash;
}

int main(int argc, char* argv[]) {

    if (argc != 2) {
        printf("Usage: %s <API Name>\n", argv[0]);
    }
    else {
        printf("#define HASH_%s %0#.8x\n", argv[1], HashKey(argv[1]));
    }
    return 0;
}
