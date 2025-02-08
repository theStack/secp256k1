#include <stdio.h>
#include <string.h>
#include "../src/hash_impl.h"

void generate_sha256_tagged_midstate_init(const char *tag)
{
    int i;
    secp256k1_sha256 sha;

    secp256k1_sha256_initialize_tagged(&sha, tag, strlen(tag));
    printf("static void secp256k1_MODULE_sha256_init_TAGGEDHASH(secp256k1_sha256 *sha) {\n");
    printf("    secp256k1_sha256_initialize(sha);\n");
    for (i=0; i<8; i++) {
        printf("    sha->s[%d] = 0x%08xul;\n", i, sha.s[i]);
    }
    printf("    sha->bytes = 64;\n");
    printf("}\n");
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: %s <tag>\n", argv[0]);
        return 1;
    }
    generate_sha256_tagged_midstate_init(argv[1]);
}
