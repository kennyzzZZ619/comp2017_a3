#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sha256.h" // Make sure to include the correct path to your sha256.h

#define SHA256_BFLEN (1024)

// Function to calculate SHA256 hash for a given file
void calculate_file_hash(const char *filename, char *output_hash) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    struct sha256_compute_data cdata = {0};
    sha256_compute_data_init(&cdata);

    char buf[SHA256_BFLEN];
    size_t nbytes;
    uint8_t hashout[SHA256_INT_SZ];
    char final_hash[SHA256_HEXLEN + 1] = {0};

    while ((nbytes = fread(buf, 1, SHA256_BFLEN, file)) == SHA256_BFLEN) {
        sha256_update(&cdata, buf, SHA256_BFLEN);
    }

    sha256_update(&cdata, buf, nbytes);
    sha256_finalize(&cdata, hashout);
    sha256_output_hex(&cdata, final_hash);

    strcpy(output_hash, final_hash);

    fclose(file);
}

int main() {
    char *bpkg_filename = "file1.bpkg";
    char *data_filename = "file1.data";
    bpkg_obj *obj = bpkg_load(bpkg_filename);
    if (!obj) {
        fprintf(stderr, "Failed to load bpkg file.\n");
        return -1;
    }

    char **computed_hashes = malloc(obj->nchunks * sizeof(char *));
    if (!computed_hashes) {
        fprintf(stderr, "Failed to allocate hashes.\n");
        return -1;
    }

    for (int i = 0; i < obj->nchunks; i++) {
        fseek(data_file, obj->chunks[i].offset, SEEK_SET);
        char *data_chunk = malloc(obj->chunks[i].size);
        fread(data_chunk, 1, obj->chunks[i].size, data_file);

        char computed_hash[SHA256_HEXLEN];
        calculate_file_hash(data_filename, computed_hash);
        computed_hashes[i] = strdup(computed_hash);

        free(data_chunk);
    }
    fclose(data_file);

    struct merkle_tree_node *root = build_merkle_tree(obj, computed_hashes);
    if (!root) {
        fprintf(stderr, "Failed to build Merkle tree.\n");
        return -1;
    }

    for (int i = 0; i < obj->nhashes; i++) {
        printf("Expected hash: %s\n", obj->hashes[i]);
    }

    free_tree(root);
    free(computed_hashes);
    return 0;
}
