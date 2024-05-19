#include "package.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

Package **packages = NULL;
int package_count = 0;

void clear_rest_line(FILE *file, char buffer[]) {
    if (strchr(buffer, '\n') == NULL) {
        int c;
        while ((c = fgetc(file)) != '\n' && c != EOF);
    }
}

Package *load_package(const char *path) {
    Package *pkg = malloc(sizeof(Package));
    if (pkg == NULL) {
        fprintf(stderr, "Memory allocation failed for Package\n");
        return NULL;
    }

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        perror("Failed to open file");
        free(pkg);
        return NULL;
    }

    char buffer[1025];
    memset(buffer, 0, sizeof(buffer));

    if (!fgets(buffer, sizeof(buffer), file) || buffer[5] != ':') {
        fprintf(stderr, "Failed to read identifier\n");
        fclose(file);
        free(pkg);
        return NULL;
    }
    buffer[strcspn(buffer, "\r\n")] = 0;
    strncpy(pkg->ident, buffer + 6, sizeof(pkg->ident) - 1);
    pkg->ident[sizeof(pkg->ident) - 1] = '\0';
    printf("Ident: %s\n", pkg->ident);

    clear_rest_line(file, buffer);

    if (!fgets(buffer, sizeof(buffer), file) || buffer[8] != ':') {
        fprintf(stderr, "Failed to read filename\n");
        fclose(file);
        free(pkg);
        return NULL;
    }
    buffer[strcspn(buffer, "\r\n")] = 0;
    strncpy(pkg->filename, buffer + 9, sizeof(pkg->filename) - 1);
    pkg->filename[sizeof(pkg->filename) - 1] = '\0';
    printf("Filename: %s\n", pkg->filename);

    if (!fgets(buffer, sizeof(buffer), file) || sscanf(buffer, "size:%u", &pkg->size) != 1) {
        fprintf(stderr, "Failed to parse size.\n");
        fclose(file);
        free(pkg);
        return NULL;
    }
    printf("Size: %u\n", pkg->size);

    if (!fgets(buffer, sizeof(buffer), file) || sscanf(buffer, "nchunks:%u", &pkg->nchunks) != 1) {
        fprintf(stderr, "Failed to parse nchunks.\n");
        fclose(file);
        free(pkg);
        return NULL;
    }
    printf("Nchunks: %u\n", pkg->nchunks);

    fgets(buffer, sizeof(buffer), file);

    char line[256];
    int index = 0;
    unsigned long tempOffset, tempSize;
    pkg->chunks = malloc(pkg->nchunks * sizeof(Chunk));
    if (pkg->chunks == NULL) {
        fprintf(stderr, "Failed to allocate memory for chunks\n");
        fclose(file);
        free(pkg);
        return NULL;
    }

    while (fgets(line, sizeof(line), file) && index < pkg->nchunks) {
        char *clean_line = strtok(line, "\n\r");
        clean_line = strtok(clean_line, "\t");
        pkg->chunks[index].hash = malloc(65);
        if (pkg->chunks[index].hash == NULL) {
            fprintf(stderr, "Failed to allocate memory for hash\n");
            fclose(file);
            free(pkg->chunks);
            free(pkg);
            return NULL;
        }

        int result = sscanf(clean_line, "%64[^,],%lu,%lu", pkg->chunks[index].hash, &tempOffset, &tempSize);
        if (result != 3) {
            printf("DID NOT READ ALL DATA!");
        }
        pkg->chunks[index].offset = (uint32_t)tempOffset;
        pkg->chunks[index].size = (uint32_t)tempSize;
        pkg->chunks[index].hash[strcspn(pkg->chunks[index].hash, "\r\n")] = 0;
        index++;
    }

    for (int i = 0; i < pkg->nchunks; i++) {
        printf("Chunk %d: Hash = %s, Offset = %u, Size = %u\n", i, pkg->chunks[i].hash, pkg->chunks[i].offset, pkg->chunks[i].size);
    }

    fclose(file);
    return pkg;
}

void free_package(Package *pkg) {
    if (pkg) {
        for (unsigned int i = 0; i < pkg->nchunks; ++i) {
            free(pkg->chunks[i].hash);
        }
        free(pkg->chunks);
        free(pkg);
    }
}

Package* find_package_by_identifier(const char *identifier) {
    for (int i = 0; i < package_count; ++i) {
        if (strncmp(packages[i]->ident, identifier, 32) == 0) {
            return packages[i];
        }
    }
    return NULL;
}

Chunk* find_chunk_by_hash(Package *pkg, const char *chunk_hash) {
    for (unsigned int i = 0; i < pkg->nchunks; ++i) {
        if (strcmp(pkg->chunks[i].hash, chunk_hash) == 0) {
            return &pkg->chunks[i];
        }
    }
    return NULL;
}

// Add package to the global list (example function)
void add_package_to_list(Package *pkg) {
    packages = realloc(packages, (package_count + 1) * sizeof(Package *));
    packages[package_count++] = pkg;
}

