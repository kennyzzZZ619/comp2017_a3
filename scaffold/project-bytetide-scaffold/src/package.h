#ifndef PACKAGE_H
#define PACKAGE_H

#include <stdint.h>
#include <stdio.h>


typedef struct {
    char *hash;
    uint32_t offset;
    uint32_t size;
} Chunk;

typedef struct {
    char ident[33];
    char filename[256];
    unsigned int size;
    unsigned int nchunks;
    Chunk *chunks;
}Package;

extern Package **packages;
extern int package_count;

Package* load_package(const char *filename);
void free_package(Package *pkg);
void clear_rest_line(FILE *file, char buffer[]);
Package* find_package_by_identifier(const char *identifier);
Chunk* find_chunk_by_hash(Package *pkg, const char *chunk_hash);
void add_package_to_list(Package *pkg);

#endif // PACKAGE_H

