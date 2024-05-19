// src/config.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdint.h>
#include "config.h"

Config config;

void load_config(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open configuration file");
        exit(EXIT_FAILURE);
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *key = strtok(line, ":");
        char *value = strtok(NULL, "\n");

        if (strcmp(key, "directory") == 0) {
            strncpy(config.directory, value, sizeof(config.directory));
        } else if (strcmp(key, "max_peers") == 0) {
            config.max_peers = atoi(value);
            if (config.max_peers < 1 || config.max_peers > 2048) {
                fprintf(stderr, "Invalid max_peers value\n");
                exit(4);
            }
        } else if (strcmp(key, "port") == 0) {
            config.port = (uint16_t)atoi(value);
            if (config.port <= 1024 || config.port > 65535) {
                fprintf(stderr, "Invalid port value\n");
                exit(5);
            }
        } else {
            fprintf(stderr, "Unknown configuration key: %s\n", key);
            exit(EXIT_FAILURE);
        }
    }

    fclose(file);

    struct stat st = {0};
    if (stat(config.directory, &st) == -1) {
        if (mkdir(config.directory, 0700) != 0) {
            perror("Failed to create directory");
            exit(3);
        }
    } else if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Directory path is not a directory\n");
        exit(3);
    }
}

