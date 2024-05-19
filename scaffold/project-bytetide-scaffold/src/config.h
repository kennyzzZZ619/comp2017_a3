#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>


typedef struct {
    char directory[256];
    int max_peers;
    uint16_t port;
} Config;


extern Config config;


void load_config(const char *filename);

#endif // CONFIG_H

