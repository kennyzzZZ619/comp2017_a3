//
// PART 2
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "config.h"
#include "network.h"
#include "peer.h"
#include "package.h"

void print_usage() {
    printf("Usage: btide <config_file>\n");
}

void process_command(char *command) {
    char *cmd = strtok(command, " ");
    if (strcmp(cmd, "CONNECT") == 0) {
        char *address = strtok(NULL, ":");
        char *port_str = strtok(NULL, "");
        if (!address || !port_str) {
            printf("Missing address and port argument.\n");
            return;
        }
        uint16_t port = (uint16_t)atoi(port_str);
        connect_peer(address, port);
    } else if (strcmp(cmd, "DISCONNECT") == 0) {
        char *address = strtok(NULL, ":");
        char *port_str = strtok(NULL, "");
        if (!address || !port_str) {
            printf("Missing address and port argument.\n");
            return;
        }
        uint16_t port = (uint16_t)atoi(port_str);
        disconnect_peer(address, port);
    } else if (strcmp(cmd, "ADDPACKAGE") == 0) {
        char *file = strtok(NULL, "");
        if (!file) {
            printf("Missing file argument.\n");
            return;
        }
        Package *pkg = load_package(file);
        if (!pkg) {
            printf("Unable to parse bpkg file.\n");
            return;
        }
        add_package_to_list(pkg);
        printf("Package loaded successfully.\n");

    } else if (strcmp(cmd, "REMPACKAGE") == 0) {
        char *ident = strtok(NULL, "");
        if (!ident) {
            printf("Missing identifier argument, please specify whole 1024 character or at least 20 characters.\n");
            return;
        }
        Package *pkg = find_package_by_identifier(ident);
        if (pkg) {
            free_package(pkg);
            printf("Package removed successfully.\n");
        } else {
            printf("Identifier provided does not match managed packages.\n");
        }

    } else if (strcmp(cmd, "PACKAGES") == 0) {

        if (package_count == 0) {
            printf("No packages managed.\n");
        } else {
            for (int i = 0; i < package_count; ++i) {
                printf("%d. %s, %s : %s\n", i + 1, packages[i]->ident, packages[i]->filename,
                    (packages[i]->nchunks == 0) ? "INCOMPLETE" : "COMPLETED");
            }
        }
    } else if (strcmp(cmd, "PEERS") == 0) {
        list_peers();
    } else if (strcmp(cmd, "FETCH") == 0) {
        char *address = strtok(NULL, ":");
        char *port_str = strtok(NULL, " ");
        char *identifier = strtok(NULL, " ");
        char *hash = strtok(NULL, " ");
        char *offset_str = strtok(NULL, "");
        if (!address || !port_str || !identifier || !hash) {
            printf("Missing arguments from command.\n");
            return;
        }
        uint16_t port = (uint16_t)atoi(port_str);
        int offset = offset_str ? atoi(offset_str) : 0;

        fetch_chunk(address, port, identifier, hash, offset);
    } else if (strcmp(cmd, "QUIT") == 0) {
        exit(0);
    } else {
        printf("Invalid Input.\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        print_usage();
        return 1;
    }

    load_config(argv[1]);

    pthread_t server_thread;
    pthread_create(&server_thread, NULL, (void *(*)(void *))start_server, (void *)(intptr_t)config.port);
    pthread_detach(server_thread);

    char command[5520];
    while (1) {
        printf("> ");
        if (fgets(command, sizeof(command), stdin) == NULL) {
            break;
        }
        command[strcspn(command, "\n")] = 0; 
        if (strlen(command) == 0) {
            continue; 
        }
        process_command(command);
    }

    return 0;
}

