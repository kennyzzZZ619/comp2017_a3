// src/network.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdint.h>
#include "network.h"
#include "package.h"
#include "peer.h"

void send_packet(int socket, const struct btide_packet *packet) {
    if (send(socket, packet, sizeof(struct btide_packet), 0) <= 0) {
        perror("Failed to send packet");
    }
}

void receive_packet(int socket, struct btide_packet *packet) {
    if (recv(socket, packet, sizeof(struct btide_packet), 0) <= 0) {
        perror("Failed to receive packet");
    }
}

void send_req_packet(int socket, const struct req_packet *packet) {
    send_packet(socket, (struct btide_packet *)packet);
}

void handle_req_packet(int client_socket, const struct req_packet *packet) {
   
    Package *pkg = find_package_by_identifier(packet->identifier);
    if (!pkg) {
        fprintf(stderr, "Package not found\n");
        return;
    }

    Chunk *chunk = find_chunk_by_hash(pkg, packet->chunk_hash);
    if (!chunk) {
        fprintf(stderr, "Chunk not found\n");
        return;
    }

 
    FILE *file = fopen(pkg->filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    fseek(file, packet->file_offset, SEEK_SET);
    char data[packet->data_len];
    fread(data, 1, packet->data_len, file);
    fclose(file);

   
    struct res_packet res;
    res.file_offset = packet->file_offset;
    res.data_len = packet->data_len;
    memcpy(res.data, data, packet->data_len);
    strncpy(res.chunk_hash, packet->chunk_hash, 64);
    strncpy(res.identifier, packet->identifier, 1024);
    
    send_packet(client_socket, (struct btide_packet *)&res);
}


void send_res_packet(int socket, const struct res_packet *packet) {
    send_packet(socket, (struct btide_packet *)packet);
}

void handle_res_packet(int client_socket, const struct res_packet *packet) {
   
    FILE *file = fopen(packet->identifier, "rb+");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    fseek(file, packet->file_offset, SEEK_SET);
    fwrite(packet->data, 1, packet->data_len, file);
    fclose(file);

    printf("Received data for chunk %s\n", packet->chunk_hash);
}


void* handle_client(void* arg) {
    int client_socket = *((int*)arg);
    free(arg);

    struct btide_packet packet;
    while (1) {
        receive_packet(client_socket, &packet);
        switch (packet.msg_code) {
            case PKT_MSG_ACP:
                printf("Received ACP from client\n");
                struct btide_packet ack_packet = { PKT_MSG_ACK, 0, {{0}} };
                send_packet(client_socket, &ack_packet);
                break;
            case PKT_MSG_DSN:
                printf("Client requested disconnect\n");
                close(client_socket);
                return NULL;
            case PKT_MSG_REQ:
                handle_req_packet(client_socket, (struct req_packet *)&packet);
                break;
            case PKT_MSG_RES:
                handle_res_packet(client_socket, (struct res_packet *)&packet);
                break;
            default:
                printf("Unknown packet type: %d\n", packet.msg_code);
                break;
        }
    }
}


void handle_incoming_connection(int server_socket) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    while (1) {
        int *client_socket = malloc(sizeof(int));
        *client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);
        if (*client_socket < 0) {
            perror("Failed to accept connection");
            free(client_socket);
            continue;
        }

        printf("New connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_client, client_socket);
        pthread_detach(thread_id);
    }
}

void start_server(uint16_t port) {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 10) < 0) {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", port);

    handle_incoming_connection(server_socket);

    close(server_socket);
}

void fetch_chunk(const char *ip, uint16_t port, const char *identifier, const char *chunk_hash, uint32_t offset) {
    int peer_found = 0;
    for (int i = 0; i < peer_count; ++i) {
        if (strcmp(peers[i].ip, ip) == 0 && peers[i].port == port) {
            peer_found = 1;
            break;
        }
    }
    if (!peer_found) {
        printf("Unable to request chunk, peer not in list\n");
        return;
    }

    Package *pkg = find_package_by_identifier(identifier);
    if (!pkg) {
        printf("Unable to request chunk, package is not managed\n");
        return;
    }

    Chunk *chunk = find_chunk_by_hash(pkg, chunk_hash);
    if (!chunk) {
        printf("Unable to request chunk, chunk hash does not belong to package\n");
        return;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation error");
        return;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sock);
        return;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return;
    }

    struct req_packet req;
    req.msg_code = PKT_MSG_REQ;
    req.error = 0;
    req.file_offset = offset;
    req.data_len = 0;
    strncpy(req.chunk_hash, chunk_hash, 64);
    strncpy(req.identifier, identifier, 1024);

    send_req_packet(sock, &req);

    close(sock);
}

