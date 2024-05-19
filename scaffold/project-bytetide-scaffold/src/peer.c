// src/peer.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include "network.h"
#include "peer.h"



Peer peers[2048];
int peer_count = 0;
pthread_mutex_t peer_mutex = PTHREAD_MUTEX_INITIALIZER;

void* connect_to_peer(void* arg) {
    Peer *new_peer = (Peer*)arg;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation error");
        free(new_peer);
        return NULL;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(new_peer->port);

    if (inet_pton(AF_INET, new_peer->ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sock);
        free(new_peer);
        return NULL;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        free(new_peer);
        return NULL;
    }

    new_peer->socket = sock;

    struct btide_packet acp_packet = { PKT_MSG_ACP, 0, {{0}} };
    send_packet(sock, &acp_packet);

    struct btide_packet ack_packet;
    receive_packet(sock, &ack_packet);
    if (ack_packet.msg_code == PKT_MSG_ACK) {
        pthread_mutex_lock(&peer_mutex);
        peers[peer_count++] = *new_peer;
        pthread_mutex_unlock(&peer_mutex);
        printf("Connection established with peer.\n");
    } else {
        printf("ACK not received.\n");
        close(sock);
    }

    free(new_peer);
    return NULL;
}

void connect_peer(const char *ip, uint16_t port) {
    if (peer_count >= 2048) {
        fprintf(stderr, "Maximum number of peers reached.\n");
        return;
    }

    Peer *new_peer = malloc(sizeof(Peer));
    if (!new_peer) {
        fprintf(stderr, "Failed to allocate memory for new peer.\n");
        return;
    }

    strncpy(new_peer->ip, ip, 16);
    new_peer->port = port;
    new_peer->socket = -1;

    pthread_t thread_id;
    pthread_create(&thread_id, NULL, connect_to_peer, new_peer);
    pthread_detach(thread_id);
}

void disconnect_peer(const char *ip, uint16_t port) {
    pthread_mutex_lock(&peer_mutex);
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peers[i].ip, ip) == 0 && peers[i].port == port) {
            struct btide_packet dsn_packet = { PKT_MSG_DSN, 0, {{0}} };
            send_packet(peers[i].socket, &dsn_packet);
            close(peers[i].socket);

            for (int j = i; j < peer_count - 1; j++) {
                peers[j] = peers[j + 1];
            }
            peer_count--;
            printf("Disconnected from peer.\n");
            pthread_mutex_unlock(&peer_mutex);
            return;
        }
    }
    pthread_mutex_unlock(&peer_mutex);
    printf("Unknown peer, not connected.\n");
}

void list_peers() {
    pthread_mutex_lock(&peer_mutex);
    if (peer_count == 0) {
        printf("Not connected to any peers\n");
    } else {
        printf("Connected to:\n");
        for (int i = 0; i < peer_count; i++) {
            printf("%d. %s:%d\n", i + 1, peers[i].ip, peers[i].port);
        }
    }
    pthread_mutex_unlock(&peer_mutex);
}

