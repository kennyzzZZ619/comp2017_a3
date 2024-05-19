#ifndef PEER_H
#define PEER_H

#include <pthread.h>

typedef struct {
    char ip[16];
    uint16_t port;
    int socket;
} Peer;

extern Peer peers[2048];
extern int peer_count;
extern pthread_mutex_t peer_mutex;

void* connect_to_peer(void* arg);
void connect_peer(const char *ip, uint16_t port);
void disconnect_peer(const char *ip, uint16_t port);
void list_peers();

#endif // PEER_H

