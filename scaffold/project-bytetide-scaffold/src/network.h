#ifndef NETWORK_H
#define NETWORK_H
#include <stdint.h>
#define PAYLOAD_MAX 4096
// Define the packet message codes
#define PKT_MSG_ACK 0x0c
#define PKT_MSG_ACP 0x02
#define PKT_MSG_DSN 0x03
#define PKT_MSG_REQ 0x06
#define PKT_MSG_RES 0x07
#define PKT_MSG_PNG 0xFF
#define PKT_MSG_POG 0x00

union btide_payload {
    uint8_t data[PAYLOAD_MAX];
};

struct btide_packet {
    uint16_t msg_code;
    uint16_t error;
    union btide_payload pl;
};

struct req_packet {
    uint16_t msg_code;
    uint16_t error;
    uint32_t file_offset;
    uint16_t data_len;
    char chunk_hash[64];
    char identifier[1024];
};

struct res_packet {
    uint16_t msg_code;
    uint16_t error;
    uint32_t file_offset;
    uint16_t data_len;
    char data[2998];
    char chunk_hash[64];
    char identifier[1024];
};

void send_packet(int socket, const struct btide_packet *packet);
void receive_packet(int socket, struct btide_packet *packet);
void handle_incoming_connection(int server_socket);
void start_server(uint16_t port);
void* handle_client(void* arg);

void send_req_packet(int socket, const struct req_packet *packet);
void handle_req_packet(int client_socket, const struct req_packet *packet);
void send_res_packet(int socket, const struct res_packet *packet);
void handle_res_packet(int client_socket, const struct res_packet *packet);
void fetch_chunk(const char *ip, uint16_t port, const char *identifier, const char *chunk_hash, uint32_t offset);

#endif
