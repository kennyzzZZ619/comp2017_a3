#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../include/tree/merkletree.h"
#include "../../include/chk/pkgchk.h"
#include "../../include/crypt/sha256.h"
//Your code here!


struct merkle_tree_node *create_node(const char *expected_hash, const char *computed_hash, int is_leaf) {
    struct merkle_tree_node *node = malloc(sizeof(struct merkle_tree_node));
    if (!node) {
        fprintf(stderr, "Failed to allocate node.\n");
        return NULL;
    }
    if (expected_hash) {
        strncpy(node->expected_hash, expected_hash, SHA256_HEXLEN);
        node->expected_hash[SHA256_HEXLEN] = '\0';
    } else {
        memset(node->expected_hash, 0, SHA256_HEXLEN);
    }
    if (computed_hash) {
        strncpy(node->computed_hash, computed_hash, SHA256_HEXLEN);
        node->computed_hash[SHA256_HEXLEN] = '\0'; 
    } else {
        memset(node->computed_hash, 0, SHA256_HEXLEN);
    }
    node->is_leaf = is_leaf;
    node->left = node->right = NULL;
    return node;
}

void compute_hash(struct merkle_tree_node *node) {
    if (node->left && node->right) {
        char combined[SHA256_HEXLEN * 2 + 1];
        snprintf(combined, sizeof(combined), "%s%s", node->left->computed_hash, node->right->computed_hash);
        combined[SHA256_HEXLEN * 2] = '\0';
        get_sha256_hash(combined, node->computed_hash);
    }
}


struct merkle_tree_node *build_merkle_tree(bpkg_obj *obj, char **hashes, struct merkle_tree_node ***nodes_out, int *total_nodes_out) {
    int n = obj->nchunks;
    int total_nodes = n * 2 - 1;
    struct merkle_tree_node **nodes = malloc(sizeof(struct merkle_tree_node *) * total_nodes);
    if (!nodes) {
        fprintf(stderr, "Failed to allocate nodes.\n");
        return NULL;
    }

    // Initialize leaf nodes
    for (int i = 0; i < n; i++) {
        nodes[i] = create_node(obj->chunks[i].hash, hashes[i], 1);
        if (!nodes[i]) {
            fprintf(stderr, "Failed to create node.\n");
            for (int j = 0; j < i; j++) free(nodes[j]);
            free(nodes);
            return NULL;
        }
    }

    int current_level_count = n;
    int next_level_start = n;

    // Build the tree from leaf nodes up to the root
    while (current_level_count > 1) {
        int next_level_count = 0;
        for (int i = 0; i < current_level_count; i += 2) {
            if (i + 1 < current_level_count) {
                nodes[next_level_start + next_level_count] = create_node("", "", 0);
                if (!nodes[next_level_start + next_level_count]) {
                    fprintf(stderr, "Failed to create non-leaf node.\n");
                    for (int j = 0; j < next_level_start + next_level_count; j++) free(nodes[j]);
                    for (int j = 0; j < n; j++) free(nodes[j]);
                    free(nodes);
                    return NULL;
                }
                nodes[next_level_start + next_level_count]->left = nodes[i];
                nodes[next_level_start + next_level_count]->right = nodes[i + 1];
                compute_hash(nodes[next_level_start + next_level_count]);
            } else {
                nodes[next_level_start + next_level_count] = nodes[i];
            }
            next_level_count++;
        }
        current_level_count = next_level_count;
        next_level_start += next_level_count;
    }

    struct merkle_tree_node *root = nodes[next_level_start - 1];
    *nodes_out = nodes;
    *total_nodes_out = total_nodes;
    return root;
}



void free_tree(struct merkle_tree_node **nodes, int total_nodes) {
    for (int i = 0; i < total_nodes; i++) {
        if (nodes[i]) {  
            free(nodes[i]);
            nodes[i] = NULL;  
        }
    }
    free(nodes);
}





void get_sha256_hash(char *input, char *output) {
    struct sha256_compute_data data;
    sha256_compute_data_init(&data);
    sha256_update(&data, input, strlen(input));
    sha256_finalize(&data, (uint8_t *)output);
    sha256_output_hex(&data, output);
}
