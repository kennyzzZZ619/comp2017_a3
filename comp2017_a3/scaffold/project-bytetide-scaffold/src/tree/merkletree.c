#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../include/tree/merkletree.h"
#include "../../include/chk/pkgchk.h"
#include "../../include/crypt/sha256.h"
//Your code here!


void get_sha256_hash(char* input, char* output) {
    struct sha256_compute_data data;
    sha256_compute_data_init(&data);
    sha256_update(&data, input, strlen(input));
    sha256_finalize(&data, (uint8_t*)output);
    sha256_output_hex(&data, output);  // Assumes output is large enough to hold the hash
}


// struct merkle_tree_node* create_node(char* data){
//     struct merkle_tree_node* node = malloc(sizeof(struct merkle_tree_node));
//     if(!node){
//         return NULL;
//     }
//     get_sha256_hash(data, node->computed_hash);
//     node->value = data[0];
//     node->left = node->right = NULL;
//     return node;
// }

// struct merkle_tree_node* insert_node(char** data, int leaf_no){
//     // 1. Check if it is the first node
//     if(leaf_no == 1){
//         return create_node(data[0]);
//     }
//     // 2. Define a middle point to divide tree into left and right
//     int mid = leaf_no/2; 
//     struct merkle_tree_node* left = insert_node(data, mid);
//     struct merkle_tree_node* right = insert_node(data+mid, leaf_no-mid);

//     struct merkle_tree_node* parent = malloc(sizeof(struct merkle_tree_node));
//     if(!parent){
//         return NULL;
//     }

//     char concatenated_hashes[2 * 65];  // Two hashes concatenated
//     snprintf(concatenated_hashes, sizeof(concatenated_hashes), "%s%s", left->computed_hash, right->computed_hash);
    
//     get_sha256_hash(concatenated_hashes, parent->computed_hash);
//     parent->left = left;
//     parent->right = right;
//     return parent;
// }

// void free_merkle_tree(struct merkle_tree_node* node) {
//     if (!node) return;
//     free_merkle_tree(node->left);
//     free_merkle_tree(node->right);
//     free(node);
// }


struct merkle_tree_node* create_node(char* hash, char isLeaf) {
    struct merkle_tree_node* node = malloc(sizeof(struct merkle_tree_node));
    if (!node) {
        return NULL;
    }
    if (isLeaf) {
        // Directly use the hash for leaf nodes
        strncpy(node->computed_hash, hash, 64);
    } else {
        // Compute the hash for internal nodes
        get_sha256_hash(hash, node->computed_hash);
    }
    node->left = node->right = NULL;
    return node;
}

struct merkle_tree_node* build_merkle_tree(char** data, int start, int end) {
    if (start == end) {
        // Base case: create a leaf node
        return create_node(data[start], 1);
    }
    int mid = (start + end) / 2;
    struct merkle_tree_node* left = build_merkle_tree(data, start, mid);
    struct merkle_tree_node* right = build_merkle_tree(data, mid + 1, end);

    char concatenated_hashes[2 * 65] = {0};  // Two hashes concatenated
    snprintf(concatenated_hashes, sizeof(concatenated_hashes), "%s%s", left->computed_hash, right->computed_hash);

    struct merkle_tree_node* parent = create_node(concatenated_hashes, 0);
    parent->left = left;
    parent->right = right;
    return parent;
}

void free_merkle_tree(struct merkle_tree_node* node) {
    if (!node) return;
    free_merkle_tree(node->left);
    free_merkle_tree(node->right);
    free(node);
}
