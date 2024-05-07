#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include <stddef.h>

#define SHA256_HEXLEN (64)

struct merkle_tree_node {
    int key;
    char value;
    struct merkle_tree_node* left;
    struct merkle_tree_node* right;
    int is_leaf;
    char expected_hash[SHA256_HEXLEN];
    char computed_hash[SHA256_HEXLEN];
};


struct merkle_tree {
    struct merkle_tree_node* root;
    size_t n_nodes;
};

struct merkle_tree_node* create_node(char* hash, char isLeaf);
struct merkle_tree_node* build_merkle_tree(char** data, int start, int end);
void free_merkle_tree(struct merkle_tree_node* node);

// struct merkle_tree_node* create_node(char* data);

// void get_sha256_hash(char* input, char* output);

// struct merkle_tree_node* insert_node(char** data, int leaf_no);

// void free_merkle_tree(struct merkle_tree_node* node);

#endif
