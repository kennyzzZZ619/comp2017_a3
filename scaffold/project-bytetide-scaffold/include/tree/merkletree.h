#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include <stddef.h>
#include "../chk/pkgchk.h"

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

struct merkle_tree_node *create_node(const char *expected_hash, const char *computed_hash, int is_leaf);
void compute_hash(struct merkle_tree_node *node);
struct merkle_tree_node *create_node(const char *expected_hash, const char *computed_hash, int is_leaf);
void free_tree(struct merkle_tree_node **root, int total);
void get_sha256_hash(char *input, char *output);



#endif
