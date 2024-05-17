struct merkle_tree_node *create_node(const char *expected_hash, int is_leaf) {
    struct merkle_tree_node *node = (struct merkle_tree_node *)malloc(sizeof(struct merkle_tree_node));
    if (!node) {
        fprintf(stderr, "Failed to allocate node.\n");
        return NULL;
    }
    strcpy(node->expected_hash, expected_hash);
    node->is_leaf = is_leaf;
    node->left = node->right = NULL;
    return node;
}

void compute_hash(struct merkle_tree_node *node) {
    char combined[SHA256_HEXLEN * 2 + 1] = {0};
    sprintf(combined, "%s%s", node->left->computed_hash, node->right->computed_hash);
    get_sha256_hash(combined, node->computed_hash);
}

struct merkle_tree_node *build_merkle_tree(char **hashes, int n) {
    struct merkle_tree_node **nodes = (struct merkle_tree_node **)malloc(n * sizeof(struct merkle_tree_node *));
    if (!nodes) {
        fprintf(stderr, "Failed to allocate nodes array.\n");
        return NULL;
    }

    for (int i = 0; i < n; i++) {
        nodes[i] = create_node(hashes[i], 1);
    }

    int current_level_count = n;
    while (current_level_count > 1) {
        int next_level_count = 0;
        for (int i = 0; i < current_level_count; i += 2) {
            if (i + 1 < current_level_count) {
                nodes[next_level_count] = create_node("", 0);
                nodes[next_level_count]->left = nodes[i];
                nodes[next_level_count]->right = nodes[i + 1];
                compute_hash(nodes[next_level_count]);
            } else {
                nodes[next_level_count] = nodes[i];
            }
            next_level_count++;
        }
        current_level_count = next_level_count;
    }

    struct merkle_tree_node *root = nodes[0];
    free(nodes);
    return root;
}
