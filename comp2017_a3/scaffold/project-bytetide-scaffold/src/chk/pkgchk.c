#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include "../../include/chk/pkgchk.h"
#include "../../include/tree/merkletree.h"

// PART 1


/**
 * Loads the package for when a valid path is given
 */
void traverse_and_collect_hashes(struct merkle_tree_node* node, struct bpkg_query* qry);
void clear_rest_line(FILE* file, char buffer[]){
    if(strchr(buffer, '\n') == NULL){ // Clear the rest of the line
        int c;
        while ((c = fgetc(file)) != '\n' && c != EOF);
    }
}

bpkg_obj* bpkg_load(const char* path) {
    bpkg_obj* obj = malloc(sizeof(bpkg_obj));
    if (obj == NULL) {
        fprintf(stderr, "Memory allocation failed for bpkg_obj\n");
        exit(EXIT_FAILURE);
    }

    FILE* file = fopen(path, "r");
    if (file == NULL) {
        perror("Failed to open file");
        free(obj);
        exit(EXIT_FAILURE);
    }

    char buffer[1025];
    
    // Read identifier
    if (fgets(buffer, sizeof(buffer), file) != NULL) {
        buffer[strcspn(buffer, "\r\n")] = 0;  // Remove newline characters
        obj->ident = strdup(buffer + 6);
        printf("Ident: %s\n", obj->ident);
    }

    clear_rest_line(file, buffer);

    // Read filename
    if (fgets(buffer, sizeof(buffer), file) != NULL) {
        buffer[strcspn(buffer, "\r\n")] = 0;  // Remove newline characters
        obj->filename = strdup(buffer + 9);
        printf("Filename: %s\n", obj->filename);
    }

    // Read size
    if (fgets(buffer, sizeof(buffer), file) != NULL) {
        buffer[strcspn(buffer, "\r\n")] = 0;
        if (sscanf(buffer, "size:%u", &obj->size) != 1) {
            fprintf(stderr, "Failed to parse size.\n");
            exit(EXIT_FAILURE);
        }
        printf("Size: %u\n", obj->size);
    }

    // Read nhashes
    if (fgets(buffer, sizeof(buffer), file) != NULL) {
        buffer[strcspn(buffer, "\r\n")] = 0;
        if (sscanf(buffer, "nhashes:%u", &obj->nhashes) != 1) {
            fprintf(stderr, "Failed to parse nhashes.\n");
            exit(EXIT_FAILURE);
        }
        printf("Nhashes: %u\n", obj->nhashes);
    }

    // Dynamic memory allocation for storing hashes, as an example
    obj->hashes = (char**)malloc(obj->nhashes * sizeof(char*));
    for(int i=0;i<obj->nhashes;i++){
        obj->hashes[i] = (char*)malloc(66);
        if(fgets(obj->hashes[i],66,file)!=NULL){
            obj->hashes[i][strcspn(obj->hashes[i], "\r\n")] = 0;
            printf("%s\n", obj->hashes[i]);
        }else{
            printf("error\n");
        }
    }

    // Allocate and read chunks
    obj->chunks = malloc(obj->nchunks * sizeof(Chunks));
    for (int i = 0; i < obj->nchunks; i++) {
        obj->chunks[i].hash = malloc(65);
        fgets(buffer, sizeof(buffer), file);
        sscanf(buffer, "%64s %u %u", obj->chunks[i].hash, &obj->chunks[i].offset, &obj->chunks[i].size);
    }

    fclose(file);
    return obj;
}


/**
 * Checks to see if the referenced filename in the bpkg file
 * exists or not.
 * @param bpkg, constructed bpkg object
 * @return query_result, a single string should be
 *      printable in hashes with len sized to 1.
 * 		If the file exists, hashes[0] should contain "File Exists"
 *		If the file does not exist, hashes[0] should contain "File Created"
 */
struct bpkg_query bpkg_file_check(bpkg_obj* bpkg){
    struct bpkg_query result = {0};
    FILE* file = fopen(bpkg->filename,"r");
    if(file){
        fseek(file,0,SEEK_END);   
        size_t size = ftell(file);
        fclose(file);

        result.hashes = malloc(sizeof(char*));
        if (size == bpkg->size) {
            result.hashes[0] = strdup("File Exists");
            result.len = 1;
        } else {
            result.hashes[0] = strdup("Size Mismatch");
            result.len = 1;
        }
    }else{
        file = fopen(bpkg->filename, "w");
        if (file) {
            fseek(file, bpkg->size - 1, SEEK_SET);
            fputc('\0', file); // Expand file to the specified size
            fclose(file);

            result.hashes = malloc(sizeof(char*));
            result.hashes[0] = strdup("File Created");
            result.len = 1;
        } else {
            result.hashes = malloc(sizeof(char*));
            result.hashes[0] = strdup("Failed to Create File");
            result.len = 1;
        }
    }
    return result;
}

/**
 * Retrieves a list of all hashes within the package/tree
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */

void traverse_and_collect_hashes(struct merkle_tree_node* node, struct bpkg_query* qry) {
    if (node == NULL) {
        return;  // Base case: reached a leaf's null child
    }
    // Resize the hashes array to accommodate a new hash
    qry->hashes = realloc(qry->hashes, (qry->len + 1) * sizeof(char*));
    if (qry->hashes == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    qry->hashes[qry->len] = malloc(SHA256_HEXLEN * sizeof(char));
    if (qry->hashes[qry->len] == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    strcpy(qry->hashes[qry->len], node->computed_hash);
    qry->len++;
    
    // Recursive calls to traverse left and right subtrees
    traverse_and_collect_hashes(node->left, qry);
    traverse_and_collect_hashes(node->right, qry);
}

// Public function to get all hashes from a Merkle tree
struct bpkg_query bpkg_get_all_hashes(bpkg_obj* bpkg) {
    struct bpkg_query qry = {NULL, 0};

    // First, collect hashes from the bpkg_obj's hash array
    for (uint32_t i = 0; i < bpkg->nhashes; i++) {
        qry.hashes = realloc(qry.hashes, (qry.len + 1) * sizeof(char*));
        if (qry.hashes == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            exit(EXIT_FAILURE);
        }
        qry.hashes[qry.len] = strdup(bpkg->hashes[i]);
        qry.len++;
    }

    // Next, collect hashes from the Merkle tree, if it exists
    if (bpkg->merkle_tree && bpkg->merkle_tree->root) {
        traverse_and_collect_hashes(bpkg->merkle_tree->root, &qry);
    }

    return qry;
}



/**
 * Retrieves all completed chunks of a package object
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_completed_chunks(bpkg_obj* bpkg) {
    struct bpkg_query qry = {NULL, 0};
    if (bpkg == NULL) {
        return qry;  // Always check for NULL pointers.
    }

    // Assuming 'completed' is a boolean array indicating the completion state of each chunk.
    qry.hashes = malloc(bpkg->nchunks * sizeof(char*));
    if (qry.hashes == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return qry;
    }

    for (int i = 0; i < bpkg->nchunks; i++) {
        if (bpkg->chunks[i].completed) {
            qry.hashes[qry.len] = strdup(bpkg->chunks[i].hash);
            qry.len++;
        }
    }
    return qry;
}



/**
 * Gets only the required/min hashes to represent the current completion state
 * Return the smallest set of hashes of completed branches to represent
 * the completion state of the file.
 *
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_min_completed_hashes(bpkg_obj* bpkg) {
    struct bpkg_query qry = { 0 };
    return qry;
}


/**
 * Retrieves all chunk hashes given a certain an ancestor hash (or itself)
 * Example: If the root hash was given, all chunk hashes will be outputted
 * 	If the root's left child hash was given, all chunks corresponding to
 * 	the first half of the file will be outputted
 * 	If the root's right child hash was given, all chunks corresponding to
 * 	the second half of the file will be outputted
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_all_chunk_hashes_from_hash(bpkg_obj* bpkg, 
    char* hash) {
    
    struct bpkg_query qry = { 0 };
    return qry;
}


/**
 * Deallocates the query result after it has been constructed from
 * the relevant queries above.
 */
void bpkg_query_destroy(struct bpkg_query* qry) {
    //TODO: Deallocate here!
    if(!qry){
        return;
    }
    for(size_t i=0;i<qry->len;i++){
        free(qry->hashes[i]);
    }
    free(qry->hashes);
}

/**
 * Deallocates memory at the end of the program,
 * make sure it has been completely deallocated
 */
void bpkg_obj_destroy(bpkg_obj* obj) {
    //TODO: Deallocate here!
    if (!obj) return;
    free(obj->ident);
    free(obj->filename);
    for (int i = 0; i < obj->nhashes; i++) {
        free(obj->hashes[i]);
    }
    free(obj->hashes);

    for (int i = 0; i < obj->nchunks; i++) {
        free(obj->chunks[i].hash);
    }
    free(obj->chunks);
    free(obj);

}


