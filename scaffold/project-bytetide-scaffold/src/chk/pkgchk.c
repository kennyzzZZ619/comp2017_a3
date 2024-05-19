#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include "../../include/chk/pkgchk.h"
#include "../../include/tree/merkletree.h"

// PART 1


/**
 * Loads the package for when a valid path is given
 */
void clear_rest_line(FILE *file, char buffer[]) {
    if (strchr(buffer, '\n') == NULL) {
        int c;
        while ((c = fgetc(file)) != '\n' && c != EOF);
    }
}

bpkg_obj *bpkg_load(const char *path) {
    bpkg_obj *obj = malloc(sizeof(bpkg_obj));
    if (obj == NULL) {
        fprintf(stderr, "Memory allocation failed for bpkg_obj\n");
        return NULL;
    }

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        perror("Failed to open file");
        free(obj);
        return NULL;
    }

    char buffer[1025];
    memset(buffer, 0, sizeof(buffer));

    if (!fgets(buffer, sizeof(buffer), file) || buffer[5] != ':') {
        fprintf(stderr, "Failed to read identifier\n");
        fclose(file);
        free(obj);
        return NULL;
    }
    buffer[strcspn(buffer, "\r\n")] = 0;
    obj->ident = strdup(buffer + 6);
    printf("Ident: %s\n", obj->ident);

    clear_rest_line(file, buffer);

    if (!fgets(buffer, sizeof(buffer), file) || buffer[8] != ':') {
        fprintf(stderr, "Failed to read filename\n");
        fclose(file);
        free(obj);
        free(obj->ident);
        return NULL;
    }
    buffer[strcspn(buffer, "\r\n")] = 0;
    obj->filename = strdup(buffer + 9);
    printf("Filename: %s\n", obj->filename);

    if (!fgets(buffer, sizeof(buffer), file) || sscanf(buffer, "size:%u", &obj->size) != 1) {
        fprintf(stderr, "Failed to parse size.\n");
        fclose(file);
        free(obj->filename);
        free(obj->ident);
        free(obj);
        return NULL;
    }
    printf("Size: %u\n", obj->size);

    if (!fgets(buffer, sizeof(buffer), file) || sscanf(buffer, "nhashes:%u", &obj->nhashes) != 1) {
        fprintf(stderr, "Failed to parse nhashes.\n");
        fclose(file);
        free(obj->filename);
        free(obj->ident);
        free(obj);
        return NULL;
    }
    printf("Nhashes: %u\n", obj->nhashes);

    obj->hashes = (char **)malloc(obj->nhashes * sizeof(char *));
    if (obj->hashes == NULL) {
        fprintf(stderr, "Failed to allocate memory for hashes\n");
        fclose(file);
        free(obj->filename);
        free(obj->ident);
        free(obj);
        return NULL;
    }

    char temp[64];
    fgets(temp, 64, file);
    int actualIndex = 0;
    for (int i = 0; i < obj->nhashes * 2; i++) {
        char tempstore[66];  
        if (fgets(tempstore, 66, file) == NULL) {
            break;
        }

        if (tempstore[0] != '\n' && tempstore[0] != '\r' && strlen(tempstore) > 0) {
            if (actualIndex >= obj->nhashes) {
                fprintf(stderr, "More non-empty lines than expected\n");
                break;
            }

            obj->hashes[actualIndex] = (char *)malloc(66);
            if (obj->hashes[actualIndex] == NULL) {
                fprintf(stderr, "Failed to allocate memory for hash %d\n", actualIndex);
                break;
            }

            strncpy(obj->hashes[actualIndex], tempstore, 65);
            obj->hashes[actualIndex][65] = '\0'; 

            
            char temp_hash[66];
            strncpy(temp_hash, obj->hashes[actualIndex], 66);
            temp_hash[65] = '\0'; 

            char *clean_hash = strtok(temp_hash, "\r\n");
            clean_hash = strtok(clean_hash, "\t");

            strncpy(obj->hashes[actualIndex], clean_hash, 65);
            obj->hashes[actualIndex][65] = '\0'; 

            printf("%d: %s\n", actualIndex, obj->hashes[actualIndex]);
            actualIndex++;
        }
    }

    if (actualIndex != obj->nhashes) {
        fprintf(stderr, "Mismatch in the number of expected non-empty hashes\n");
    }

    
    if (fgets(buffer, sizeof(buffer), file)) {
        if (sscanf(buffer, "nchunks:%u", &obj->nchunks) != 1) {
            fprintf(stderr, "Failed to parse nchunks.\n");
            fclose(file);
            free(obj->filename);
            free(obj->ident);
            free(obj);
            return NULL;
        }
        printf("Nchunks: %u\n", obj->nchunks);
    } else {
        fprintf(stderr, "Failed to read line for nchunks.\n");
        fclose(file);
        free(obj->filename);
        free(obj->ident);
        free(obj);
        return NULL;
    }
    fgets(buffer, sizeof(buffer), file);

    char line[256];
    int index = 0;
    unsigned long tempOffset, tempSize;
    obj->chunks = malloc(obj->nchunks * sizeof(Chunks));
    if (obj->chunks == NULL) {
        fprintf(stderr, "Failed to allocate memory for hash\n");
        fclose(file);
        return NULL;
    }
    while (fgets(line, sizeof(line), file) && index < obj->nchunks) {
        char *clean_line = strtok(line, "\n\r");
        clean_line = strtok(clean_line, "\t");
        obj->chunks[index].hash = malloc(65);
        if (obj->chunks[index].hash == NULL) {
            fprintf(stderr, "Failed to allocate memory for hash\n");
            fclose(file);
            return NULL;
        }

        int result = sscanf(clean_line, "%64[^,],%lu,%lu", obj->chunks[index].hash, &tempOffset, &tempSize);
        if (result != 3) {
            printf("DID NOT READ ALL DATA!");
        }
        obj->chunks[index].offset = (uint32_t)tempOffset;
        obj->chunks[index].size = (uint32_t)tempSize;
        obj->chunks[index].hash[strcspn(obj->chunks[index].hash, "\r\n")] = 0;
        index++;
    }

    for (int i = 0; i < obj->nchunks; i++) {
        printf("Chunk %d: Hash = %s, Offset = %u, Size = %u\n", i, obj->chunks[i].hash, obj->chunks[i].offset, obj->chunks[i].size);
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
struct bpkg_query bpkg_file_check(bpkg_obj* bpkg) {
    const char* base_directory = "../resources/pkgs/";
    struct bpkg_query result;
    result.hashes = malloc(sizeof(char *));
    if (!result.hashes) {
        fprintf(stderr, "Failed to allocate memory for result hashes.\n");
        result.len = 0;
        return result;
    }

    // Construct the full path
    size_t full_path_len = strlen(base_directory) + strlen(bpkg->filename) + 1;
    char* full_path = malloc(full_path_len);
    if (!full_path) {
        fprintf(stderr, "Failed to allocate memory for the file path.\n");
        free(result.hashes);
        result.len = 0;
        return result;
    }

    snprintf(full_path, full_path_len, "%s%s", base_directory, bpkg->filename);
    printf("The full path is: %s\n",full_path);
    if (access(full_path, F_OK) != -1) {
        result.hashes[0] = strdup("File Exists");
    } else {
        FILE *file = fopen(full_path, "wb");
        if (file) {
            ftruncate(fileno(file), bpkg->size);
            fclose(file);
            result.hashes[0] = strdup("File Created");
        } else {
            perror("Failed to create file");
            result.hashes[0] = strdup("File Creation Failed");
        }
    }

    free(full_path);
    result.len = 1;
    return result;
}


/**
 * Retrieves a list of all hashes within the package/tree
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */

struct bpkg_query bpkg_get_all_hashes(bpkg_obj* bpkg) {
    struct bpkg_query result;
    int count = 0;
    uint32_t total_hashes = bpkg->nhashes + bpkg->nchunks;

    // Allocate memory for all hashes
    result.hashes = malloc(sizeof(char *) * total_hashes);
    if (!result.hashes) {
        fprintf(stderr, "Failed to allocate memory for result hashes.\n");
        result.len = 0;
        return result;
    }

    // Copy hashes
    for (uint32_t i = 0; i < bpkg->nhashes; i++) {
        result.hashes[count] = strdup(bpkg->hashes[i]);
        if (!result.hashes[count]) {
            fprintf(stderr, "Failed to duplicate hash.\n");
            // Cleanup already allocated memory
            for (uint32_t j = 0; j < count; j++) {
                free(result.hashes[j]);
            }
            free(result.hashes);
            result.len = 0;
            return result;
        }
        count++;
    }

    // Copy chunk hashes
    for (uint32_t i = 0; i < bpkg->nchunks; i++) {
        result.hashes[count] = strdup(bpkg->chunks[i].hash);
        if (!result.hashes[count]) {
            fprintf(stderr, "Failed to duplicate chunk hash.\n");
            // Cleanup already allocated memory
            for (uint32_t j = 0; j < count; j++) {
                free(result.hashes[j]);
            }
            free(result.hashes);
            result.len = 0;
            return result;
        }
        count++;
    }

    result.len = count;
    return result;
}




/**
 * Retrieves all completed chunks of a package object
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_completed_chunks(bpkg_obj* bpkg, char** computed_hash) {
    struct bpkg_query qry = {0};
    if (bpkg == NULL) {
        return qry;  // Always check for NULL pointers.
    }
	
    // Assuming 'completed' is a boolean array indicating the completion state of each chunk.
    qry.hashes = malloc(bpkg->nchunks * sizeof(char*));
    if (qry.hashes == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return qry;
    }
    int count=0;
    for (int i = 0; i < bpkg->nchunks; i++) {
	if (strcmp(computed_hash[i], bpkg->chunks[i].hash) == 0){
		qry.hashes[count] = strdup(computed_hash[i]);
		count++;
	}
    }
    qry.len = count;
    if(count == 0){
    	printf("No save chunk data here!\n");
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
    struct bpkg_query result;
    result.hashes = malloc(sizeof(char *) * (bpkg->nchunks + 1));
    if (!result.hashes) {
        fprintf(stderr, "Failed to allocate memory for result hashes.\n");
        result.len = 0;
        return result;
    }

    
    char **hashes = malloc(sizeof(char *) * bpkg->nchunks);
    for (uint32_t i = 0; i < bpkg->nchunks; i++) {
        if (bpkg->chunks[i].completed) {
            hashes[i] = strdup(bpkg->chunks[i].hash);
        } else {
            hashes[i] = strdup(""); 
        }
    }

    struct merkle_tree_node **nodes;
    int total_nodes;
    struct merkle_tree_node *root = build_merkle_tree(bpkg, hashes, &nodes, &total_nodes);
    if (!root) {
        fprintf(stderr, "Failed to build Merkle tree.\n");
        result.len = 0;
        for (uint32_t i = 0; i < bpkg->nchunks; i++) {
            free(hashes[i]);
        }
        free(hashes);
        return result;
    }

    
    int count = 0;
    for (uint32_t i = 0; i < bpkg->nchunks; i++) {
        if (bpkg->chunks[i].completed) {
            result.hashes[count] = strdup(bpkg->chunks[i].hash);
            count++;
        } else {
            break;
        }
    }

    result.len = count;

    free_tree(nodes, total_nodes);
    for (uint32_t i = 0; i < bpkg->nchunks; i++) {
        free(hashes[i]);
    }
    free(hashes);

    return result;
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

struct bpkg_query bpkg_get_all_chunk_hashes_from_hash(bpkg_obj* bpkg, char* hash) {
    struct bpkg_query result;
    result.hashes = malloc(sizeof(char *) * bpkg->nchunks);
    if (!result.hashes) {
        fprintf(stderr, "Failed to allocate memory for result hashes.\n");
        result.len = 0;
        return result;
    }

    
    char **hashes = malloc(sizeof(char *) * bpkg->nchunks);
    for (uint32_t i = 0; i < bpkg->nchunks; i++) {
        hashes[i] = strdup(bpkg->chunks[i].hash);
    }

    struct merkle_tree_node **nodes;
    int total_nodes;
    struct merkle_tree_node *root = build_merkle_tree(bpkg, hashes, &nodes, &total_nodes);
    if (!root) {
        fprintf(stderr, "Failed to build Merkle tree.\n");
        result.len = 0;
        for (uint32_t i = 0; i < bpkg->nchunks; i++) {
            free(hashes[i]);
        }
        free(hashes);
        return result;
    }

    
    struct merkle_tree_node *node = root;
    if (strcmp(node->computed_hash, hash) != 0) {
        int found = 0;
        struct merkle_tree_node *stack[bpkg->nchunks * 2];
        int stack_size = 0;
        stack[stack_size++] = node;
        while (stack_size > 0 && !found) {
            node = stack[--stack_size];
            if (node->left) stack[stack_size++] = node->left;
            if (node->right) stack[stack_size++] = node->right;
            if (strcmp(node->computed_hash, hash) == 0) found = 1;
        }
        if (!found) {
            fprintf(stderr, "Hash not found in Merkle tree.\n");
            result.len = 0;
            for (uint32_t i = 0; i < bpkg->nchunks; i++) {
                free(hashes[i]);
            }
            free(hashes);
            free_tree(nodes, total_nodes);
            return result;
        }
    }

    
    int count = 0;
    struct merkle_tree_node *stack[bpkg->nchunks * 2];
    int stack_size = 0;
    stack[stack_size++] = node;
    while (stack_size > 0) {
        node = stack[--stack_size];
        if (node->is_leaf) {
            result.hashes[count++] = strdup(node->computed_hash);
        } else {
            if (node->left) stack[stack_size++] = node->left;
            if (node->right) stack[stack_size++] = node->right;
        }
    }

    result.len = count;

    free_tree(nodes, total_nodes);
    for (uint32_t i = 0; i < bpkg->nchunks; i++) {
        free(hashes[i]);
    }
    free(hashes);

    return result;
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
void bpkg_obj_destroy(bpkg_obj *obj) {
    if (!obj) return;
    if (obj->ident) free(obj->ident);
    if (obj->filename) free(obj->filename);
    if (obj->hashes) {
        for (int i = 0; i < obj->nhashes; i++) {
            if (obj->hashes[i]) free(obj->hashes[i]);
        }
        free(obj->hashes);
    }
    if (obj->chunks) {
        for (int i = 0; i < obj->nchunks; i++) {
            if (obj->chunks[i].hash) free(obj->chunks[i].hash);
        }
        free(obj->chunks);
    }
    free(obj);
}



