#include "../include/chk/pkgchk.h"
#include "../include/crypt/sha256.h"
#include "../include/tree/merkletree.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
//#include "../resources/pkgs/test.c"
//#include "chk/pkgchk.c"
//#include "crypt/sha256.c"
//#include "tree/merkletree.c"

#define SHA256_HEX_LEN (64)


char** read_computed_hash(char* data_filename, bpkg_obj* obj);
int arg_select(int argc, char** argv, int* asel, char* harg) {
	
	
	char* cursor = argv[2];
	*asel = 0;
	if(argc < 3) {
		puts("bpkg or flag not provided");
		exit(1);
	}

	if(strcmp(cursor, "-all_hashes") == 0) {
		*asel = 1;
	}
	if(strcmp(cursor, "-chunk_check") == 0) {
		*asel = 2;
	}
	if(strcmp(cursor, "-min_hashes") == 0) {
		*asel = 3;
	}
	if(strcmp(cursor, "-hashes_of") == 0) {
		if(argc < 4) {
			puts("filename not provided");
			exit(1);
		}
		*asel = 4;
		strncpy(harg, argv[3], SHA256_HEX_LEN);
	}
	if(strcmp(cursor, "-file_check") == 0) {
		*asel = 5;
	}
	if(strcmp(cursor, "lookall") == 0) {
		*asel = 6;
	}
	return *asel;
}


void bpkg_print_hashes(struct bpkg_query* qry) {
	for(int i = 0; i < qry->len; i++) {
		printf("%.64s\n", qry->hashes[i]);
	}
	
}



char** read_computed_hash(char* data_filename, bpkg_obj* obj) {
    // Define the base directory where the data files are located
    const char* base_directory = "resources/pkgs/";
    
    // Allocate memory for the full path
    size_t full_path_len = strlen(base_directory) + strlen(data_filename) + 1;
    char* full_path = malloc(full_path_len);
    if (!full_path) {
        fprintf(stderr, "Failed to allocate memory for the file path.\n");
        return NULL;
    }
    
    // Construct the full path
    snprintf(full_path, full_path_len, "%s%s", base_directory, data_filename);

    // Open the file using the full path
    FILE* data_file = fopen(full_path, "rb");
    if (data_file == NULL) {
        perror("Failed to open file");
        free(full_path);
        return NULL;
    }
    char **computed_hashes = malloc(obj->nchunks * sizeof(char *));
    if (!computed_hashes) {
        fprintf(stderr, "Failed to allocate hashes.\n");
        fclose(data_file);
        free(full_path);
        return NULL;
    }

    for (int i = 0; i < obj->nchunks; i++) {
        fseek(data_file, obj->chunks[i].offset, SEEK_SET);
        char *data_chunk = malloc(obj->chunks[i].size);
        if (!data_chunk) {
            fprintf(stderr, "Failed to allocate data chunk.\n");
            // Free already allocated memory
            for (int j = 0; j < i; j++) {
                free(computed_hashes[j]);
            }
            free(computed_hashes);
            fclose(data_file);
            free(full_path);
            return NULL;
        }

        size_t read_size = fread(data_chunk, 1, obj->chunks[i].size, data_file);
        if (read_size != obj->chunks[i].size) {
            fprintf(stderr, "Failed to read data chunk.\n");
            free(data_chunk);
            // Free already allocated memory
            for (int j = 0; j < i; j++) {
                free(computed_hashes[j]);
            }
            free(computed_hashes);
            fclose(data_file);
            free(full_path);
            return NULL;
        }

        char computed_hash[SHA256_HEXLEN + 1];
        struct sha256_compute_data cdata;
        sha256_compute_data_init(&cdata);
        sha256_update(&cdata, data_chunk, obj->chunks[i].size);
        sha256_output_hex(&cdata, computed_hash);
        computed_hash[SHA256_HEXLEN] = '\0';
        computed_hashes[i] = strdup(computed_hash);
	if (!computed_hashes[i]) {
            fprintf(stderr, "Failed to duplicate hash.\n");
            free(data_chunk);
            for (int j = 0; j <= i; j++) {
                free(computed_hashes[j]);
            }
            free(computed_hashes);
            fclose(data_file);
            free(full_path);
            return NULL;
        }
        free(data_chunk);
    }

    fclose(data_file);
    free(full_path);
    return computed_hashes;
}


int main(int argc, char** argv) {
	
	int argselect = 0;
	char hash[SHA256_HEX_LEN];


	if(arg_select(argc, argv, &argselect, hash)) {
		struct bpkg_query qry = { 0 };
		bpkg_obj* obj = bpkg_load(argv[1]);
		printf("load over!\n");
		char **computed_hashes; 
    		computed_hashes = read_computed_hash(obj->filename,obj);
    		if (!computed_hashes) {
            		fprintf(stderr, "Failed to read computed hashes.\n");
            		return -1;
        }
    		for(int i=0;i<obj->nchunks;i++){
                       printf("computed hash: %s\n",computed_hashes[i]);

                }
                struct merkle_tree_node **nodes;
                int total_nodes;
                struct merkle_tree_node *root = build_merkle_tree(obj, computed_hashes, &nodes, &total_nodes);
    		if (!root) {
        	    fprintf(stderr, "Failed to build Merkle tree.\n");
                    return -1;
    		}
		if(!obj) {
			puts("Unable to load pkg and tree");
			exit(1);
		}

		if(argselect == 1) {
			qry = bpkg_get_all_hashes(obj);
			bpkg_print_hashes(&qry);
			bpkg_query_destroy(&qry);
		} else if(argselect == 2) {

			qry = bpkg_get_completed_chunks(obj,computed_hashes);
			bpkg_print_hashes(&qry);
			bpkg_query_destroy(&qry);
		} else if(argselect == 3) {

			qry = bpkg_get_min_completed_hashes(obj);
			bpkg_print_hashes(&qry);
			bpkg_query_destroy(&qry);
		} else if(argselect == 4) {

			qry = bpkg_get_all_chunk_hashes_from_hash(obj, 
					hash);
			bpkg_print_hashes(&qry);
			bpkg_query_destroy(&qry);
		} else if(argselect == 5) {

			qry = bpkg_file_check(obj);
			bpkg_print_hashes(&qry);
			bpkg_query_destroy(&qry);
		}else if(argselect == 6){
		        printf("simple check\n");
		} else {
			puts("Argument is invalid");
			return 1;
		}
		
		for (int i = 0; i < obj->nchunks; i++) {
            		free(computed_hashes[i]);
        	}
		free(computed_hashes);
		//int total = (obj->nchunks+obj->nhashes);
        	free_tree(nodes,total_nodes); 
        	bpkg_obj_destroy(obj); 

	}

	return 0;
}

