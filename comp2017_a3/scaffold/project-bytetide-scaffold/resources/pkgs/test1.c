#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include <ctype.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define SHA256K 64
#define rotate_r(val, bits) (val >> bits | val << (32 - bits))
#define SHA256_HEXLEN (64)


#define SHA256_CHUNK_SZ (64)
#define SHA256_INT_SZ (8)
#define SHA256_DFTLEN (1024)

//Original: https://github.com/LekKit/sha256/blob/master/sha256.h
struct sha256_compute_data {
	uint64_t data_size;
	uint32_t hcomps[SHA256_INT_SZ];
	uint8_t last_chunk[SHA256_CHUNK_SZ];
	uint8_t chunk_size;
};

void sha256_calculate_chunk(struct sha256_compute_data* data,
		uint8_t chunk[SHA256_CHUNK_SZ]);

void sha256_compute_data_init(struct sha256_compute_data* data);

void sha256_update(struct sha256_compute_data* data,
		void* bytes, uint32_t size); 

void sha256_finalize(struct sha256_compute_data* data, 
		uint8_t hash[SHA256_INT_SZ]);


void sha256_output_hex(struct sha256_compute_data* data, 
		char hexbuf[SHA256_CHUNK_SZ]);

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
    size_t leaf_count;
};
typedef struct{
	char* hash;
	uint32_t offset;
	uint32_t size;
}Chunks;

//TODO: Provide a definition
typedef struct{
	char* ident;
	char* filename;
	uint32_t size;
	uint32_t nhashes;
	char** hashes;
	uint32_t nchunks;
	Chunks* chunks;
}bpkg_obj;

// void bpkg_load(const char* path);
bpkg_obj* bpkg_load(const char* path);
struct merkle_tree_node* create_node(char* hash, char isLeaf);
struct merkle_tree_node* build_merkle_tree(char** data, int start, int end, int* leaf_count);
void free_merkle_tree(struct merkle_tree_node* node);
int is_blank(const char *line);


//Constant List from: https://en.wikipedia.org/wiki/SHA-2#Pseudocode
static const uint32_t k[SHA256K] = {
    0x428a2f98, 0x71374491, 
    0xb5c0fbcf, 0xe9b5dba5, 
    0x3956c25b, 0x59f111f1, 
    0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 
    0x243185be, 0x550c7dc3, 
    0x72be5d74, 0x80deb1fe, 
    0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 
    0x0fc19dc6, 0x240ca1cc, 
    0x2de92c6f, 0x4a7484aa, 
    0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 
    0xb00327c8, 0xbf597fc7, 
    0xc6e00bf3, 0xd5a79147, 
    0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 
    0x4d2c6dfc, 0x53380d13, 
    0x650a7354, 0x766a0abb, 
    0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 
    0xc24b8b70, 0xc76c51a3, 
    0xd192e819, 0xd6990624, 
    0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 
    0x2748774c, 0x34b0bcb5, 
    0x391c0cb3, 0x4ed8aa4a, 
    0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 
    0x84c87814, 0x8cc70208, 
    0x90befffa, 0xa4506ceb, 
    0xbef9a3f7, 0xc67178f2
};

//Initialisation From: https://en.wikipedia.org/wiki/SHA-2#Pseudocode
//and https://github.com/LekKit/sha256/blob/master/sha256.c
void sha256_compute_data_init(struct sha256_compute_data* data) {
	data->hcomps[0] = 0x6a09e667;
	data->hcomps[1] = 0xbb67ae85;
	data->hcomps[2] = 0x3c6ef372;
	data->hcomps[3] = 0xa54ff53a;
	data->hcomps[4] = 0x510e527f;
	data->hcomps[5] = 0x9b05688c;
	data->hcomps[6] = 0x1f83d9ab;
	data->hcomps[7] = 0x5be0cd19;

	data->data_size = 0;
	data->chunk_size = 0;

}

//Derived from: https://en.wikipedia.org/wiki/SHA-2#Pseudocode
//And https://github.com/LekKit/sha256/blob/master/sha256.c
void sha256_calculate_chunk(struct sha256_compute_data *data, 
		uint8_t chunk[SHA256_CHUNK_SZ]) {
	uint32_t w[SHA256_CHUNK_SZ];
	uint32_t tv[SHA256_INT_SZ];

    //
	for(uint32_t i = 0; i < 16; i++) {
		w[i] = (uint32_t) chunk[0] << 24 
			| (uint32_t) chunk[1] << 16 
			| (uint32_t) chunk[2] << 8 
			| (uint32_t) chunk[3];

		chunk += 4;
	}

    //
	for(uint32_t i = 16; i < 64; i++) {
		
		uint32_t s0 = rotate_r(w[i-15], 7) 
			    ^ rotate_r(w[i-15], 18) 
			    ^ (w[i-15] >> 3);
		
		uint32_t s1 = rotate_r(w[i-2], 17) 
			    ^ rotate_r(w[i-2], 19) 
			    ^ (w[i-2] >> 10);

		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}

	for(uint32_t i = 0; i < SHA256_INT_SZ; i++) {
		tv[i] = data->hcomps[i];
	}

	for(uint32_t i = 0; i < SHA256_CHUNK_SZ; i++) {
		uint32_t S1 = rotate_r(tv[4], 6) 
			    ^ rotate_r(tv[4], 11) 
			    ^ rotate_r(tv[4], 25);

		uint32_t ch = (tv[4] & tv[5]) 
			    ^ (~tv[4] & tv[6]);
		
		uint32_t temp1 = tv[7] + S1 + ch + k[i] + w[i];
		
		uint32_t S0 = rotate_r(tv[0], 2) 
			    ^ rotate_r(tv[0], 13) 
			    ^ rotate_r(tv[0], 22);
		
		uint32_t maj = (tv[0] & tv[1]) 
			     ^ (tv[0] & tv[2]) 
			     ^ (tv[1] & tv[2]);
		
		uint32_t temp2 = S0 + maj;
		
		tv[7] = tv[6];
		tv[6] = tv[5];
		tv[5] = tv[4];
		tv[4] = tv[3] + temp1;
		tv[3] = tv[2];
		tv[2] = tv[1];
		tv[1] = tv[0];
		tv[0] = temp1 + temp2;
	}

	for(uint32_t i = 0; i < SHA256_INT_SZ; i++) {
		data->hcomps[i] += tv[i];
	}
}

//Derived from: https://en.wikipedia.org/wiki/SHA-2#Pseudocode
//And https://github.com/LekKit/sha256/blob/master/sha256.c
void sha256_update(struct sha256_compute_data *data, 
		void *bytes, uint32_t size) {
	
	uint8_t* ptr = (uint8_t*) bytes;
	data->data_size += size;
	
	if (size + data->chunk_size >= 64) {
		uint8_t tmp_chunk[64];
		memcpy(tmp_chunk, 
				data->last_chunk, 
				data->chunk_size);
		memcpy(tmp_chunk + data->chunk_size, 
				ptr, 
				64 - data->chunk_size);
		ptr += (64 - data->chunk_size);
		size -= (64 - data->chunk_size);
		data->chunk_size = 0;
		sha256_calculate_chunk(data, tmp_chunk);
	}

	while (size >= 64) {
		sha256_calculate_chunk(data, ptr);
		ptr += 64;
		size -= 64; 
	}

	memcpy(data->last_chunk + data->chunk_size, ptr, size);
	data->chunk_size += size;
}

//Derived from: https://en.wikipedia.org/wiki/SHA-2#Pseudocode
//And https://github.com/LekKit/sha256/blob/master/sha256.c
void sha256_finalize(struct sha256_compute_data *data, 
		uint8_t hash[SHA256_INT_SZ]) {
	
	

	data->last_chunk[data->chunk_size] = 0x80;
	data->chunk_size++;

	memset(data->last_chunk + 
			data->chunk_size, 
			0, 
			64 - data->chunk_size);

	if (data->chunk_size > 56) {
		sha256_calculate_chunk(data, data->last_chunk);
		memset(data->last_chunk, 0, 64);
	}

	/* Add total size as big-endian int64 x8 */
	uint64_t size = data->data_size * 8;
	
	for (int32_t i = 8; i > 0; --i) {
		data->last_chunk[55+i] = size & 255;
		size >>= 8;
	}

	sha256_calculate_chunk(data, data->last_chunk);
}

//Original: https://github.com/LekKit/sha256/blob/master/sha256.c
void sha256_output(struct sha256_compute_data* data, 
		uint8_t* hash) {
	for (uint32_t i = 0; i < 8; i++) {
		hash[i*4] = (data->hcomps[i] >> 24) & 255;
		hash[i*4 + 1] = (data->hcomps[i] >> 16) & 255;
		hash[i*4 + 2] = (data->hcomps[i] >> 8) & 255;
		hash[i*4 + 3] = data->hcomps[i] & 255;
	}
}

//Original: https://github.com/LekKit/sha256/blob/master/sha256.c
static void bin_to_hex(const void* data, uint32_t len, char* out) {
    
	static const char* const lut = "0123456789abcdef";

	for (uint32_t i = 0; i < len; ++i){
		uint8_t c = ((const uint8_t*)data)[i];
		out[i*2] = lut[c >> 4];
		out[i*2 + 1] = lut[c & 15];
	}
}

//Original: https://github.com/LekKit/sha256/blob/master/sha256.c
void sha256_output_hex(struct sha256_compute_data* data, 
		char hexbuf[SHA256_CHUNK_SZ]) {
	uint8_t hash[32] = { 0 };
	sha256_output(data, hash);
	bin_to_hex(hash, 32, hexbuf);
}


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
        return NULL;
    }

    FILE* file = fopen(path, "r");
    if (file == NULL) {
        perror("Failed to open file");
        free(obj);
        return NULL;
    }

    char buffer[1025];
    memset(buffer, 0, sizeof(buffer));  // Initialize buffer to zero

    // Read identifier
    if (!fgets(buffer, sizeof(buffer), file) || buffer[5] != ':') {
        fprintf(stderr, "Failed to read identifier\n");
        fclose(file);
        free(obj);
        return NULL;
    }
    buffer[strcspn(buffer, "\r\n")] = 0;  // Remove newline characters
    obj->ident = strdup(buffer + 6);
    printf("Ident: %s\n", obj->ident);

    clear_rest_line(file, buffer);

    // Read filename
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

    // Read size
    if (!fgets(buffer, sizeof(buffer), file) || sscanf(buffer, "size:%u", &obj->size) != 1) {
        fprintf(stderr, "Failed to parse size.\n");
        fclose(file);
        free(obj->filename);
        free(obj->ident);
        free(obj);
        return NULL;
    }
    printf("Size: %u\n", obj->size);

    // Read nhashes
    if (!fgets(buffer, sizeof(buffer), file) || sscanf(buffer, "nhashes:%u", &obj->nhashes) != 1) {
        fprintf(stderr, "Failed to parse nhashes.\n");
        fclose(file);
        free(obj->filename);
        free(obj->ident);
        free(obj);
        return NULL;
    }
    printf("Nhashes: %u\n", obj->nhashes);
    // Read and allocate nchunks
    // Assuming that `obj->nhashes` represents the number of actual non-empty hash entries you expect
obj->hashes = (char**)malloc(obj->nhashes * sizeof(char*));  // Allocate memory for storing hashes
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
int actualIndex = 0;  // This will keep track of non-empty lines
for (int i = 0; i < obj->nhashes * 2; i++) {
    char* tempstore = (char*)malloc(66);  // Temporary storage for a line
    if (fgets(tempstore, 66, file) == NULL) {
        free(tempstore);
        break;  // Exit if there are no more lines to read
    }

    // Check if the line is not just empty or whitespace
    if (tempstore[0] != '\n' && tempstore[0] != '\r' && strlen(tempstore) > 0) {
        // Ensure there is enough allocated space
        if (actualIndex > obj->nhashes) {
            fprintf(stderr, "More non-empty lines than expected\n");
            break;
        }

        obj->hashes[actualIndex] = (char*)malloc(66);  // Allocate space for each hash
        if (obj->hashes[actualIndex] == NULL) {
            fprintf(stderr, "Failed to allocate memory for hash %d\n", actualIndex);
            free(tempstore);
            break;
        }

        strcpy(obj->hashes[actualIndex], tempstore);  // Copy non-empty line into hashes
        obj->hashes[actualIndex][strcspn(obj->hashes[actualIndex], "\r\n")] = 0;  // Remove newline characters
        printf("%d: %s\n", actualIndex, obj->hashes[actualIndex]);
        actualIndex++;  // Increment the count of actual hashes
    }

    free(tempstore);
}

// Now actualIndex should hold the count of non-blank hashes
if (actualIndex != obj->nhashes) {
    fprintf(stderr, "Mismatch in the number of expected non-empty hashes\n");
    // You may want to handle this case according to your needs
}

    char tempb[65];
    

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
    while (fgets(line, sizeof(line), file) && index < obj->nchunks) {
        obj->chunks[index].hash = malloc(65);
        if (obj->chunks[index].hash == NULL) {
            fprintf(stderr, "Failed to allocate memory for hash\n");
            fclose(file);
            return NULL;
        }

        // Parse the line
        sscanf(line, "%64[^,],%lu,%lu", obj->chunks[index].hash, &tempOffset, &tempSize);
        obj->chunks[index].offset = (uint32_t)tempOffset;
        obj->chunks[index].size = (uint32_t)tempSize;
        // Remove potential newline character
         obj->chunks[index].hash[strcspn(obj->chunks[index].hash, "\r\n")] = 0;

        index++;
    }


    // Example usage: Print each chunk's information
    for (int i = 0; i < obj->nchunks; i++) {
        printf("Chunk %d: Hash = %s, Offset = %u, Size = %u\n",
               i, obj->chunks[i].hash, obj->chunks[i].offset, obj->chunks[i].size);
    }

    // Free the allocated memory
    free(obj->chunks);

    fclose(file);
    return obj;
}

int is_blank(const char *line) {
    for (; *line != '\0'; line++) {
        if (!isspace((unsigned char)*line)) {
            return 0; // Not blank
        }
    }
    return 1; // Blank
}

void get_sha256_hash(char* input, char* output) {
    struct sha256_compute_data data;
    sha256_compute_data_init(&data);
    sha256_update(&data, input, strlen(input));
    sha256_finalize(&data, (uint8_t*)output);
    sha256_output_hex(&data, output);  // Assumes output is large enough to hold the hash
}


struct merkle_tree_node* create_node(char* hash, char isLeaf) {
    struct merkle_tree_node* node = malloc(sizeof(struct merkle_tree_node));
    if (!node) {
        return NULL;
    }
    if (isLeaf) {
        // Directly use the hash for leaf nodes
        strncpy(node->computed_hash, hash, 64);
        node->computed_hash[SHA256_CHUNK_SZ] = '\0';
    } else {
        // Compute the hash for internal nodes
        get_sha256_hash(hash, node->computed_hash);
        printf("computed hash: %s\n\n", node->computed_hash);
    }
    node->left = node->right = NULL;
    return node;
}




struct merkle_tree_node* build_merkle_tree(char** data, int start, int end, int* leaf_count) {
    if (start > end) {
        return NULL; // Empty tree for invalid range
    }
    if (start == end) {
        if (leaf_count) (*leaf_count)++;
        return create_node(data[start], 1);
    }
    int mid = (start + end) / 2;
    struct merkle_tree_node* left = build_merkle_tree(data, start, mid, leaf_count);
    struct merkle_tree_node* right = build_merkle_tree(data, mid + 1, end, leaf_count);
    if (!left || !right) {
        free_merkle_tree(left);
        free_merkle_tree(right);
        return NULL;
    }
    char concatenated_hashes[2 * 66] = {0};
    snprintf(concatenated_hashes, sizeof(concatenated_hashes), "%s%s", left->computed_hash, right->computed_hash);
    //printf("leaf count:%d\n",*leaf_count);
    struct merkle_tree_node* parent = create_node(concatenated_hashes, 0);
    parent->left = left;
    parent->right = right;
    //printf("leaf count:%d\n",*leaf_count);
    return parent;
}


void free_merkle_tree(struct merkle_tree_node* node) {
    if (!node) return;
    free_merkle_tree(node->left);
    free_merkle_tree(node->right);
    free(node);
}

// int build_tree(struct merkle_tree* mtree, unsigned char** hashes, int length){
//     //initial the counter
//     int i,j;
//     int leaf_count = strlen(hashes);
//     int node_count = (leaf_count*2)-1;
//     //initial the tree construct
    
//     for(i=0;i<node_count;i++){
//         mtree->root[i].value =  (char*)malloc(sizeof(char)*16);
//         mtree->root[i].key = i;
//         mtree->root[i].left = -1;
//         mtree->root[i].right = -1;
//         mtree->root[i].computed_hash = hashes[i];
//     }
// }


int main(){     
    char* filename = "file1.bpkg";
    bpkg_obj* obj = malloc(sizeof(bpkg_obj));
    obj = bpkg_load(filename);
    int leaf_count = 0;
    struct merkle_tree_node* root = build_merkle_tree(obj->hashes, 0, obj->nhashes, &leaf_count);
    printf("Leaf count: %d\n", leaf_count);
    free_merkle_tree(root);
    return 0;
}