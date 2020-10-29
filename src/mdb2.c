#include "mdb2.h"
#include "mdata.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//Note that there are much from local network, the hash algorithm may be better.

unsigned int hashData(struct mdata* data, unsigned int seed){ //Currently only focus on src ip & port
    unsigned int result = seed;
    result = (result << 2) ^ result ^ (data->ip_src.s_addr) ^ (data->ip_src.s_addr >> 16);
    result = (result << 2) ^ result ^ data->port_src;
    return result & MDB_HASH_POOL_MASK;
}

unsigned int hashDataReversed(struct mdata* data, unsigned int seed){ //Currently only focus on dst ip & port
    unsigned int result = seed;
    result = (result << 2) ^ result ^ (data->ip_des.s_addr) ^ (data->ip_des.s_addr >> 16);
    result = (result << 2) ^ result ^ data->port_des;
    return result & MDB_HASH_POOL_MASK;
}

int getValidPos(struct mdb* db, int current_key, unsigned int init_pos){
    init_pos &= MDB_HASH_POOL_MASK;
    int counter = 6; //SPEED LIMIT
    while(db->table_key[init_pos] >= 0 && db->table_key[init_pos] != current_key && counter --)
        init_pos = (init_pos + 133) & MDB_HASH_POOL_MASK;
    return init_pos;
}

int getPos(struct mdb* db, int current_key, unsigned int init_pos){
    init_pos &= MDB_HASH_POOL_MASK;
    int counter = 6; //SPEED LIMIT
    while(db->table_key[init_pos] != current_key && counter --)
        init_pos = (init_pos + 133) & MDB_HASH_POOL_MASK;
    if(db->table_key[init_pos] != current_key)
        return -1;
    return init_pos;
}

void mdb_init(struct mdb* db){
    memset(db->table_header, 0, sizeof(db->table_header));
    memset(db->table_tail, 0, sizeof(db->table_tail));
    memset(db->table_key, -1, sizeof db->table_key);
    db->seed = rand() & MDB_HASH_POOL_MASK;
    db->seed2 = rand() & MDB_HASH_POOL_MASK;
}

int mdb_try_insert(struct mdb* db, struct mdata* data){
//return MDB_FAIL;
// fprintf(stderr, "INSERTING\n");
    unsigned int hash_val = hashData(data, db->seed);
    int current_key = hashData(data, db->seed2);
    int pos = getValidPos(db, current_key, hash_val);
    struct datablock* block = malloc(sizeof(struct datablock));
    block->data = data;
    block->next_block = NULL;
// fprintf(stderr, "%d %d %lld\n", pos, current_key, db->table_key[pos]);
//fprintf(stderr, "%lld\n", db->table_tail[pos]);
    if(db->table_key[pos] == current_key) {
        db->table_tail[pos]->next_block = block;
	db->table_tail[pos] = block;
    }else if(db->table_key[pos] == -1){
        db->table_key[pos] = current_key;
        db->table_header[pos] = block;
        db->table_tail[pos] = block;
    }else{
        struct datablock* tmp;
        while(tmp = db->table_header[pos]){
            db->table_header[pos] = tmp->next_block;
            free(tmp->data); //Packet loss
            free(tmp);
        }
        db->table_key[pos] = current_key;
        db->table_header[pos] = block;
        db->table_tail[pos] = block;
    }
    return MDB_SUCCESS;
}

struct mdata* mdb_search(struct mdb* db, struct mdata* data, int pop){
//	return NULL;
    unsigned int hash_val = hashDataReversed(data, db->seed);
    int current_key = hashDataReversed(data, db->seed2);
    int pos = getPos(db, current_key, hash_val);
    if(pos == -1)
        return NULL;
    struct mdata* result = db->table_header[pos]->data;
    struct datablock* tmp = db->table_header[pos];
    
    if(pop){
        db->table_header[pos] = tmp->next_block;
        if(!tmp->next_block) {
            db->table_tail[pos] = NULL;
            db->table_key[pos] = -1;
        }
        free(tmp);
    }
    
    return result;
}

void mdb_destroy(struct mdb* db){
}
