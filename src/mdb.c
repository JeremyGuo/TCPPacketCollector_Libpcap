#include "mdb.h"
#include "mdata.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//Note that there are much from local network, the hash algorithm may be better.

unsigned int hashData(struct mdata* data, unsigned int seed){ //Currently only focus on src ip & port
    unsigned int result = seed;
    result = (result << 2) ^ result ^ data->ip_src.s_addr;
    result = (result << 2) ^ result ^ data->port_src;
    return result & MDB_HASH_POOL_MASK;
}

unsigned int hashDataReversed(struct mdata* data, unsigned int seed){ //Currently only focus on dst ip & port
    unsigned int result = seed;
    result = (result << 2) ^ result ^ data->ip_des.s_addr;
    result = (result << 2) ^ result ^ data->port_des;
    return result & MDB_HASH_POOL_MASK;
}

int getValidPos(struct mdb* db, unsigned int init_pos){
    static unsigned int random_seed = 19260817;
    random_seed = (random_seed << 2) ^ random_seed ^ 1;
    init_pos ^= random_seed;
    init_pos &= MDB_HASH_POOL_MASK;
    int counter = 1000; //SPEED LIMIT
    while(db->data_queue[init_pos] && counter --)
        init_pos = (init_pos + 133) & MDB_HASH_POOL_MASK;
    if(!db->data_queue[init_pos])
        return init_pos;
    return -1;
}

void mdb_init(struct mdb* db){
    unsigned int i;
    db->data_queue = malloc(sizeof(struct mdb*)*MDB_HASH_POOL_SIZE);
    memset(db->hash_table, -1, sizeof db->hash_table);
    for(i=0;i<MDB_HASH_COUNTER;i++)
        db->seeds[i] = rand() & MDB_HASH_POOL_MASK;
}

int mdb_try_insert(struct mdb* db, struct mdata* data){
    unsigned int i = 0;
    unsigned int hash_val[MDB_HASH_COUNTER];
    for(i=0;i<MDB_HASH_COUNTER;i++)
        hash_val[i] = hashData(data, db->seeds[i]);
    int pos = getValidPos(db, hash_val[0]);
    if(pos == -1)
        return MDB_FAIL;
    db->data_queue[pos] = data;
    for(i=0;i<MDB_HASH_COUNTER;i++)
        db->hash_table[i][hash_val[i]] = pos;
    return MDB_SUCCESS;
}

struct mdata* mdb_search(struct mdb* db, struct mdata* data, int pop){
    unsigned int i;
    unsigned int hash_val[MDB_HASH_COUNTER];
    for(i=0;i<MDB_HASH_COUNTER;i++)
        hash_val[i] = hashDataReversed(data, db->seeds[i]);
    int current_counter = 0;
    int current_id = -1;
    int current_table_id;
    for(i=0;i<MDB_HASH_COUNTER;i++){
        current_table_id = db->hash_table[i][hash_val[i]];
        if(current_table_id < 0)
            continue;
        if(current_table_id == current_id)
            current_counter ++;
        else{
            if(!current_counter) {
                current_counter = 1;
                current_id = current_table_id;
            }else current_counter --;
        }
    }
    if(current_id == -1)
        return NULL;
    struct mdata* result = db->data_queue[current_id];
    if(pop){
        for(int i=0;i<MDB_HASH_COUNTER;i++){
            if(db->hash_table[i][hash_val[i]] == current_id)
                db->hash_table[i][hash_val[i]] = -1;
        }
        db->data_queue[current_id] = NULL;
    }
    return result;
}

void mdb_destroy(struct mdb* db){
    free(db->data_queue);
    db->data_queue = NULL;
}
