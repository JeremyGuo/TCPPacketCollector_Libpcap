#ifndef H_MDB
#include "mdata.h"

#define MDB_HASH_POOL_SIZE 2097152
#define MDB_HASH_POOL_MASK 2097151u

struct datablock{
    struct mdata* data;
    struct datablock* next_block;
};

struct mdb {
    struct datablock* table_header[MDB_HASH_POOL_SIZE];
    struct datablock* table_tail[MDB_HASH_POOL_SIZE];
    int table_key[MDB_HASH_POOL_SIZE];
    unsigned int seed;
    unsigned int seed2;
}; //Used to store permanent data & store to hard driver.

int mdb_try_insert(struct mdb*, struct mdata*);
void mdb_init(struct mdb*);
struct mdata* mdb_search(struct mdb*, struct mdata*, int);

#define MDB_FAIL -1
#define MDB_SUCCESS 0

#endif
#define H_MDB
