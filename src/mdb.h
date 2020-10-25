#ifndef H_MDB
#include "mdata.h"

#define MDB_HASH_COUNTER 3
#define MDB_HASH_POOL_SIZE 2097152
#define MDB_HASH_POOL_MASK 2097151u

struct mdb {
    struct mdata** data_queue; //Used to store detailed info.
    int hash_table[MDB_HASH_COUNTER][MDB_HASH_POOL_SIZE];
    unsigned int seeds[MDB_HASH_COUNTER];
}; //Used to store permanent data & store to hard driver.

int mdb_try_insert(struct mdb*, struct mdata*);
void mdb_init(struct mdb*);
struct mdata* mdb_search(struct mdb*, struct mdata*, int);

#define MDB_FAIL -1
#define MDB_SUCCESS 0

#endif
#define H_MDB