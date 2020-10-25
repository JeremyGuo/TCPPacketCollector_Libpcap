#ifndef H_MQUEUE

#include "mdata.h"

struct mqueue{
    struct mdata** data;
    unsigned int front_p;
    unsigned int end_p;
    unsigned int qsize;
    unsigned int buffsize;
}; //Used to store temp data.

void mqueue_init(struct mqueue*, int);
unsigned int mqueue_size(struct mqueue*);
struct mdata* mqueue_front(struct mqueue*);
void mqueue_pop(struct mqueue*);
int mqueue_push(struct mqueue*, struct mdata*);
void mqueue_destroy(struct mqueue*);

#define QUEUE_SUCCESS 0
#define QUEUE_FAIL -1

#endif
#define H_MQUEUE