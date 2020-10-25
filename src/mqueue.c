#include "mqueue.h"
#include "mdata.c"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int mqueue_push(struct mqueue* que, struct mdata* data){
    if(que->qsize == que->buffsize)
        return QUEUE_FAIL;
    que->qsize ++;
    que->data[que->end_p++] = data;
    if(que->end_p == que->buffsize)
        que->end_p -= que->buffsize;
    return QUEUE_SUCCESS;
}

void mqueue_pop(struct mqueue* que){
    if(que->qsize == 0)
        return ;
    que->qsize --;
    que->front_p ++;
    if(que->front_p == que->buffsize)
        que->front_p -= que->buffsize;
}

struct mdata* mqueue_front(struct mqueue* que){
    return que->data[que->front_p];
}

unsigned int mqueue_size(struct mqueue* que){
    return que->qsize;
}

void mqueue_init(struct mqueue* que, int buffsize){ // buffsize must be (1 << n)
    que->data = (struct mdata**)malloc(sizeof(struct mdata*) * buffsize);
    que->buffsize = buffsize;
    que->front_p = 0;
    que->end_p = 0;
    que->qsize = 0;
}

void mqueue_destroy(struct mqueue* que){
    free(que->data);
    memset(que, 0, sizeof(struct mqueue));
}