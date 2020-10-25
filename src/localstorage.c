#include "localstorage.h"
#include <sys/file.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

FILE* fhandler = NULL;
int fd = -1;
unsigned int save_counter;

int local_set_param(struct LocalParam* param){
    if(fhandler){
        fclose(fhandler);
        fhandler = NULL;
        fd = -1;
    }
    save_counter = LOCAL_SAVE_COUNTER;
    fhandler = fopen(param->dst, "wb");
    if(!fhandler)
        return LOCAL_FAIL;
    fd = fileno(fhandler);
    return LOCAL_SUCCESS;
}

int local_save(struct mdata* data){
    if(fd == -1)
        return LOCAL_FAIL;
    flock(fd, LOCK_EX);
    lseek(fd, 0, SEEK_SET);
    if(write(fd, (void*)data, sizeof(struct mdata)) == -1){
        flock(fd, LOCK_UN);
        return LOCAL_FAIL;
    }
    save_counter --;
    if(!save_counter){
        save_counter = LOCAL_SAVE_COUNTER;
        fflush(fhandler);
    }
    flock(fd, LOCK_UN);
    return LOCAL_SUCCESS;
}
