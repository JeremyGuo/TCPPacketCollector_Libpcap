#ifndef H_LOCALSTORAGE

#include "mdata.h"

struct LocalParam{
    char *dst;
};

int local_set_param(struct LocalParam*);
int local_save(struct mdata*);

#define LOCAL_FAIL -1
#define LOCAL_SUCCESS 0
#define LOCAL_SAVE_COUNTER 1

#endif
#define H_LOCALSTORAGE