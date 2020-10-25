#ifndef H_MDATA

#include <sys/time.h>
#include <netinet/ip.h>

struct mdata{
    struct in_addr ip_des;
    struct in_addr ip_src;
    unsigned short port_des;
    unsigned short port_src;
    unsigned char proto;
    struct timeval ts; //precise time
};

#endif
#define H_MDATA