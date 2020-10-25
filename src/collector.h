#ifndef H_COLLECTOR

#include <pcap.h>

void collectorInit();
pcap_t *createNewHandler(char*, int, int, int, int, int);
void closeHandler(pcap_t*);

#endif
#define H_COLLECTOR