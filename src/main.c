#include "collector.h"
#include "mqueue.h"
#include "mdata.h"
#ifndef MDB2
#include "mdb.h"
#else
#include "mdb2.h"
#endif
#include "localstorage.h"

#include<stdio.h>
#include<stdlib.h>
#include<stdio.h>
#include<sys/types.h>
#include<sys/sysinfo.h>
#include<unistd.h>

#define __USE_GNU
#include<sched.h>
#include<ctype.h>
#include<string.h>
#include<pthread.h>
#define THREAD_MAX_NUM 200
#define QUEUE_MAX_SIZE 1024*1024

#include<netinet/in.h>
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>

#define DEBUG

pthread_cond_t condition_listen_handle;
pthread_cond_t condition_handle_storage;
pthread_mutex_t mutex_lock_listen_handle;
pthread_mutex_t mutex_lock_handle_storage;

struct mqueue queue_listen_handle;
struct mqueue queue_handle_storage;

struct mdb database;

bpf_u_int32 net; //IP
bpf_u_int32 mask;

void print_ip(unsigned int ip_addr, unsigned int port){
    for(int i=0;i<4;i++){
        fprintf(stderr, "%d.", ip_addr & ((1 << 8)-1));
        ip_addr >>= 8;
    }
    if(port)
        fprintf(stderr, ":%d", port);
}

void print_data(struct mdata* data){
    #ifdef DEBUG
    print_ip(data->ip_src.s_addr, data->port_src);
    fprintf(stderr, " TO ");
    print_ip(data->ip_des.s_addr, data->port_des);
    fprintf(stderr, "\n");
    #endif
}

struct mdata* mhandler_ip(const u_char *bytes, const struct pcap_pkthdr *h){
    struct ip *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;

    struct mdata* data = malloc(sizeof(struct mdata));
    
    iph = (struct ip*)bytes;
    data->ip_src = iph->ip_src;
    data->ip_des = iph->ip_dst;
    data->proto = iph->ip_p;

    switch(data->proto){
        // case 1: // ICMP
        // case 2: // IGMP
        case 6: // TCP
            tcph = (struct tcphdr*)(bytes+sizeof(struct ip));
            data->port_des = tcph->dest;
            data->port_src = tcph->source;
            if(data->ip_src.s_addr != net && h->len-(tcph->th_off*4)-34 == 0){
                free(data);
                return NULL;
            }
            break;
        //case 17: // UDP
            //udph = (struct udphdr*)(bytes+sizeof(struct ip));
            //data->port_des = udph->dest;
            //data->port_src = udph->source;
            //free(data);
            //data = NULL;
            //break;
        default:
            free(data);
            data = NULL;
    }
    
    return data;
}

void mhandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    struct ether_header *eth;
    eth=(struct ether_header *)bytes; //Ethernet Header

    //Network layer protocol
    unsigned int typeno;
	typeno=ntohs(eth->ether_type);

    struct mdata* data = NULL;
	switch(typeno){
        case ETHERTYPE_IP:
            data = mhandler_ip(bytes + sizeof(struct ether_header), h);
            break;
        case ETHERTYPE_PUP:
            //NOT SUPPORTED
            break;
        case ETHERTYPE_ARP:
            //NOT SUPPORTED
            break;
        default:
            return ;
	}

    


    if(data != NULL){
        data->ts = h->ts;
        int result = mqueue_push(&queue_listen_handle, data); //Here can defined &queuexx as a global variable to speed up.
        if(result == QUEUE_FAIL){
            free(data);
            fprintf(stderr, "[ERROR]Failed to push, packet loss.\n");
        }
        pthread_mutex_lock(&mutex_lock_listen_handle);
        pthread_cond_signal(&condition_listen_handle);
        pthread_mutex_unlock(&mutex_lock_listen_handle);
    }
}

int bindCore(int cid){
    cpu_set_t mask;
    cpu_set_t get;
    CPU_ZERO(&mask);
    CPU_SET(1, &mask);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &mask) != 0){
        fprintf(stderr, "[ERROR]Couldn't bind cpu core.\n");
        return -1;
    }
    fprintf(stderr, "[SUCCESS]Successfully bind core.\n");
    return 0;
}

void* storageThread(void* param){
    fprintf(stderr, "[SUCCESS]Storage Thread started.\n");
    struct mqueue* queue = &queue_handle_storage;
    struct mdata* data;
    while(1){
        if(mqueue_size(queue) == 0){
            pthread_mutex_lock(&mutex_lock_handle_storage);
            pthread_cond_wait(&condition_handle_storage, &mutex_lock_handle_storage);
            pthread_mutex_unlock(&mutex_lock_handle_storage);
        }
        data = mqueue_front(queue);
        int result = local_save(data);
        if(result == LOCAL_FAIL){
            #ifdef DEBUG
            fprintf(stderr, "[ERROR]Failed to save packet to local storage.\n");
            #endif
        }
        free(data);
        mqueue_pop(queue);
    }
    fprintf(stderr, "[INFO]Storage Thread ended.\n");
    return NULL;
}

void* handleThread(void *param){ //Used to handle the data
    fprintf(stderr, "[SUCCESS]Handle Thread started.\n");
    struct mqueue* queue = &queue_listen_handle;
    struct mqueue* queue_h = &queue_handle_storage;
    struct mdata* data;
    struct mdata* tdata;
    struct mdata* old_data;
    struct mdb* db = &database;
    while(1){
        if(mqueue_size(queue) == 0){
            pthread_mutex_lock(&mutex_lock_listen_handle);
            pthread_cond_wait(&condition_listen_handle, &mutex_lock_listen_handle);
            pthread_mutex_unlock(&mutex_lock_listen_handle);
        }
        data = mqueue_front(queue);
        mqueue_pop(queue);
        // fprintf(stderr, "%d\n", queue->front_p);

        // print_data(data);
        
        //Tell the type and decide whether to save on disk or in memory.
        if(data->ip_src.s_addr == net){
            //ACK packet
            #ifdef DEBUG
            // fprintf(stderr, "[INFO]Trying to match.\n");
            #endif
            old_data = mdb_search(db, data, 1);
            if(!old_data) {
                #ifdef DEBUG
                fprintf(stderr, "[WARNING]Packet not found and loss.\n");
                #endif
            }else{
                #ifdef DEBUG
                fprintf(stderr, "[INFO]Packet matched.\n");
                #endif
                tdata = malloc(sizeof(struct mdata));
                memcpy(tdata, old_data, sizeof(struct mdata));

                tdata->ts.tv_sec = data->ts.tv_sec - tdata->ts.tv_sec;
                tdata->ts.tv_usec = data->ts.tv_usec - tdata->ts.tv_usec;
                
                mqueue_push(queue_h, tdata);
                pthread_mutex_lock(&mutex_lock_handle_storage);
                pthread_cond_signal(&condition_handle_storage);
                pthread_mutex_unlock(&mutex_lock_handle_storage);
                free(old_data);
            }
            free(data);
        }else{
            //Not a ack packet
            int result = mdb_try_insert(db, data);
            if(result == MDB_FAIL){
                #ifdef DEBUG
                fprintf(stderr, "[ERROR]Packet loss.\n");
                #endif
                free(data);
                data = NULL;
            }
        }
    }
    return NULL;
}

void* listenThread(void *param){
    #ifdef DEBUG
    fprintf(stderr, "[SUCCESS]Listen thread started.\n");
    #endif
    pcap_t *handler = (pcap_t*)param;
    if(pcap_loop(handler, -1, mhandler, "main") != 0)
    #ifdef DEBUG
        fprintf(stderr, "[ERROR]Failed to get packet.\n");
    #endif
}

void* daemonListenThread(void *param) {
    while(1){
        pthread_t thread_handler;
        pthread_create(&thread_handler, NULL, listenThread, param);
        pthread_join(thread_handler, NULL);
    }
    return NULL;
}

void* daemonHandleThread(void *param) {
    while(1){
        pthread_t thread_handler;
        pthread_create(&thread_handler, NULL, handleThread, NULL);
        pthread_join(thread_handler, NULL);
    }
    #ifdef DEBUG
    fprintf(stderr, "[ERROR]Daemon thread of handle ended.\n");
    #endif
    return NULL;
}

void startListen(pcap_t *handler, char *outfile){
    pthread_t thread_daemon_handle;
    pthread_t thread_daemon_storage;
    pthread_t thread_daemon_listen;

    pthread_cond_init(&condition_listen_handle, NULL);
    pthread_cond_init(&condition_handle_storage, NULL);
    pthread_mutex_init(&mutex_lock_listen_handle, NULL);
    pthread_mutex_init(&mutex_lock_handle_storage, NULL);

    mqueue_init(&queue_listen_handle, QUEUE_MAX_SIZE);
    mqueue_init(&queue_handle_storage, QUEUE_MAX_SIZE);
    mdb_init(&database);

    struct LocalParam *par = malloc(sizeof(struct LocalParam));
    par->dst = outfile;
    int result = local_set_param(par);
    free(par);
    if(result == LOCAL_FAIL) {
        fprintf(stderr, "Failed to open local storage.\n");
        return ;
    }

    thread_daemon_handle = pthread_create(&thread_daemon_handle, NULL, handleThread, NULL);
    thread_daemon_storage = pthread_create(&thread_daemon_storage, NULL, storageThread, NULL);
    
    listenThread((void*)handler);

    mqueue_destroy(&queue_listen_handle);
    mqueue_destroy(&queue_handle_storage);

    fprintf(stderr, "[INFO]Thread ended.\n");
}

int main(int argc, char **argv)
{
    collectorInit();
    char errbuf[PCAP_ERRBUF_SIZE];
    // printf("Device: %s\n", dev);
    if(pcap_lookupnet(argv[1], &net, &mask, errbuf) < 0){
        #ifdef DEBUG
        fprintf(stderr, "[ERROR]Failed to obtain NIC info.\n");
        #endif
        return 1;
    }
    // fprintf(stderr, "%d\n", net);
    int a, b, c, d;
    sscanf(argv[2], "%d.%d.%d.%d", &a, &b, &c, &d);
    net = (d << 24) | (c << 16) | (b << 8) | a;

    pcap_t *handler = createNewHandler(argv[1], 54, 0, 0, 0, 0);
    
    if(!handler) {
        #ifdef DEBUG
        fprintf(stderr, "[ERROR]Not a valid handler.\n");
        #endif
        return 0;
    }
    fprintf(stderr, "[SUCCESS]Get a valid handler.\n");

    int *data_list_point;
    int len = pcap_list_datalinks(handler, &data_list_point);

    if(len <= 0) {
        #ifdef DEBUG
        fprintf(stderr, "[ERROR]No valid header to use\n");
        #endif
        pcap_free_datalinks(data_list_point);
        closeHandler(handler);
        return 1;
    }

    int header_type = data_list_point[0];
    pcap_free_datalinks(data_list_point);

    if(pcap_set_datalink(handler, header_type) == PCAP_ERROR){
        #ifdef DEBUG
        fprintf(stderr, "[ERROR]Unable to set header type.\n");
        #endif
        closeHandler(handler);
        return 1;
    }
    #ifdef DEBUG
    fprintf(stderr, "[SUCCESS]Successfully set header type.\n");
    #endif

    struct bpf_program filter;
    if(pcap_compile(handler, &filter, "ip proto \\tcp", 1, mask) == PCAP_ERROR){
        fprintf(stderr, "[ERROR]Failed to compile BPF.\n");
        pcap_perror(handler, "");
        closeHandler(handler);
        return 1;
    }

    if(pcap_setfilter(handler, &filter) == PCAP_ERROR){
        fprintf(stderr, "[ERROR]Failed to set BPF.\n");
        pcap_perror(handler, "");
        closeHandler(handler);
        return 1;
    }

    startListen(handler, argv[3]);

    closeHandler(handler);
    handler = NULL;

    return 0;
}