#include "collector.h"

char errbuf[PCAP_ERRBUF_SIZE];

void collectorInit() {

}

pcap_t *createNewHandler(char *ifname, int snaplen, int promisc, int mon_mode, int timeout, int buffsize){
    pcap_t *handler;
    int result;
    handler = pcap_create(ifname, errbuf);
    if(handler == NULL) {
        fprintf(stderr, "[ERROR]Failed to create handler on %s\n", ifname);
        fprintf(stderr, errbuf);
        fprintf(stderr, "\n");
        return NULL;
    }
    if(handler){
        if(snaplen > 0){
            if(pcap_set_snaplen(handler, snaplen) != 0)
                fprintf(stderr, "[WARNING]Failed to change snaplen.\n");
        }
        if(pcap_set_promisc(handler, promisc) != 0) {
            fprintf(stderr, "[WARNING]Failed to set promisc before activate.\n");
        }
        if(mon_mode && pcap_can_set_rfmon(handler) != 0) {
            if(pcap_set_rfmon(handler, 1) != 0)
                fprintf(stderr, "[WARNING]Failed to set monitor mode.");
        }else if(mon_mode)
            fprintf(stderr, "[WARNING]Your device can't use monitor mode.\n");
        if(timeout > 0){
            if(pcap_set_timeout(handler, timeout) != 0) {
                fprintf(stderr, "[WARNING]Failed to set timeout.\n");
            }
        }
        if(buffsize > 0){
            if(pcap_set_buffer_size(handler, buffsize) != 0){
                fprintf(stderr, "Failed to set buffer size.\n");
            }
        }
    }
    
    result = pcap_activate(handler);
    if(result != 0)
        switch(result){
            case PCAP_WARNING_PROMISC_NOTSUP:
                pcap_perror(handler, errbuf);
                fprintf(stderr, "[WARNING][CONTENT]%s\n", errbuf);
            case PCAP_WARNING:
            case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
                fprintf(stderr, "[WARNING]WARNING_OCCURED, code: %d\n", result);
                break;
            case PCAP_ERROR_PERM_DENIED:
            case PCAP_ERROR_NO_SUCH_DEVICE:
                pcap_perror(handler, errbuf);
                fprintf(stderr, "[ERROR][CONTENT]%s\n", errbuf);
            case PCAP_ERROR_PROMISC_PERM_DENIED:
            case PCAP_ERROR_RFMON_NOTSUP:
            case PCAP_ERROR_IFACE_NOT_UP:
            case PCAP_ERROR:
                fprintf(stderr, "[ERROR]Failed to activate handler.\n");
                pcap_close(handler);
                handler = NULL;
                break;
        }
    return handler;
}

void closeHandler(pcap_t* handler) {
    pcap_close(handler);
}