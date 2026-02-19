#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> 
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

int main () {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevices;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    if(pcap_findalldevs(&alldevices, errbuf) == PCAP_ERROR) 
    {
        printf("Não foi possivel encontrar dispositivos: %s", errbuf);
        exit(1);
    }

    if(pcap_lookupnet(alldevices->name, &netp, &maskp, errbuf) == PCAP_ERROR)
    {
        printf("Não foi possivel encontrar net e mask: %s", errbuf);
        exit(1);
    }

    struct in_addr addr;
    char *net;
    addr.s_addr = netp;
    net = inet_ntoa(addr);

    printf("%s\n", net);

    char *mask;
    addr.s_addr = maskp;
    mask = inet_ntoa(addr);

    printf("%s\n", mask);


    

    return 0;

}