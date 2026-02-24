#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pcap.h> 
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include "wirebass.h"

void callback( unsigned char *user, const struct pcap_pkthdr *hdr, const unsigned char *packet ){
    printf( "=== Pacote Captruado ===\n" );
    printf( "Capturado em: %s", ctime(( const time_t * )&hdr->ts.tv_sec ) );
    printf( "Tamanho do pacote: %d\n", hdr->len );
    printf( "Tamanho header Ethernet: 14\n");


    struct sniff_ethernet * etr_ptr = (struct sniff_ethernet *) packet;

    printf("ethertype: %04X\n", ntohs(etr_ptr->ether_type));

    printf("destination: %02x:%02x:%02x:%02x:%02x:%02x\n",
        etr_ptr->ether_dhost[0], etr_ptr->ether_dhost[1],
        etr_ptr->ether_dhost[2], etr_ptr->ether_dhost[3],
        etr_ptr->ether_dhost[4], etr_ptr->ether_dhost[5]);

    printf("source: %02x:%02x:%02x:%02x:%02x:%02x\n",
        etr_ptr->ether_host[0], etr_ptr->ether_host[1],
        etr_ptr->ether_host[2], etr_ptr->ether_host[3],
        etr_ptr->ether_host[4], etr_ptr->ether_host[5]);
}

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


    pcap_t *open_live;

    open_live = pcap_open_live(alldevices->name, BUFSIZ, 0, 1000, errbuf);

    if( open_live == NULL )
    {
        printf("Não foi possivel abrir dispositivo: %s", errbuf);
        exit(1);
    }

    const unsigned char *packet;
    struct pcap_pkthdr hdr;

  

    packet = pcap_next(open_live, &hdr);

    printf( "=== Pacote Captruado ===\n" );
    printf( "Capturado em: %s", ctime(( const time_t * )&hdr.ts.tv_sec ) );
    printf( "Tamanho do pacote: %d\n", hdr.len );
    printf( "Tamanho header Ethernet: 14\n");


    struct sniff_ethernet * etr_ptr = (struct sniff_ethernet *) packet;

    printf("ethertype: %04X\n", ntohs(etr_ptr->ether_type));

    printf("destination: %02x:%02x:%02x:%02x:%02x:%02x\n",
        etr_ptr->ether_dhost[0], etr_ptr->ether_dhost[1],
        etr_ptr->ether_dhost[2], etr_ptr->ether_dhost[3],
        etr_ptr->ether_dhost[4], etr_ptr->ether_dhost[5]);

    printf("source: %02x:%02x:%02x:%02x:%02x:%02x\n",
        etr_ptr->ether_host[0], etr_ptr->ether_host[1],
        etr_ptr->ether_host[2], etr_ptr->ether_host[3],
        etr_ptr->ether_host[4], etr_ptr->ether_host[5]);



    
    struct bpf_program compiled_program;
    
    if( pcap_compile(open_live, &compiled_program, "ether proto 0x0800", 0, netp) == -1){
        exit(1);
    }

    pcap_loop(open_live, -1, callback, NULL);


    return 0;

}