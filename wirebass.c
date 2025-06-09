#include <sys/types.h>
#include <stdio.h>
#include <pcap.h>

int main(){

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    int ret;

    bpf_u_int32 net;
    bpf_u_int32 mask;
    ret = pcap_findalldevs(&alldevs, errbuf);
    
    if (pcap_lookupnet(alldevs->name, &net, &mask, errbuf) == -1){
        fprintf(stderr,"Nao foi possivel conseguir a net mask para o dispositivo %s", alldevs->name);
        net = 0;
        mask = 0;
    }

    for(pcap_if_t *d = alldevs; d!=NULL; d=d->next){
        printf("%s - %s\n", d->name, d->description);
    }

    pcap_t *handle;

    handle = pcap_open_live(alldevs->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Nao foi possivel abrir o dispositivo %s\n", alldevs->name, errbuf);
    }
        // Header de internet
    printf("%d", pcap_datalink(handle));
   
    struct bpf_program fp;    
    char filter_exp[] = "port 80";

    if (pcap_compile(handle, &fp, filter_exp, 0, net)==-1){
        fprintf(stderr, "Nao foi possivel analisar o filtro %s: %s", filter_exp, pcap_geterr(handle));
    }; 

    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "nao foi possivel instalar o filtro %s: %s", filter_exp, pcap_geterr(handle));
    }
   
    const unsigned char *packet;
    struct pcap_pkthdr header;
    packet = pcap_next(handle, &header);           
    printf("len: %d\n", header.len);
    pcap_close(handle);
    return 0;
}






