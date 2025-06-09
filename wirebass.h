#include <netinet/in.h>
// Os endereços ehternet possuem 6 bytes
#define ETHERNET_ADDR_LEN 6

// Ethernet header
struct sniff_ethernet
{
    unsigned char ether_dhost[ETHERNET_ADDR_LEN]; // destination host addr
    unsigned char ether_host[ETHERNET_ADDR_LEN];  // source host addr
    unsigned short ether_type;
};

// IP header
struct sniff_ip
{
    unsigned char ip_vhl;  // version << 4 | header length >> 2
    unsigned char ip_tos;  // type of service
    unsigned short ip_len; // length
    unsigned short ip_id;  // identificação
    unsigned short ip_off; // fragment offset field
#define IP_RF 0x8000       // reserved fragment flag
#define IP_DF 0x4000       // dont fragment flag
#define IP_MF 0x2000       // more fragment flag
#define IP_OFFMASK 0x1fff  // mascara para os bits dos fragmentos
    unsigned char ip_ttl;  // time to live
    unsigned char ip_p;    // protocol
    unsigned short ip_sum; // checksum
    struct in_addr ip_src, ip_dst;
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)   // header lenght  
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)     // version

// TCP header
typedef unsigned int tcp_seq;

struct sniff_tcp
{
    unsigned short th_sport; // source port
    unsigned short th_dport; // destine port
    tcp_seq th_seq;          // sequence number
    tcp_seq th_ack;          // acknowledgment number
    unsigned char th_offsetx2;
};