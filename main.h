#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "util.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define SIOCGARP 0x00008951
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif


#ifndef PCAP_OPENFLAG_PROMISCUOUS
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif

//ARP头部 
struct ARP_HEADER {  
	unsigned short arp_hdr;
	unsigned short arp_pro;
	unsigned char   arp_hln;
	unsigned char   arp_pln;
	unsigned short arp_opt;
	unsigned char   arp_sha[6];
	unsigned char   arp_spa[4];
	unsigned char   arp_tha[6];
	unsigned long   arp_tpa[4];
};

struct ether_header {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

