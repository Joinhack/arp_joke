#include "main.h"

pcap_t *driver;
u_char *buff;
void arp_send();
int main(int argc, char **argv) {
	u_char packet[100];
	char *eth_dst = "00-02-3f-03-3f-26";
	char errbuff[PCAP_ERRBUF_SIZE];
	char *data;
	char *devn, p;
	int i = 0;
	char tmp[ETHER_ADDR_LEN];
	struct ARP_HEADER *arp;
	if(getuid() != 0) {
		fprintf(stderr, "please run as root\n");
		return -1;
	}

	while((p = getopt(argc, argv, "i:")) != -1) {
		switch(p) {
		case 'i':
			devn = optarg;
			break;
		default:
			return -1;
		}
	}

	if((driver = pcap_open_live(devn,65535,PCAP_OPENFLAG_PROMISCUOUS,1000,errbuff)) == NULL) {
		fprintf(stderr,"open a driver error ,reason:%s\n",errbuff);
		return -1;
	}

	buff = (u_char*)malloc(sizeof(struct ether_header) + sizeof(struct ARP_HEADER));
	struct ether_header *eh = (struct ether_header*)buff;
	//dst-host-eth-addr
	memset(tmp,0,ETHER_ADDR_LEN);
	eth_addr_parse("ff-ff-ff-ff-ff-ff",tmp);
	memcpy(&(eh->ether_dhost),tmp,ETHER_ADDR_LEN);
	//src-host-eth-addr
	memset(tmp,0,ETHER_ADDR_LEN);
	eth_addr_parse(eth_dst,tmp);
	memcpy(&(eh->ether_shost),tmp,ETHER_ADDR_LEN);
	eh->ether_type=htons(0x0806);
	arp = (struct ARP_HEADER*)(buff + sizeof(struct ether_header));
	arp->arp_hdr = htons(1);
	arp->arp_pro = htons(0x0800);
	arp->arp_hln = 0x0006;
	arp->arp_pln = 0x0004;
	arp->arp_opt = htons(0x0002);

	memset(tmp,0,ETHER_ADDR_LEN);
	eth_addr_parse(eth_dst,tmp);
	memcpy(&(arp->arp_sha),tmp,ETHER_ADDR_LEN);

	inet_aton("10.100.0.61",(struct in_addr*)&(arp->arp_spa));

	memset(tmp,0,ETHER_ADDR_LEN);
	eth_addr_parse("ff-ff-ff-ff-ff-ff",tmp);
	memcpy(&(arp->arp_tha),tmp,ETHER_ADDR_LEN);

	inet_aton("0.0.0.0",(struct in_addr*)&(arp->arp_tpa));
	arp_send();
	return 0;
}

void arp_send() {
	while(1) {
		if(pcap_sendpacket(driver, buff, sizeof(struct ether_header) + sizeof(struct ARP_HEADER)) != 0) {
			fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(driver));
			return;
		}
		sleep(1);
	}
}

