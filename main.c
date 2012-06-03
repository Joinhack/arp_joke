#include "main.h"

pcap_t *driver;
u_char *buff;
void arp_send();
int main(int argc, char **argv) {
	pcap_if_t *all,*current;
	u_char packet[100];
	struct pcap_pkthdr *head;
	char *eth_dst = "00-02-3f-03-3f-26";
	char errbuff[PCAP_ERRBUF_SIZE];
	char *data;
	char in;
	int intin;
	int i = 0;
	if(getuid() != 0) {
		printf("please run as root\n");
		return -1;
	}
	if(pcap_findalldevs(&all,errbuff) == -1) {
		fprintf(stderr,"error in open interface\n\tthe reason is: %s",errbuff);
		exit(-1);
	}
	i = 1;
	for(current = all;current;current = current->next) {
		fprintf(stdout,"%d.%s(%s)\n",i,current->name,current->description);
		i++;
	}
	fprintf(stdout,"input the number of the interface:");
	scanf("%c",&in);
	intin = atoi(&in);
	for(current = all,i = 1;current;current = current->next,i++) {
		if(i == intin) {
			break;
		}
	}
	fprintf(stdout,"you choice driver is %s(%s)",current->name,current->description);
	char buff_t[strlen(current->name)];
	strcpy(buff_t,current->name);
	pcap_freealldevs(all);
	if((driver = pcap_open_live(buff_t,65535,PCAP_OPENFLAG_PROMISCUOUS,1000,errbuff)) == NULL) {
		fprintf(stdout,"open a driver error ,reason:%s",errbuff);
		return -1;
	}

	/* Send down the packet */
	if (pcap_sendpacket(driver, packet, 100 ) != 0) {
		fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(driver));
		return 1;
	}
	buff = (u_char*)malloc(sizeof(struct ether_header) + sizeof(struct ARP_HEADER));
	struct ether_header *eh = (struct ether_header*)buff;
	char tmp[ETHER_ADDR_LEN];
	//dst-host-eth-addr
	memset(tmp,0,ETHER_ADDR_LEN);
	eth_addr_parse("ff-ff-ff-ff-ff-ff",tmp);
	memcpy(&(eh->ether_dhost),tmp,ETHER_ADDR_LEN);
	//src-host-eth-addr
	memset(tmp,0,ETHER_ADDR_LEN);
	eth_addr_parse(eth_dst,tmp);
	memcpy(&(eh->ether_shost),tmp,ETHER_ADDR_LEN);
	eh->ether_type=htons(0x0806);
	struct ARP_HEADER *arp;
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

