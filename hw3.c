#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>
#include <net/if_arp.h>

#ifndef __linux
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#endif

#define MAC_ADDRSTRLEN 2*6+5+1
#define STR_BUF 16
#define netmask 0xffffff
#define MAX_SIZE 500

typedef struct eth_h {
	u_char	ether_dhost[6];
	u_char	ether_shost[6];
	u_short	ether_type;
}eth_h ;

typedef struct ip_address{
     u_char byte1;
     u_char byte2;
     u_char byte3;
     u_char byte4;
}ip_address;

typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

typedef struct tcp_header{
    u_short  source_port;       // (16 bits)                         
    u_short  destination_port;  // (16 bits)                        
    u_long seq_number;        // Sequence Number (32 bits)         
    u_long ack_number;        // Acknowledgment Number (32 bits)     
    u_short  info_ctrl;         // Data Offset (4 bits), Reserved (6 bits), Control bits (6 bits)
    u_short  window;            // (16 bits)
    u_short  checksum;          // (16 bits)
    u_short  urgent_pointer;    // (16 bits)
} tcp_header;

typedef struct ip_MEM{
    char src[25];
    char des[25];
    int num;
}ip_MEM;
ip_MEM IPNUM[MAX_SIZE];

static const char *mac_ntoa(u_int8_t *d);
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
static void dump_ethernet(u_int32_t len,const u_char *pkt_data);
u_short data_count=0;
u_short IP_count=0;
int main(int argc,char **argv){
    pcap_t *fp;
    char filename[20] ;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_ERRBUF_SIZE];
    char packet_filter[] = "ip";
    struct bpf_program fcode;

    if(argc < 2){
        printf("usage: %s filename", argv[0]);
        return -1;
    }
    char *device = NULL;
    device = pcap_lookupdev(errbuf);
    if(!device) {
        fprintf(stderr, "pcap_lookupdev(): %s\n", errbuf);
        exit(1);
    }
    printf("Sniffing: %s\n", device);
    strcpy(filename,argv[2]);
    if((fp = pcap_open_offline(filename,errbuf))==NULL){
        fprintf(stderr, "\nUnable to open the file:%s!", filename);
        return -1;
    }
    if(pcap_compile(fp, &fcode, packet_filter, 1, netmask) <0){
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax");
        return -1;
    }
    if (pcap_setfilter(fp, &fcode)<0)       //ignore packet that not ip
    {
        fprintf(stderr,"\nError setting the filter.\n");
        return -1;
    }
    memset(IPNUM,0,sizeof(IPNUM));
    pcap_freecode(&fcode);
    pcap_loop(fp, 0, dispatcher_handler, NULL);
    int i;
    printf("\n\n\n\n\n---------------This is all packet quantity---------------\n");
    for(i=0;i<IP_count;i++){
        printf("SRCIP:%s\tDESIP:%s has %d data.\n",IPNUM[i].src,IPNUM[i].des,IPNUM[i].num+1);
    }
    return 0;
}
void dispatcher_handler(u_char *tmp1, const struct pcap_pkthdr *header, const u_char *pkt_data){
    data_count++;
    printf("\n\n\n---------------This is %d data---------------",data_count);
    ip_header *ih;
    tcp_header *th;
    udp_header *uh;
    u_short sport;
    u_short dport;
    u_int ip_len;
    struct tm *timeinfo;
    char buffer[80];
    char srcip[MAX_SIZE]={0};
    char desip[MAX_SIZE]={0};
    timeinfo = localtime(&header->ts.tv_sec);      
    strftime(buffer,80,"%Y年%m月%d日%H時%M分%S秒",timeinfo); 
    printf("\nTime :%s",buffer);
    dump_ethernet(header->caplen, pkt_data);
    ih = (ip_header *)(pkt_data + 14);
    ip_len = (ih->ver_ihl & 0xf) * 4;
    snprintf(srcip,sizeof(srcip),"%d.%d.%d.%d",
    ih->saddr.byte1,
    ih->saddr.byte2,
    ih->saddr.byte3,
    ih->saddr.byte4);
    snprintf(desip,sizeof(desip),"%d.%d.%d.%d",
    ih->daddr.byte1,
    ih->daddr.byte2,
    ih->daddr.byte3,
    ih->daddr.byte4);
    printf("SRCip=%s  DESip=%s\n",srcip,desip);
    int i=0;
    int is_find=0;
    for(i=0;i<MAX_SIZE;i++){
        if(strcmp(IPNUM[i].src,srcip)==0 && strcmp(IPNUM[i].des,desip)==0){
            IPNUM[i].num++;
            is_find=1;
        }
    }
    if(!is_find){
        strcpy(IPNUM[IP_count].src,srcip);
        strcpy(IPNUM[IP_count].des,desip);
        IP_count++;
    }
    switch(ih->proto){
        case 17: //UDP
        uh = (udp_header *) ((u_char*)ih + ip_len);
        sport = ntohs(uh->sport);
        dport = ntohs(uh->dport);
        printf("This is UDP data!\n");
        printf("SRCport = %d\tDESport = %d\n",sport,dport);
        break;
        case 6:  //TCP
        th = (tcp_header *) ((u_char*)ih + ip_len);
        sport = ntohs(th->source_port);
        dport = ntohs(th->destination_port);
        printf("This is TCP data!\n");
        printf("SRCport = %d\tDESport = %d\n",sport,dport);
        printf("---------------The  data  end---------------\n");
    }
}
static void dump_ethernet(u_int32_t length, const u_char *pkt_data){
    char sMAC[MAC_ADDRSTRLEN]={0};
    char dMAC[MAC_ADDRSTRLEN]={0};
    struct eth_h *ethernet = (struct eth_h *)pkt_data;
    sprintf(sMAC, "%s", mac_ntoa(ethernet->ether_shost));
    sprintf(dMAC, "%s", mac_ntoa(ethernet->ether_dhost));
    printf("\n\nSource MAC Address:%17s", sMAC);
    printf("\nDestination MAC Address:%17s\n\n", dMAC);
}
static const char *mac_ntoa(u_int8_t *d) {
    static char mac[STR_BUF][MAC_ADDRSTRLEN];
    static int which = -1;
    which = (which + 1 == STR_BUF ? 0 : which + 1);
    memset(mac[which], 0, MAC_ADDRSTRLEN);
    snprintf(mac[which], sizeof(mac[which]), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);
    return mac[which];
}