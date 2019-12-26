#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>

#ifndef __linux
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#else /* if BSD */
#define __FAVOR_BSD
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <linux/if_link.h>
#include <netinet/ether.h>
#endif /* if linux */

#include <net/if_arp.h>

#define MAC_ADDRSTRLEN 2*6+5+1

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;

/*typedef struct	ether_header {
	u_char	ether_dhost[6];
	u_char	ether_shost[6];
	u_short	ether_type;
}ether_header ;*/

typedef struct ip_address{
     u_char byte1;
     u_char byte2;
     u_char byte3;
     u_char byte4;
}ip_address;
  
 /* IPv4 header */
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
    WORD  source_port;       // (16 bits)                         Winsock 内置函数 ntohs（），主要作用将大端转换为小端！
    WORD  destination_port;  // (16 bits)                         Winsock 内置函数 ntohs（），主要作用将大端转换为小端！
    DWORD seq_number;        // Sequence Number (32 bits)         大小端原因，高低位4个8bit的存放顺序是反的，intel使用小端模式
    DWORD ack_number;        // Acknowledgment Number (32 bits)     大小端原因，高低位4个8bit的存放顺序是反的，intel使用小端模式
    WORD  info_ctrl;         // Data Offset (4 bits), Reserved (6 bits), Control bits (6 bits)                intel使用小端模式
    WORD  window;            // (16 bits)
    WORD  checksum;          // (16 bits)
    WORD  urgent_pointer;    // (16 bits)
} tcp_header;
static const char *mac_ntoa(u_int8_t *d);
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
//static void dump_ethernet(u_int32_t len,const u_char *pkt_data);
int main(int argc,char **argv){
    pcap_t *fp;
    char filename[20] ;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_ERRBUF_SIZE];
    char packet_filter[] = "ip and tcp";
    struct bpf_program fcode;
    u_int netmask;

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
    netmask = 0xffffff;
    if(pcap_compile(fp, &fcode, packet_filter, 1, netmask) <0){
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax");
        return -1;
    }
        //printf("passby!\n");
    if(pcap_setfilter(fp, &fcode)<0){
        fprintf(stderr, "\nError setting the filter");
        return -1;
    }
    pcap_freecode(&fcode);
        //printf("passby!\n");
    pcap_loop(fp, 0, dispatcher_handler, NULL);
    return 0;
}
void dispatcher_handler(u_char *tmp1, const struct pcap_pkthdr *header, const u_char *pkt_data){
    ip_header *ih;
    tcp_header *th;
    //u_int ip_len;
    u_short sport, dport;
    u_int ip_len;
    struct tm *timeinfo;
    char buffer[80];
    // timeval -> Vids time
    timeinfo = localtime(&header->ts.tv_sec);
    strftime(buffer,80,"%Y年%m月%d日%H時%M分%S秒",timeinfo); 
    printf("Time :%s",buffer);
    printf(" %.6ld len:%d\n",header->ts.tv_usec, header->len);
    ih = (ip_header *)(pkt_data + 14);   //ethernet len = 14
    ip_len = (ih->ver_ihl & 0xf) * 4;
    th = (tcp_header *)((u_char*)ih + ip_len);
    sport = ntohs(th->source_port);
    dport = ntohs(th->destination_port);
    printf("source = %d.%d.%d.%d.port = %d ->destination = %d.%d.%d.%d. port = %d\n",
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4,
        sport,
        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4,
        dport);
        //dump_ethernet(header->caplen, pkt_data);
}
/*static void dump_ethernet(u_int32_t length, const u_char *pkt_data){
    char sMAC[MAC_ADDRSTRLEN]={0};
    char dMAC[MAC_ADDRSTRLEN]={0};
    u_int16_t type;

    struct ethernet_header *ethernet = (struct ethernet_header *)pkt_data;
    snprintf(sMAC, sizeof(sMAC), "%s", mac_ntoa(ethernet->ether_shost));
    snprintf(dMAC, sizeof(dMAC), "%s", mac_ntoa(ethernet->ether_dhost));
    type = ntohs(ethernet->ether_type);

    if(type <= 1500)
        printf("IEEE 802.3 Ethernet Frame:\n");
    else
        printf("Ethernet Frame:\n");
    printf("+-------------------------+-------------------------+-------------------------+\n");
    printf("| Source MAC Address:                                   %17s|\n", sMAC);
    printf("+-------------------------+-------------------------+-------------------------+\n");
    printf("| Destination MAC Address:                                        %17s|\n", dMAC);
    printf("+-------------------------+-------------------------+-------------------------+\n");
}*/