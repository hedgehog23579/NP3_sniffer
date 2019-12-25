#include <pcap.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
typedef struct ip_address{
     u_char byte1;
     u_char byte2;
     u_char byte3;
     u_char byte4;
}ip_address;
  
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;

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

void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(int argc,char **argv){
    pcap_t *fp;
    char filename[20] ;
    strcpy(filename,argv[2]);
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_ERRBUF_SIZE];
    char packet_filter[] = "ip and tcp";
    struct bpf_program fcode;
    u_int netmask;

    if(argc < 2){
        printf("usage: %s filename", argv[0]);
        return -1;
    }

    if((fp = pcap_open_offline(filename,errbuf))==NULL){
        fprintf(stderr, "\nUnable to open the file:%s!", filename);
        return -1;
    }
    netmask = 0xffffff;

    if(pcap_compile(fp, &fcode, packet_filter, 1, netmask) <0){
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax");
        return -1;
    }
    if(pcap_setfilter(fp, &fcode)<0){
        fprintf(stderr, "\nError setting the filter");
        return -1;
    }
    pcap_loop(fp, 0, dispatcher_handler, NULL);
    return 0;
}
void dispatcher_handler(u_char *tmp1, const struct pcap_pkthdr *header, const u_char *pkt_data){
    ip_header *ih;
    tcp_header *th;
    u_int ip_len;
    u_short sport, dport;
    struct tm *timeinfo;
    char buffer[80];
    // timeval -> Vids time
    timeinfo = localtime(&header->ts.tv_sec);
    strftime(buffer,80,"%Y年%m月%d日%H時%M分%S秒",timeinfo); 

}
