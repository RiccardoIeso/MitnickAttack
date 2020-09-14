#include <stdio.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <stdlib.h>
#include "sender.h"
/* IP header */
struct ipHeader {
    u_char ip_vhl;        /* version << 4 | header length >> 2 */
    u_char ip_tos;        /* type of service */
    u_short ip_len;        /* total length */
    u_short ip_id;        /* identification */
    u_short ip_off;        /* fragment offset field */
    u_char ip_ttl;        /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;        /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};


#define IP_HEADER_LENGTH(ip)    (((ip)->ip_vhl) & 0x0f)

struct tcpHeader {
    u_short th_sport;    /* source port */
    u_short th_dport;    /* destination port */
    u_int th_seq;        /* sequence number */
    u_int th_ack;        /* acknowledgement number */
    u_char th_offx2;    /* data offset, rsvd */
    #define TH_OFF(th)    (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;        /* window */
    u_short th_sum;        /* checksum */
    u_short th_urp;        /* urgent pointer */
};
void packetSnifferInitialize(libnet_t *l,u_long kevin, u_long xterminal)
{
    char *dev;
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* des;       
    bpf_u_int32 subMask;            
    bpf_u_int32 ipAddr;   
    struct bpf_program fp;         
    dev = pcap_lookupdev(errbuff);

    //Check on device
    if(dev==NULL)
    {
        fprintf(stderr,"Error with default device %s",errbuff);
        exit(0);
    }

    //retrieve net info
    if(pcap_lookupnet(dev,&ipAddr, &subMask, errbuff)<0)
    {
        fprintf(stderr,"Error with net info %s",errbuff);
        exit(0);
    }
    //Open
    if((des=pcap_open_live(dev,BUFSIZ,0,1000,errbuff))<0)
    {
        fprintf(stderr,"Error open live %s", errbuff);
    }

    //Set filter
    if(pcap_compile(des, &fp, "src host 172.16.17.4 and not arp", 0, subMask)<0)
    {
        fprintf(stderr, "%s", pcap_geterr(des));
        pcap_close(des);
        exit(0);
    }

    if(pcap_setfilter(des, &fp)<0)
    {
        fprintf(stderr, "%s", pcap_geterr(des));
        pcap_close(des);
        exit(0);
    }
    for(int i=0; i<2;i++)
    {
        //send packet
        tcpTagCreate(l,libnet_get_prand(LIBNET_PRu16),(u_int16_t)513,(u_int32_t)123456,(u_int32_t)1,NULL,0,TH_SYN);
        ipTagCreate(l,(u_int32_t)kevin,(u_int32_t)xterminal,NULL,(u_int32_t)0);
        sendPacket(l);
        usleep(10000);
        printf("miao");
        fflush(stdout);

    }
     pcap_close(des);

}

void closePacketSniffer(pcap_t* des)
{
    pcap_close(des);
}

