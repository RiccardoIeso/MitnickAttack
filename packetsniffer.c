#include <stdio.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <stdlib.h>
#include "sender.h"


	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};

	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

    	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
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
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

void packetSnifferInitialize(libnet_t *l,u_long kevin, u_long xterminal)
{
    char *dev;
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* des;       
    bpf_u_int32 subMask;            
    bpf_u_int32 ipAddr;   
    struct bpf_program fp;         
    struct pcap_pkthdr *header=malloc(sizeof(struct pcap_pkthdr));
    const u_char *packet;	
    const struct sniff_tcp* sniff_tcp;
    dev = pcap_lookupdev(errbuff);


	//const struct sniff_ethernet *ethernet; /* The ethernet header */

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
        tcpTagCreate(l,(u_int32_t)514, (u_int32_t)514,(u_int32_t)123456,(u_int32_t)1,NULL,0,TH_SYN);
        ipTagCreate(l,(u_int32_t)kevin,(u_int32_t)xterminal,NULL,(u_int32_t)0);
        sendPacket(l);
        usleep(1000);
        if((packet = pcap_next(des, &header))<0)
        {
            printf("\n mm ");
            exit(0);
        }
	    struct sniff_ethernet *ethernet=(struct sniff_ethernet *)(packet);
        struct sniff_ip *ip=(struct sniff_ip *)(packet + 14);
        sniff_tcp=(const struct sniff_tcp *)(packet +14+sizeof(struct sniff_ip));
        uint32_t seq = ntohl(sniff_tcp->th_seq);
        printf("received seq %u\n", seq);
        fflush(stdout);
        printf("miao");
        fflush(stdout);

    }
     pcap_close(des);

}

void closePacketSniffer(pcap_t* des)
{
    pcap_close(des);
}

