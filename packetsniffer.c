#include <stdio.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "sender.h"


uint32_t packetSnifferInitialize(libnet_t *l,u_long kevin, u_long xterminal)
{
    char *dev;
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* des;       
    bpf_u_int32 subMask;            
    bpf_u_int32 ipAddr;   
    struct bpf_program fp;         
    struct pcap_pkthdr *header;
    const u_char *packet;	
    const struct tcphdr* tcp;
    uint32_t seq[3];
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
    if(pcap_compile(des, &fp, "src host xterminal and (tcp[tcpflags] & (tcp-syn | tcp-ack) != 0)", 0, subMask)<0)
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
    for(int i=0; i<3;i++)
    {
        //send packet
        tcpTagCreate(l,(u_int32_t)514, (u_int32_t)514,(u_int32_t)123456,(u_int32_t)1,NULL,0,TH_SYN);
        ipTagCreate(l,(u_int32_t)kevin,(u_int32_t)xterminal,NULL,(u_int32_t)0);
        sendPacket(l);
        int status;

        status = pcap_next_ex(des, &header, &packet);
            

        if (status < 0) {
            fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(des));
            exit(1);
        }
	    struct ethernet *ethernet=(struct ethernet *)(packet);
        struct ip *ip=(struct ip *)(packet + 14);
        tcp=(const struct tcphdr *)(packet +14+sizeof(struct ip));
        seq[i] =ntohl(tcp->th_seq);
        printf("received seq %u\n", ntohl(tcp->th_seq));
        fflush(stdout);

    }
    
    //generate next seq
    printf("\nLAST: ", seq[2]);
    uint32_t next=seq[1]+(seq[1]-seq[0])+11111111;
    pcap_close(des);
    return next;
}
