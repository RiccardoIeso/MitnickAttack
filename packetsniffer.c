#include <stdio.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "sender.h"

#define FILTER "src host xterminal and (tcp[tcpflags] & (tcp-syn | tcp-ack) != 0)"


pcap_t* packetSnifferInitialize()
{
    char *dev;
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* des;       
    bpf_u_int32 subMask;            
    bpf_u_int32 ipAddr;   
    struct bpf_program fp;   


    //Get device for sniff      
    dev = pcap_lookupdev(errbuff);

    //Check on device
    if(dev==NULL)
    {
        fprintf(stderr,"Error with default device %s",errbuff);
        exit(0);
    }

    //Retrieve network info
    if(pcap_lookupnet(dev,&ipAddr, &subMask, errbuff)<0)
    {
        fprintf(stderr,"Error with net info %s",errbuff);
        exit(0);
    }
    
    //Open device for capturing
    if((des=pcap_open_live(dev,BUFSIZ,0,1000,errbuff))<0)
    {
        fprintf(stderr,"Error open live %s", errbuff);
    }

    //Compile filter expression
    if(pcap_compile(des, &fp, FILTER, 0, subMask)<0)
    {
        fprintf(stderr, "%s", pcap_geterr(des));
        pcap_close(des);
        exit(0);
    }

    //Set filter
    if(pcap_setfilter(des, &fp)<0)
    {
        fprintf(stderr, "%s", pcap_geterr(des));
        pcap_close(des);
        exit(0);
    }

    return des;

}

double timeToAnswer(libnet_t *l,u_long kevin, u_long xterminal, u_int32_t sport, u_int32_t dport, pcap_t* des)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
   
    int status;

    tcpTagCreate(l,(u_int32_t)514, (u_int32_t)514,(u_int32_t)123456,(u_int32_t)1,NULL,0,TH_SYN);
    ipTagCreate(l,(u_int32_t)kevin,(u_int32_t)xterminal,NULL,(u_int32_t)0);
    time_t start = time(NULL);
    sendPacket(l);

    //Read packet
    status = pcap_next_ex(des, &header, &packet);
        
    //Check the result of the reading
    return (double)(time(NULL) - start);
}


uint32_t getNextSeq(libnet_t *l,u_long kevin, u_long xterminal, u_int32_t sport, u_int32_t dport, pcap_t* des )
{
    
    struct pcap_pkthdr *header;
    const u_char *packet;
   
    const struct tcphdr* tcp;
    int status;
    uint32_t seq[2];

    for(int i=0; i<2;i++)
    {
        //Send SYN packet
        tcpTagCreate(l,(u_int32_t)514, (u_int32_t)514,(u_int32_t)123456,(u_int32_t)1,NULL,0,TH_SYN);
        ipTagCreate(l,(u_int32_t)kevin,(u_int32_t)xterminal,NULL,(u_int32_t)0);
        sendPacket(l);

        //Read packet
        status = pcap_next_ex(des, &header, &packet);
            
        //Check the result of the reading
        if (status < 0) {
            fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(des));
            exit(1);
        }

	    //struct ethernet *ethernet=(struct ethernet *)(packet);
        //struct ip *ip=(struct ip *)(packet + 14);

        //Retrieve tcp header
        tcp=(const struct tcphdr *)(packet +14+sizeof(struct ip));
        //Save seq retrieved
        seq[i] =ntohl(tcp->th_seq);

    }
    
    //Generate next seq
    uint32_t next=seq[1]+(seq[1]-seq[0])+11111111;
    
    pcap_close(des);
    return next;
}
