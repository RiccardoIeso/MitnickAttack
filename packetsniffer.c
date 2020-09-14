#include <stdio.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <stdlib.h>
#include "sender.h"
#include "headerdefinition.h"
void packetSnifferInitialize(libnet_t *l,u_long kevin, u_long xterminal)
{
    char *dev;
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* des;       
    bpf_u_int32 subMask;            
    bpf_u_int32 ipAddr;   
    struct bpf_program fp;         
    struct pcap_pkthdr header;
    const u_char *packet;	
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
        tcpTagCreate(l,(u_int32_t)514, (u_int32_t)514,(u_int32_t)123456,(u_int32_t)1,NULL,0,TH_SYN);
        ipTagCreate(l,(u_int32_t)kevin,(u_int32_t)xterminal,NULL,(u_int32_t)0);
        sendPacket(l);
        usleep(1000);
        packet = pcap_next(des, &header);
        printf("miao");
        fflush(stdout);

    }
     pcap_close(des);

}

void closePacketSniffer(pcap_t* des)
{
    pcap_close(des);
}

