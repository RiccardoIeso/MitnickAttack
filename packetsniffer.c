#include <stdio.h>
#include <pcap/pcap.h>
#include<stdlib.h>
pcap_t* packetSnifferInitialize()
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
    des=pcap_open_live(dev,BUFSIZ,0,1000,errbuff);

    if(des==NULL)
    {
        fprintf(stderr,"Error open live %s", errbuff);
    }

    //Set filter
    pcap_compile(des, &fp, "src host 172.16.17.4 and not arp", 0, subMask);
    if(des==NULL)
    {
        fprintf(stderr, "%s", pcap_geterr(des));
        pcap_close(des);
        exit(0);
    }

    pcap_setfilter(des, &fp);
    if(des==NULL)
    {
        fprintf(stderr, "%s", pcap_geterr(des));
        pcap_close(des);
        exit(0);
    }

    return des;

}

void closePacketSniffer(pcap_t* des)
{
    pcap_close(des);
}

