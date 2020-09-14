#include "sender.h"
void tcpTagCreate( libnet_t *l,u_int32_t srcPort, u_int32_t dstPort,
                                u_int32_t seqNumber, u_int32_t ackNumber,
                                    char *payload, u_int32_t payloadLength, 
                                        u_int8_t controlFlags)
{
    libnet_ptag_t tcp=libnet_build_tcp(
        srcPort,        //source TCP port
        dstPort,        //destination TCP port
        seqNumber,      //sequence number
        ackNumber,      //acknowledgement
        controlFlags,   //control flags
        libnet_get_prand(LIBNET_PRu16), //window size
        0,
        0,
        LIBNET_TCP_H + payloadLength, //packet length
        (u_int8_t *)payload,
        payloadLength,
        l,
        tcp
    );

    if(tcp==-1)
    {
        fprintf(stderr, "Error building tcp header");
        exit(0);
    }

}


void ipTagCreate( libnet_t *l, u_int32_t srcAddr, u_int32_t dstAddr, 
                                char *payload, u_int32_t payloadLength)
{
    libnet_ptag_t ip=libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + payloadLength, //packet length
        0,
        libnet_get_prand(LIBNET_PRu16),
        0,
        64,
        IPPROTO_TCP,
        0,
        srcAddr,
        dstAddr,
        NULL,
        0,
        l,
        ip
    );

    if(ip==-1)
    {
        fprintf(stderr, "Error building ip header");
        exit(0);
    }

}

void sendPacket(libnet_t *l)
{
    int write=libnet_write(l);
    if(write==-1)
    {
        fprintf(stderr, "Error in write packet");
        fprintf(stderr, "%s",libnet_geterror(l));
    }
}