#include <stdio.h>
#include <libnet.h>

libnet_ptag_t tcpTagCreate( libnet_t *l,u_int32_t srcPort, u_int32_t dstPort,
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
        LIBNET_TCP_H + payload_length, //packet length
        payload,
        payloadLength,
        l,
        tcp
    );

    if(tcp==-1)
    {
        fprintf(stderr, "Error building tcp header");
        exit(0);
    }

    return tcp;
}
