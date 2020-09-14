#ifndef WHATEVER_H_INCLUDED
#define WHATEVER_H_INCLUDED
#include <libnet.h>

libnet_ptag_t tcpTagCreate(libnet_t *l,u_int32_t srcPort, u_int32_t dstPort, u_int32_t seqNumber, u_int32_t ackNumber, char *payload, u_int32_t payloadLength, u_int8_t controlFlags);
libnet_ptag_t ipTagCreate(libnet_t *l,u_int32_t srcAddr, u_int32_t dstAddr,char *payload, u_int32_t payloadLength)
void sendPacket()
#endif