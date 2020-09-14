#ifndef _SENDER_H_
#define _SENDER_H_
#include <libnet.h>
void tcpTagCreate(libnet_t *l,u_int32_t srcPort, u_int32_t dstPort, u_int32_t seqNumber, u_int32_t ackNumber, char *payload, u_int32_t payloadLength, u_int8_t controlFlags);
void ipTagCreate(libnet_t *l,u_int32_t srcAddr, u_int32_t dstAddr,char *payload, u_int32_t payloadLength);
void sendPacket(libnet_t *l);
#endif