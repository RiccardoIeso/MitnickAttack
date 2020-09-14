#ifndef _PACKETSNIFFER_H
#define _PACKETSNIFFER_H
#include <pcap/pcap.h>
void packetSnifferInitialize(libnet_t *l,u_long kevin, u_long xterminal);
void closePacketSniffer(pcap_t* des);
#endif