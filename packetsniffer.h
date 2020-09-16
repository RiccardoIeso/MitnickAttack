#ifndef _PACKETSNIFFER_H
#define _PACKETSNIFFER_H
#include <pcap/pcap.h>
uint32_t packetSnifferInitialize();
uint32_t getNextSeq(libnet_t *l,u_long kevin, u_long xterminal, u_int32_t sport, u_int32_t dport, pcap_t* des );
#endif