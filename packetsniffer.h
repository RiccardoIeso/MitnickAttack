#ifndef _PACKETSNIFFER_H
#define _PACKETSNIFFER_H
#include <pcap/pcap.h>
pcap_t* packetSnifferInitialize();
void closePacketSniffer(pcap_t* des);
#endif