#ifndef _PACKETSNIFFER_H
#define _PACKETSNIFFER_H
#include <pcap/pcap.h>
/* IP header */
struct ipHeader {
    u_char ip_vhl;        /* version << 4 | header length >> 2 */
    u_char ip_tos;        /* type of service */
    u_short ip_len;        /* total length */
    u_short ip_id;        /* identification */
    u_short ip_off;        /* fragment offset field */
    u_char ip_ttl;        /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;        /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};


#define IP_HEADER_LENGTH(ip)    (((ip)->ip_vhl) & 0x0f)

struct tcpHeader {
    u_short th_sport;    /* source port */
    u_short th_dport;    /* destination port */
    u_int th_seq;        /* sequence number */
    u_int th_ack;        /* acknowledgement number */
    u_char th_offx2;    /* data offset, rsvd */
    #define TH_OFF(th)    (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;        /* window */
    u_short th_sum;        /* checksum */
    u_short th_urp;        /* urgent pointer */
};
void packetSnifferInitialize(libnet_t *l,u_long kevin, u_long xterminal);
void closePacketSniffer(pcap_t* des);
#endif