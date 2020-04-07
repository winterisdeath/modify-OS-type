#ifndef PACKETS_HEADERS_H
#define PACKETS_HEADERS_H

#ifndef H1_H
#define H1_H
#define 	PCAP_OPENFLAG_PROMISCUOUS    1
    /* Определяет, должен ли адаптер переходить в случайный режим. */

#define 	PCAP_OPENFLAG_DATATX_UDP    2
    /* Определяет, должен ли перенос данных (в случае удаленного захвата) выполняться по протоколу UDP. */

#define 	PCAP_OPENFLAG_NOCAPTURE_RPCAP    4
    /* Определяет, будет ли удаленный зонд захватывать собственный сгенерированный трафик. */

#define 	PCAP_OPENFLAG_NOCAPTURE_LOCAL    8
    /* Определяет, будет ли локальный адаптер захватывать собственный сгенерированный трафик. */

#define 	PCAP_OPENFLAG_MAX_RESPONSIVENESS    16
    /*Этот флаг настраивает адаптер для максимальной отзывчивости. */



#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

typedef unsigned char  uchar;
typedef unsigned short ushort;
typedef unsigned int   uint;

/* Ethernet header */
struct sniff_ethernet {
    uchar  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    uchar  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    ushort ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    uchar  ip_vhl;                 /* version << 4 | header length >> 2 */
    uchar  ip_tos;                 /* type of service */
    ushort ip_len;                 /* total length */
    ushort ip_id;                  /* identification */
    ushort ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    uchar  ip_ttl;                 /* time to live */
    uchar  ip_p;                   /* protocol */
    ushort ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef uint tcp_seq;

struct sniff_tcp {
    ushort th_sport;               /* source port */
    ushort th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    uchar  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    uchar  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    ushort th_win;                 /* window */
    ushort th_sum;                 /* checksum */
    ushort th_urp;                 /* urgent pointer */
};
#endif // H1_H


#endif // PACKETS_HEADERS_H
