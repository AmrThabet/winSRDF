/*
 *
 *  Copyright (C) 2012-2013  Anwar Mohamed <anwarelmakrahy[at]gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to Anwar Mohamed
 *  anwarelmakrahy[at]gmail.com
 *
 */

#ifndef HPACKETS_H
#define HPACKETS_H

#include <windows.h>

typedef __int64 int64_t;
typedef unsigned __int32 u_int32_t;
typedef unsigned __int16 u_int16_t;
typedef unsigned __int8 u_int8_t;



/* Ethernet */

#define	ETHER_ADDR_LEN		6
#define	ETHER_TYPE_LEN		2
#define	ETHER_CRC_LEN		4
#define	ETHER_HDR_LEN		(ETHER_ADDR_LEN*2+ETHER_TYPE_LEN)
#define	ETHER_MIN_LEN		64
#define	ETHER_MAX_LEN		1518
#define	ETHER_IS_VALID_LEN(foo)	\
	((foo) >= ETHER_MIN_LEN && (foo) <= ETHER_MAX_LEN)

#define	ETHERTYPE_PUP		0x0200	/* PUP protocol */
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define	ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#define	ETHERTYPE_REVARP	0x8035	/* reverse Addr. resolution protocol */
#define	ETHERTYPE_VLAN		0x8100	/* IEEE 802.1Q VLAN tagging */
#define	ETHERTYPE_IPV6		0x86dd	/* IPv6 */
#define	ETHERTYPE_LOOPBACK	0x9000	/* used to test interfaces */
#define	ETHERTYPE_TRAIL		0x1000		/* Trailer packet */
#define	ETHERTYPE_NTRAILER	16

#define	ETHERMTU	(ETHER_MAX_LEN-ETHER_HDR_LEN-ETHER_CRC_LEN)
#define	ETHERMIN	(ETHER_MIN_LEN-ETHER_HDR_LEN-ETHER_CRC_LEN)


#define TCP_PACKET	6
#define UDP_PACKET	17
#define ICMP_PACKET	1
#define IGMP_PACKET	2

#define ARPHRD_ETHER 	1	/* ethernet hardware format */
#define ARPHRD_IEEE802	6	/* token-ring hardware format */
#define ARPHRD_FRELAY 	15	/* frame relay hardware format */

#define	ARPOP_REQUEST		1	/* request to resolve address */
#define	ARPOP_REPLY			2	/* response to previous request */
#define	ARPOP_REVREQUEST	3	/* request protocol address given hardware */
#define	ARPOP_REVREPLY		4	/* response giving protocol address */
#define ARPOP_INVREQUEST	8 	/* request to identify peer */
#define ARPOP_INVREPLY		9	/* response identifying peer */

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO			8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES		18


/* Codes for UNREACH. */
#define ICMP_NET_UNREACH	0	/* Network Unreachable		*/
#define ICMP_HOST_UNREACH	1	/* Host Unreachable		*/
#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH	3	/* Port Unreachable		*/
#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED		5	/* Source Route failed		*/
#define ICMP_NET_UNKNOWN	6
#define ICMP_HOST_UNKNOWN	7
#define ICMP_HOST_ISOLATED	8
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PKT_FILTERED	13	/* Packet filtered */
#define ICMP_PREC_VIOLATION	14	/* Precedence violation */
#define ICMP_PREC_CUTOFF	15	/* Precedence cut off */
#define NR_ICMP_UNREACH		15	/* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET		0	/* Redirect Net			*/
#define ICMP_REDIR_HOST		1	/* Redirect Host		*/
#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL		0	/* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/

#define IGMP_MINLEN		     8

#define IGMP_MEMBERSHIP_QUERY   	0x11	/* membership query         */
#define IGMP_V1_MEMBERSHIP_REPORT	0x12	/* Ver. 1 membership report */
#define IGMP_V2_MEMBERSHIP_REPORT	0x16	/* Ver. 2 membership report */
#define IGMP_V2_LEAVE_GROUP			0x17	/* Leave-group message	    */
#define IGMP_V3_MEMBERSHIP_REPORT	0x22

#define IGMP_DVMRP					0x13	/* DVMRP routing message    */
#define IGMP_PIM					0x14	/* PIM routing message	    */

#define IGMP_MTRACE_RESP			0x1e	/* traceroute resp.(to sender)*/
#define IGMP_MTRACE					0x1f	/* mcast traceroute messages  */

#define IGMP_MAX_HOST_REPORT_DELAY  10		/* max delay for response to     */
											/*  query (in seconds) according */
											/*  to RFC1112                   */

#define IGMP_TIMER_SCALE     10				/* denotes that the igmp code field */
											/* specifies time in 10th of seconds*/
#define IGMP_HOST_MEMBERSHIP_QUERY	IGMP_MEMBERSHIP_QUERY
#define IGMP_HOST_MEMBERSHIP_REPORT	IGMP_V1_MEMBERSHIP_REPORT
#define IGMP_HOST_NEW_MEMBERSHIP_REPORT	IGMP_V2_MEMBERSHIP_REPORT
#define IGMP_HOST_LEAVE_MESSAGE		IGMP_V2_LEAVE_GROUP


/*PCAP FILES*/

typedef UINT UINT;
typedef USHORT USHORT;
typedef int INT;

struct PCAP_GENERAL_HEADER 
{
    UINT magic_number;   /* magic number */
    USHORT version_major;  /* major version number */
    USHORT version_minor;  /* minor version number */
    INT  thiszone;       /* GMT to local correction */
    UINT sigfigs;        /* accuracy of timestamps */
    UINT snaplen;        /* max length of captured packets, in octets */
    UINT network;        /* data link type */
};

struct PCAP_PACKET_HEADER 
{
    UINT ts_sec;         /* timestamp seconds */
    UINT ts_usec;        /* timestamp microseconds */
    UINT incl_len;       /* number of octets of packet saved in file */
    UINT orig_len;       /* actual length of packet */
};


#define SLL_ADDRLEN		8
struct SLL_HEADER 
{
	u_int16_t sll_pkttype;          /* packet type */
	u_int16_t sll_hatype;           /* link-layer address type */
	u_int16_t sll_halen;            /* link-layer address length */
	u_int8_t sll_addr[SLL_ADDRLEN]; /* link-layer address */
	u_int16_t sll_protocol;         /* protocol */
};

#pragma pack(push, r1, 1)

struct PSEUDO_HEADER
{
    unsigned long saddr;
    unsigned long daddr;
    UCHAR zero;
    UCHAR protocol;
    USHORT length;
};
#pragma pack(pop, r1)

struct PETHER_HEADER
{
	u_char	DestinationHost[ETHER_ADDR_LEN];
	u_char	SourceHost[ETHER_ADDR_LEN];
	u_short ProtocolType;
};

struct PIP_HEADER
{
	UCHAR  HeaderLength:4;
	UCHAR  Version   :4;
	UCHAR  TypeOfService;
	USHORT TotalLength;
	USHORT Identification;
	UCHAR  FragmentOffsetField   :5;
	UCHAR  MoreFragment :1;
	UCHAR  DonotFragment :1;
	UCHAR  ReservedZero :1;
	UCHAR  FragmentOffset;
	UCHAR  TimeToLive;
	UCHAR  Protocol;
	USHORT Checksum;
	UINT   SourceAddress;
	UINT   DestinationAddress;
};

struct PTCP_HEADER
{
	USHORT SourcePort;
	USHORT DestinationPort;
	UINT   Sequence;
	UINT   Acknowledge;
	UCHAR  NonceSumFlag   :1;
	UCHAR  ReservedPart1:3;
	UCHAR  DataOffset:4;
	UCHAR  FinishFlag  :1;
	UCHAR  SynchroniseFlag  :1;
	UCHAR  ResetFlag  :1;
	UCHAR  PushFlag  :1;
	UCHAR  AcknowledgmentFlag  :1;
	UCHAR  UrgentFlag  :1;
	UCHAR  EchoFlag  :1;
	UCHAR  CongestionWindowReducedFlag  :1;
	USHORT Window;
	USHORT Checksum;
	USHORT UrgentPointer;
};


struct PUDP_HEADER
{
	u_short SourcePort;
	u_short DestinationPort;
	u_short DatagramLength;
	u_short Checksum;
};

struct PICMP_HEADER
{
	u_int8_t Type;
	u_int8_t SubCode;
	u_int16_t Checksum;
	/*union
	{
		struct
		{
			u_int16_t	Identification;
			u_int16_t	Sequence;
		} Echo;
		u_int32_t	Gateway;
		struct
		{
		  u_int16_t	__unused;
		  u_int16_t	Mtu;
		} Frag;
	} un;*/
};


struct PIGMP_HEADER
{
	u_char	Type;
	u_char	Code;
	u_short Checksum;
	struct	in_addr	Group;
};

struct PARP_HEADER
{
	u_short	HardwareType;
	u_short	ProtocolType;
	u_char	HardwareAddressLength;
	u_char	ProtocolAddressLength;
	u_short	OperationCode;
#ifdef COMMENT_ONLY
	u_char	SourceHardwareAddress[];
	u_char	SourceProtocolAddress[];
	u_char	TargetHardwareAddress[];
	u_char	TargetProtocolAddress[];
#endif
};

#endif


