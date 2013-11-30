/*
 *  Copyright (c) 2004, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of SWITCH nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 *  $Author: peter $
 *
 *  $Id: sflow.c 75 2006-05-21 15:32:48Z peter $
 *
 *  $LastChangedRevision: 75 $
 *	
 *
 */

/* 
 * sfcapd makes use of code originated from sflowtool by InMon Corp. 
 * Those parts of the code are distributed under the InMon Public License below.
 * All other/additional code is pubblished under BSD license.
 */


/*
 *  ----------------------------------------------------------------------- 
 *         Copyright (c) 2001-2002 InMon Corp.  All rights reserved.
 *  -----------------------------------------------------------------------
 * 
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer. 
 * 
 *  2. Redistributions in binary form must reproduce the above 
 *     copyright notice, this list of conditions and the following 
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 * 
 *  3. Redistributions of any form whatsoever must retain the following
 *     acknowledgment:
 *      "This product includes sFlow(TM), freely available from
 *       http://www.inmon.com/".
 *       
 *  4. All advertising materials mentioning features or use of this
 *     software must display the following acknowledgment:
 *      "This product includes sFlow(TM), freely available from
 *       http://www.inmon.com/".
 * 
 *  5. InMon Corp. may publish revised and/or new versions
 *     of the license from time to time. Each version will be given a
 *     distinguishing version number. Once covered code has been
 *     published under a particular version of the license, you may
 *     always continue to use it under the terms of that version. You
 *     may also choose to use such covered code under the terms of any
 *     subsequent version of the license published by InMon Corp.
 *     No one other than the InMon Corp. has the right to modify the terms
 *     applicable to covered code created under this License.
 *     
 *  6. The name "sFlow" must not be used to endorse or promote products 
 *     derived from this software without prior written permission
 *     from InMon Corp.  This does not apply to add-on libraries or tools
 *     that work in conjunction with sFlow.  In such a case the sFlow name
 *     may be used to indicate that the product supports sFlow.
 * 
 *  7. Products derived from this software may not be called "sFlow",
 *     nor may "sFlow" appear in their name, without prior written
 *     permission of InMon Corp.
 *
 *
 *  THIS SOFTWARE IS PROVIDED BY INMON CORP. ``AS IS'' AND
 *  ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
 *  PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL 
 *  INMON CORP. OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 *  OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  -------------------------------------------------------------------- 
 *
 *  This software consists of voluntary contributions made by many
 *  individuals on behalf of InMon Corp.
 *
 *  InMon Corp. can be contacted via Email at info@inmon.com.
 *  
 *  For more information on InMon Corp. and sFlow, 
 *  please see http://www.inmon.com/.
 *  
 *  InMon Public License Version 1.0 written May 31, 2001
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>
#include <setjmp.h>

#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <syslog.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nf_common.h"
#include "nffile.h"
#include "sflow.h"
#include "sflow_proto.h" // sFlow v5

/*
#ifdef DARWIN
#include <architecture/byte_order.h>
#define bswap_16(x) NXSwapShort(x)
#define bswap_32(x) NXSwapInt(x)
#else
#include <byteswap.h>
#endif
*/

/* 
 * unused
//
static uint32_t MyByteSwap32(uint32_t n) {
	return (((n & 0x000000FF)<<24) +
		((n & 0x0000FF00)<<8) +
		((n & 0x00FF0000)>>8) +
		((n & 0xFF000000)>>24));
}

static uint16_t MyByteSwap16(uint16_t n) {
	return ((n >> 8) | (n << 8));
}
*/

#define YES 1
#define NO 0

/* define my own IP header struct - to ease portability */
struct myiphdr {
		uint8_t version_and_headerLen;
		uint8_t tos;
		uint16_t tot_len;
		uint16_t id;
		uint16_t frag_off;
		uint8_t ttl;
		uint8_t protocol;
		uint16_t check;
		uint32_t saddr;
		uint32_t daddr;
};

/* same for tcp */
struct mytcphdr {
		uint16_t th_sport;		/* source port */
		uint16_t th_dport;		/* destination port */
		uint32_t th_seq;		/* sequence number */
		uint32_t th_ack;		/* acknowledgement number */
		uint8_t th_off_and_unused;
		uint8_t th_flags;
		uint16_t th_win;		/* window */
		uint16_t th_sum;		/* checksum */
		uint16_t th_urp;		/* urgent pointer */
};

/* and UDP */
struct myudphdr {
	uint16_t uh_sport;           /* source port */
	uint16_t uh_dport;           /* destination port */
	uint16_t uh_ulen;            /* udp length */
	uint16_t uh_sum;             /* udp checksum */
};

/* and ICMP */
struct myicmphdr {
	uint8_t type;		/* message type */
	uint8_t code;		/* type sub-code */
	/* ignore the rest */
};

typedef struct _SFForwardingTarget {
	struct _SFForwardingTarget *nxt;
	struct in_addr host;
	uint32_t port;
	struct sockaddr_in addr;
	int sock;
} SFForwardingTarget;

typedef enum { SFLFMT_FULL=0, SFLFMT_PCAP, SFLFMT_LINE } EnumSFLFormat;

typedef struct _SFConfig {
	uint16_t netFlowPeerAS;
	int disableNetFlowScale;
} SFConfig;

/* make the options structure global to the program */
static SFConfig sfConfig;

typedef struct _SFSample {
	struct in_addr sourceIP;
	SFLAddress agent_addr;
	uint32_t agentSubId;

	/* the raw pdu */
	u_char *rawSample;
	uint32_t rawSampleLen;
	u_char *endp;

	/* decode cursor */
	uint32_t *datap;

	uint32_t datagramVersion;
	uint32_t sampleType;
	uint32_t ds_class;
	uint32_t ds_index;

	/* generic interface counter sample */
	SFLIf_counters ifCounters;

	/* sample stream info */
	uint32_t sysUpTime;
	uint32_t sequenceNo;
	uint32_t sampledPacketSize;
	uint32_t samplesGenerated;
	uint32_t meanSkipCount;
	uint32_t samplePool;
	uint32_t dropEvents;

	/* the sampled header */
	uint32_t packet_data_tag;
	uint32_t headerProtocol;
	u_char *header;
	int headerLen;
	uint32_t stripped;

	/* header decode */
	int gotIPV4;
	int offsetToIPV4;
	int gotIPV6;
	int offsetToIPV6;
	struct in_addr dcd_srcIP;
	struct in_addr dcd_dstIP;
	uint32_t dcd_ipProtocol;
	uint32_t dcd_ipTos;
	uint32_t dcd_ipTTL;
	uint32_t dcd_sport;
	uint32_t dcd_dport;
	uint32_t dcd_tcpFlags;
	uint32_t ip_fragmentOffset;
	uint32_t udp_pduLen;

	/* ports */
	uint32_t inputPortFormat;
	uint32_t outputPortFormat;
	uint32_t inputPort;
	uint32_t outputPort;

	/* ethernet */
	uint32_t eth_type;
	uint32_t eth_len;
	u_char eth_src[8];
	u_char eth_dst[8];

	/* vlan */
	uint32_t in_vlan;
	uint32_t in_priority;
	uint32_t internalPriority;
	uint32_t out_vlan;
	uint32_t out_priority;

	/* extended data fields */
	uint32_t num_extended;
	uint32_t extended_data_tag;
#define SASAMPLE_EXTENDED_DATA_SWITCH 1
#define SASAMPLE_EXTENDED_DATA_ROUTER 4
#define SASAMPLE_EXTENDED_DATA_GATEWAY 8
#define SASAMPLE_EXTENDED_DATA_USER 16
#define SASAMPLE_EXTENDED_DATA_URL 32
#define SASAMPLE_EXTENDED_DATA_MPLS 64
#define SASAMPLE_EXTENDED_DATA_NAT 128
#define SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL 256
#define SASAMPLE_EXTENDED_DATA_MPLS_VC 512
#define SASAMPLE_EXTENDED_DATA_MPLS_FTN 1024
#define SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC 2048
#define SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL 4096

	/* IP forwarding info */
	SFLAddress nextHop;
	uint32_t srcMask;
	uint32_t dstMask;

	/* BGP info */
	SFLAddress bgp_nextHop;
	uint32_t my_as;
	uint32_t src_as;
	uint32_t src_peer_as;
	uint32_t dst_as_path_len;
	uint32_t *dst_as_path;
	/* note: version 4 dst as path segments just get printed, not stored here, however
	 * the dst_peer and dst_as are filled in, since those are used for netflow encoding
	 */
	uint32_t dst_peer_as;
	uint32_t dst_as;
	
	uint32_t communities_len;
	uint32_t *communities;
	uint32_t localpref;

	/* user id */
#define SA_MAX_EXTENDED_USER_LEN 200
	uint32_t src_user_charset;
	uint32_t src_user_len;
	char src_user[SA_MAX_EXTENDED_USER_LEN+1];
	uint32_t dst_user_charset;
	uint32_t dst_user_len;
	char dst_user[SA_MAX_EXTENDED_USER_LEN+1];

	/* url */
#define SA_MAX_EXTENDED_URL_LEN 200
#define SA_MAX_EXTENDED_HOST_LEN 200
	uint32_t url_direction;
	uint32_t url_len;
	char url[SA_MAX_EXTENDED_URL_LEN+1];
	uint32_t host_len;
	char host[SA_MAX_EXTENDED_HOST_LEN+1];

	/* mpls */
	SFLAddress mpls_nextHop;

	/* nat */
	SFLAddress nat_src;
	SFLAddress nat_dst;

	/* counter blocks */
	uint32_t statsSamplingInterval;
	uint32_t counterBlockVersion;

	/* exception handler context */
	jmp_buf env;

#define SFABORT(s, r) longjmp((s)->env, (r))
#define SF_ABORT_EOS 1
#define SF_ABORT_DECODE_ERROR 2
#define SF_ABORT_LENGTH_ERROR 3

	SFLAddress ipsrc;
	SFLAddress ipdst;
} SFSample;

typedef struct nf_buffer_s {
	void *writeto; 
	stat_record_t *stat_record; 
	data_block_header_t *data_header; 
	uint64_t first_seen; 
	uint64_t last_seen;
	uint32_t size;
	uint32_t count;
} nf_buffer_t;

static int printHex(const u_char *a, int len, char *buf, int bufLen, int marker, int bytesPerOutputLine);

static char *IP_to_a(uint32_t ipaddr, char *buf, int buflen);

static inline uint32_t getData32(SFSample *sample);

static inline uint32_t getData32_nobswap(SFSample *sample);

static inline uint64_t getData64(SFSample *sample);

static void writeCountersLine(SFSample *sample);

static void receiveError(SFSample *sample, char *errm, int hexdump) __attribute__ ((noreturn));

static inline void skipBytes(SFSample *sample, int skip);

static inline uint32_t sf_log_next32(SFSample *sample, char *fieldName);

static inline uint64_t sf_log_next64(SFSample *sample, char *fieldName);

static inline void sf_log_percentage(SFSample *sample, char *fieldName);

static inline uint32_t getString(SFSample *sample, char *buf, int bufLen);

static inline uint32_t getAddress(SFSample *sample, SFLAddress *address);

static inline char *printTag(uint32_t tag, char *buf, int bufLen);

static inline void skipTLVRecord(SFSample *sample, uint32_t tag, uint32_t len, char *description);

static inline void readSFlowDatagram(SFSample *sample, nf_buffer_t *output_buffer);

static inline void readFlowSample(SFSample *sample, int expanded, nf_buffer_t *output_buffer);

static inline void readCountersSample(SFSample *sample, int expanded, nf_buffer_t *output_buffer);

static inline void readFlowSample_v2v4(SFSample *sample, nf_buffer_t *output_buffer);

static inline void readCountersSample_v2v4(SFSample *sample, nf_buffer_t *output_buffer);

static inline void StoreSflowRecord(SFSample *sample, nf_buffer_t *output_buffer);

extern int verbose;


/*_________________---------------------------__________________
	_________________        sf_log             __________________
	-----------------___________________________------------------
*/

#ifdef DEBUG
void sf_log(char *fmt, ...);

void sf_log(char *fmt, ...) {
	if ( verbose ) {
		va_list args;
		va_start(args, fmt);
		vprintf(fmt, args);
	}
} // End of sf_log
#endif

#ifndef DEBUG
#	define sf_log(...) /* sf_log(...) */
#endif

/*_________________---------------------------__________________
	_________________        printHex           __________________
	-----------------___________________________------------------
*/

static u_char bin2hex(int nib) { return (nib < 10) ? ('0' + nib) : ('A' - 10 + nib); }

static int printHex(const u_char *a, int len, char *buf, int bufLen, int marker, int bytesPerOutputLine) {
	int b = 0, i = 0;
	for(; i < len; i++) {
		u_char byte;
		if(b > (bufLen - 10)) break;
		if(marker > 0 && i == marker) {
			buf[b++] = '<';
			buf[b++] = '*';
			buf[b++] = '>';
			buf[b++] = '-';
		}
		byte = a[i];
		buf[b++] = bin2hex(byte >> 4);
		buf[b++] = bin2hex(byte & 0x0f);
		if(i > 0 && (i % bytesPerOutputLine) == 0) buf[b++] = '\n';
		else {
			// separate the bytes with a dash
			if (i < (len - 1)) buf[b++] = '-';
		}
	}
	buf[b] = '\0';
	return b;
}

/*_________________---------------------------__________________
	_________________      IP_to_a              __________________
	-----------------___________________________------------------
*/

static char *IP_to_a(uint32_t ipaddr, char *buf, int buflen) {
	u_char *ip = (u_char *)&ipaddr;
	snprintf(buf, buflen, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
	buf[buflen-1] = '\0';
	return buf;
}

static char *printAddress(SFLAddress *address, char *buf, int bufLen) {
	if(address->type == SFLADDRESSTYPE_IP_V4)
		IP_to_a(address->address.ip_v4.s_addr, buf, bufLen);
	else {
		u_char *b = address->address.ip_v6.s6_addr;
		snprintf(buf, bufLen, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
	}
	return buf;
}

/*_________________---------------------------__________________
	_________________    writeFlowLine          __________________
	-----------------___________________________------------------
*/

static void writeFlowLine(SFSample *sample) {
char agentIP[51], srcIP[51], dstIP[51];
	// source
	printf("FLOW,%s,%d,%d,",
	 printAddress(&sample->agent_addr, agentIP, 50),
	 sample->inputPort,
	 sample->outputPort);
	// layer 2
	printf("%02x%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x%02x,0x%04x,%d,%d",
	 sample->eth_src[0],
	 sample->eth_src[1],
	 sample->eth_src[2],
	 sample->eth_src[3],
	 sample->eth_src[4],
	 sample->eth_src[5],
	 sample->eth_dst[0],
	 sample->eth_dst[1],
	 sample->eth_dst[2],
	 sample->eth_dst[3],
	 sample->eth_dst[4],
	 sample->eth_dst[5],
	 sample->eth_type,
	 sample->in_vlan,
	 sample->out_vlan);
	// layer 3/4
	printf(",IP: %s,%s,%d,0x%02x,%d,%d,%d,0x%02x",
	IP_to_a(sample->dcd_srcIP.s_addr, srcIP, 51),
	IP_to_a(sample->dcd_dstIP.s_addr, dstIP, 51),
	sample->dcd_ipProtocol,
	sample->dcd_ipTos,
	sample->dcd_ipTTL,
	sample->dcd_sport,
	sample->dcd_dport,
	sample->dcd_tcpFlags);
	// bytes
	printf(",%d,%d,%d\n",
	 sample->sampledPacketSize,
	 sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4,
	 sample->meanSkipCount);
}

/*_________________---------------------------__________________
	_________________    writeCountersLine      __________________
	-----------------___________________________------------------
*/

static void writeCountersLine(SFSample *sample)
{
	// source
	char agentIP[51];
	printf("CNTR,%s,", printAddress(&sample->agent_addr, agentIP, 50));
	printf("%u,%u,%llu,%u,%u,%llu,%u,%u,%u,%u,%u,%u,%llu,%u,%u,%u,%u,%u,%u\n",
	 sample->ifCounters.ifIndex,
	 sample->ifCounters.ifType,
	 sample->ifCounters.ifSpeed,
	 sample->ifCounters.ifDirection,
	 sample->ifCounters.ifStatus,
	 sample->ifCounters.ifInOctets,
	 sample->ifCounters.ifInUcastPkts,
	 sample->ifCounters.ifInMulticastPkts,
	 sample->ifCounters.ifInBroadcastPkts,
	 sample->ifCounters.ifInDiscards,
	 sample->ifCounters.ifInErrors,
	 sample->ifCounters.ifInUnknownProtos,
	 sample->ifCounters.ifOutOctets,
	 sample->ifCounters.ifOutUcastPkts,
	 sample->ifCounters.ifOutMulticastPkts,
	 sample->ifCounters.ifOutBroadcastPkts,
	 sample->ifCounters.ifOutDiscards,
	 sample->ifCounters.ifOutErrors,
	 sample->ifCounters.ifPromiscuousMode);
}

/*_________________---------------------------__________________
	_________________    receiveError           __________________
	-----------------___________________________------------------
*/

static void receiveError(SFSample *sample, char *errm, int hexdump) 
{
	char ipbuf[51];
	char scratch[6000];
	char *msg = "";
	char *hex = "";
	uint32_t markOffset = (u_char *)sample->datap - sample->rawSample;
	if(errm) msg = errm;
	if(hexdump) {
		printHex(sample->rawSample, sample->rawSampleLen, scratch, 6000, markOffset, 16);
		hex = scratch;
	}
	syslog(LOG_ERR, "%s (source IP = %s) %s\n", msg, IP_to_a(sample->sourceIP.s_addr, ipbuf, 51), hex);

	SFABORT(sample, SF_ABORT_DECODE_ERROR);

}

/*_________________---------------------------__________________
	_________________    lengthCheck            __________________
	-----------------___________________________------------------
*/

static void lengthCheck(SFSample *sample, char *description, u_char *start, int len) {
	uint32_t actualLen = (u_char *)sample->datap - start;
	if(actualLen != len) {
		syslog(LOG_ERR, "%s length error (expected %d, found %d)\n", description, len, actualLen);
		SFABORT(sample, SF_ABORT_LENGTH_ERROR);
	}
}

/*_________________---------------------------__________________
	_________________     decodeLinkLayer       __________________
	-----------------___________________________------------------
	store the offset to the start of the ipv4 header in the sequence_number field
	or -1 if not found. Decode the 802.1d if it's there.
*/

#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500

#define NFT_MIN_SIZ (NFT_ETHHDR_SIZ + sizeof(struct myiphdr))

static void decodeLinkLayer(SFSample *sample)
{
	u_char *start = (u_char *)sample->header;
	u_char *end = start + sample->headerLen;
	u_char *ptr = start;
	uint16_t type_len;

	/* assume not found */
	sample->gotIPV4 = NO;

	if(sample->headerLen < NFT_ETHHDR_SIZ) return; /* not enough for an Ethernet header */

	sf_log("dstMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
	memcpy(sample->eth_dst, ptr, 6);
	ptr += 6;

	sf_log("srcMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
	memcpy(sample->eth_src, ptr, 6);
	ptr += 6;
	type_len = (ptr[0] << 8) + ptr[1];
	ptr += 2;

	if(type_len == 0x8100) {
		/* VLAN  - next two bytes */
		uint32_t vlanData = (ptr[0] << 8) + ptr[1];
		uint32_t vlan = vlanData & 0x0fff;
#ifdef DEBUG
		uint32_t priority = vlanData >> 13;
#endif
		ptr += 2;
		/*  _____________________________________ */
		/* |   pri  | c |         vlan-id        | */
		/*  ------------------------------------- */
		/* [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] */
		sf_log("decodedVLAN %lu\n", vlan);
		sf_log("decodedPriority %lu\n", priority);
		sample->in_vlan = vlan;
		/* now get the type_len again (next two bytes) */
		type_len = (ptr[0] << 8) + ptr[1];
		ptr += 2;
	}

	/* now we're just looking for IP */
	if(sample->headerLen < NFT_MIN_SIZ) return; /* not enough for an IPv4 header */
	
	/* peek for IPX */
	if(type_len == 0x0200 || type_len == 0x0201 || type_len == 0x0600) {
#define IPX_HDR_LEN 30
#define IPX_MAX_DATA 546
		int ipxChecksum = (ptr[0] == 0xff && ptr[1] == 0xff);
		int ipxLen = (ptr[2] << 8) + ptr[3];
		if(ipxChecksum &&
			 ipxLen >= IPX_HDR_LEN &&
			 ipxLen <= (IPX_HDR_LEN + IPX_MAX_DATA))
			/* we don't do anything with IPX here */
			return;
	} 
	
	if(type_len <= NFT_MAX_8023_LEN) {
		/* assume 802.3+802.2 header */
		/* check for SNAP */
		if(ptr[0] == 0xAA &&
			 ptr[1] == 0xAA &&
			 ptr[2] == 0x03) {
			ptr += 3;
			if(ptr[0] != 0 ||
	 ptr[1] != 0 ||
	 ptr[2] != 0) {
	sf_log("VSNAP_OUI %02X-%02X-%02X\n", ptr[0], ptr[1], ptr[2]);
	return; /* no further decode for vendor-specific protocol */
			}
			ptr += 3;
			/* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
			type_len = (ptr[0] << 8) + ptr[1];
			ptr += 2;
		}
		else {
			if (ptr[0] == 0x06 &&
		ptr[1] == 0x06 &&
		(ptr[2] & 0x01)) {
	/* IP over 8022 */
	ptr += 3;
	/* force the type_len to be IP so we can inline the IP decode below */
	type_len = 0x0800;
			}
			else return;
		}
	}
	
	/* assume type_len is an ethernet-type now */
	sample->eth_type = type_len;

	if(type_len == 0x0800) {
		/* IPV4 */
		if((end - ptr) < sizeof(struct myiphdr)) return;
		/* look at first byte of header.... */
		/*  ___________________________ */
		/* |   version   |    hdrlen   | */
		/*  --------------------------- */
		if((*ptr >> 4) != 4) return; /* not version 4 */
		if((*ptr & 15) < 5) return; /* not IP (hdr len must be 5 quads or more) */
		/* survived all the tests - store the offset to the start of the ip header */
		sample->gotIPV4 = YES;
		sample->offsetToIPV4 = (ptr - start);
	}

	if(type_len == 0x86DD) {
		/* IPV6 */
		/* look at first byte of header.... */
		if((*ptr >> 4) != 6) return; /* not version 6 */
		/* survived all the tests - store the offset to the start of the ip6 header */
		sample->gotIPV6 = YES;
		sample->offsetToIPV6 = (ptr - start);
	}
}


/*_________________---------------------------__________________
	_________________     decodeIPLayer4        __________________
	-----------------___________________________------------------
*/

static void decodeIPLayer4(SFSample *sample, u_char *ptr, uint32_t ipProtocol) {
	u_char *end = sample->header + sample->headerLen;
	if(ptr > (end - 8)) return; // not enough header bytes left
	switch(ipProtocol) {
	case 1: /* ICMP */
		{
			struct myicmphdr icmp;
			memcpy(&icmp, ptr, sizeof(icmp));
			sf_log("ICMPType %u\n", icmp.type);
			sf_log("ICMPCode %u\n", icmp.code);
			sample->dcd_sport = icmp.type;
			sample->dcd_dport = icmp.code;
		}
		break;
	case 6: /* TCP */
		{
			struct mytcphdr tcp;
			memcpy(&tcp, ptr, sizeof(tcp));
			sample->dcd_sport = ntohs(tcp.th_sport);
			sample->dcd_dport = ntohs(tcp.th_dport);
			sample->dcd_tcpFlags = tcp.th_flags;
			sf_log("TCPSrcPort %u\n", sample->dcd_sport);
			sf_log("TCPDstPort %u\n",sample->dcd_dport);
			sf_log("TCPFlags %u\n", sample->dcd_tcpFlags);
			if(sample->dcd_dport == 80) {
	int bytesLeft;
	int headerBytes = (tcp.th_off_and_unused >> 4) * 4;
	ptr += headerBytes;
	bytesLeft = sample->header + sample->headerLen - ptr;
			}
		}
		break;
	case 17: /* UDP */
		{
			struct myudphdr udp;
			memcpy(&udp, ptr, sizeof(udp));
			sample->dcd_sport = ntohs(udp.uh_sport);
			sample->dcd_dport = ntohs(udp.uh_dport);
			sample->udp_pduLen = ntohs(udp.uh_ulen);
			sf_log("UDPSrcPort %u\n", sample->dcd_sport);
			sf_log("UDPDstPort %u\n", sample->dcd_dport);
			sf_log("UDPBytes %u\n", sample->udp_pduLen);
		}
		break;
	default: /* some other protcol */
		break;
	}
}

/*_________________---------------------------__________________
	_________________     decodeIPV4            __________________
	-----------------___________________________------------------
*/

static void decodeIPV4(SFSample *sample)
{
	if(sample->gotIPV4) {
#ifdef DEBUG
		char buf[51];
#endif
		u_char *ptr = sample->header + sample->offsetToIPV4;
		/* Create a local copy of the IP header (cannot overlay structure in case it is not quad-aligned...some
			 platforms would core-dump if we tried that).  It's OK coz this probably performs just as well anyway. */
		struct myiphdr ip;
		memcpy(&ip, ptr, sizeof(ip));
		/* Value copy all ip elements into sample */
		sample->dcd_srcIP.s_addr = ip.saddr;
		sample->dcd_dstIP.s_addr = ip.daddr;
		sample->dcd_ipProtocol = ip.protocol;
		sample->dcd_ipTos = ip.tos;
		sample->dcd_ipTTL = ip.ttl;
		sf_log("ip.tot_len %d\n", ntohs(ip.tot_len));
		/* Log out the decoded IP fields */
		sf_log("srcIP %s\n", IP_to_a(sample->dcd_srcIP.s_addr, buf, 51));
		sf_log("dstIP %s\n", IP_to_a(sample->dcd_dstIP.s_addr, buf, 51));
		sf_log("IPProtocol %u\n", sample->dcd_ipProtocol);
		sf_log("IPTOS %u\n", sample->dcd_ipTos);
		sf_log("IPTTL %u\n", sample->dcd_ipTTL);
		/* check for fragments */
		sample->ip_fragmentOffset = ntohs(ip.frag_off) & 0x1FFF;
		if(sample->ip_fragmentOffset > 0) {
			sf_log("IPFragmentOffset %u\n", sample->ip_fragmentOffset);
		}
		else {
			/* advance the pointer to the next protocol layer */
			/* ip headerLen is expressed as a number of quads */
			ptr += (ip.version_and_headerLen & 0x0f) * 4;
			decodeIPLayer4(sample, ptr, ip.protocol);
		}
	}
}

/*_________________---------------------------__________________
	_________________     decodeIPV6            __________________
	-----------------___________________________------------------
*/

static void decodeIPV6(SFSample *sample)
{
	uint16_t payloadLen;
	uint32_t label;
	uint32_t nextHeader;
	u_char *end = sample->header + sample->headerLen;

	if(sample->gotIPV6) {
		u_char *ptr = sample->header + sample->offsetToIPV6;
		
		// check the version
		{
			int ipVersion = (*ptr >> 4);
			if(ipVersion != 6) {
	sf_log("header decode error: unexpected IP version: %d\n", ipVersion);
	return;
			}
		}

		// get the tos (priority)
		sample->dcd_ipTos = *ptr++ & 15;
		sf_log("IPTOS %u\n", sample->dcd_ipTos);
		// 24-bit label
		label = *ptr++;
		label <<= 8;
		label += *ptr++;
		label <<= 8;
		label += *ptr++;
		sf_log("IP6_label 0x%lx\n", label);
		// payload
		payloadLen = (ptr[0] << 8) + ptr[1];
		ptr += 2;
		// if payload is zero, that implies a jumbo payload
		if(payloadLen == 0) sf_log("IPV6_payloadLen <jumbo>\n");
		else sf_log("IPV6_payloadLen %u\n", payloadLen);

		// next header
		nextHeader = *ptr++;

		// TTL
		sample->dcd_ipTTL = *ptr++;
		sf_log("IPTTL %u\n", sample->dcd_ipTTL);

		{// src and dst address
#ifdef DEBUG
			char buf[101];
#endif
			sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
			memcpy(&sample->ipsrc.address, ptr, 16);
			ptr +=16;
			sf_log("srcIP6 %s\n", printAddress(&sample->ipsrc, buf, 100));
			sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
			memcpy(&sample->ipdst.address, ptr, 16);
			ptr +=16;
			sf_log("dstIP6 %s\n", printAddress(&sample->ipdst, buf, 100));
		}

		// skip over some common header extensions...
		// http://searchnetworking.techtarget.com/originalContent/0,289142,sid7_gci870277,00.html
		while(nextHeader == 0 ||  // hop
		nextHeader == 43 || // routing
		nextHeader == 44 || // fragment
		// nextHeader == 50 || // encryption - don't bother coz we'll not be able to read any further
		nextHeader == 51 || // auth
		nextHeader == 60) { // destination options
			uint32_t optionLen, skip;
			sf_log("IP6HeaderExtension: %d\n", nextHeader);
			nextHeader = ptr[0];
			optionLen = 8 * (ptr[1] + 1);  // second byte gives option len in 8-byte chunks, not counting first 8
			skip = optionLen - 2;
			ptr += skip;
			if(ptr > end) return; // ran off the end of the header
		}
		
		// now that we have eliminated the extension headers, nextHeader should have what we want to
		// remember as the ip protocol...
		sample->dcd_ipProtocol = nextHeader;
		sf_log("IPProtocol %u\n", sample->dcd_ipProtocol);
		decodeIPLayer4(sample, ptr, sample->dcd_ipProtocol);
	}
}

/*_________________---------------------------__________________
	_________________   StoreSflowRecord     __________________
	-----------------___________________________------------------
*/

static inline void StoreSflowRecord(SFSample *sample, nf_buffer_t *output_buffer) {
common_record_t	*nf_record = (common_record_t *)output_buffer->writeto;
stat_record_t *stat_record = (stat_record_t *)output_buffer->stat_record;
struct timeval now;
void	*val;
uint32_t bytes, *v;
uint64_t _bytes, _packets, _t;	// tmp buffers

	gettimeofday(&now, NULL);

	// ignore fragments
	if( sample->ip_fragmentOffset > 0 ) 
		return;

	// count the bytes from the start of IP header, with the exception that
	// for udp packets we use the udp_pduLen. This is because the udp_pduLen
	// can be up tp 65535 bytes, which causes fragmentation at the IP layer.
	// Since the sampled fragments are discarded, we have to use this field
	// to get the total bytes estimates right.
	if(sample->udp_pduLen > 0) 
		bytes = sample->udp_pduLen;
	else 
		bytes = sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4;
	
	nf_record->flags		= 0;
	nf_record->mark			= 0;

	nf_record->first		= now.tv_sec;
	nf_record->last			= nf_record->first;
	nf_record->msec_first	= now.tv_usec / 1000;
	nf_record->msec_last	= nf_record->msec_first;
	_t						= 1000*now.tv_sec + nf_record->msec_first;	// tmp buff for first_seen

	nf_record->input		= (uint16_t)sample->inputPort;
	nf_record->output		= (uint16_t)sample->outputPort;
	nf_record->srcport		= (uint16_t)sample->dcd_sport;
	nf_record->dstport		= (uint16_t)sample->dcd_dport;
	nf_record->dir			= 0;
	nf_record->tcp_flags	= sample->dcd_tcpFlags;
	nf_record->prot			= sample->dcd_ipProtocol;
	nf_record->tos			= sample->dcd_ipTos;

/*
	if(sfConfig.netFlowPeerAS) {
		pkt.flow.srcAS = htons((uint16_t)sample->src_peer_as);   
		pkt.flow.dstAS = htons((uint16_t)sample->dst_peer_as);   
	}
	else {
		pkt.flow.srcAS = htons((uint16_t)sample->src_as);   
		pkt.flow.dstAS = htons((uint16_t)sample->dst_as);   
	}
*/
	nf_record->srcas		= (uint16_t)sample->src_as;
	nf_record->dstas		= (uint16_t)sample->dst_as;

	if(sample->gotIPV6) {
		ipv6_block_t	*addr = (ipv6_block_t *)nf_record->data;
		nf_record->flags		= 1;
		memcpy(&addr->srcaddr, &sample->ipsrc.address, 16);
		memcpy(&addr->dstaddr, &sample->ipdst.address, 16);

		val = (void *)((pointer_addr_t)nf_record->data + sizeof(ipv6_block_t));
	} else {
		uint32_t	*v4addr = (uint32_t *)nf_record->data;
		v4addr[0] = sample->dcd_srcIP.s_addr;
		v4addr[1] = sample->dcd_dstIP.s_addr;
		val = (void *)((pointer_addr_t)nf_record->data + 2 * sizeof(uint32_t));
	}

	// packets
	v = (uint32_t *)val;
	_packets = sample->meanSkipCount;
	*v++ = _packets;

	// bytes
	_bytes = sample->meanSkipCount * bytes;
	*v++ = _bytes;
	val = (void *)v;

	nf_record->size	= (pointer_addr_t)val - (pointer_addr_t)nf_record;

	// update first_seen, last_seen
	if ( _t < output_buffer->first_seen )	// the very first time stamp need to be set
		output_buffer->first_seen = _t;
	output_buffer->last_seen = _t;

	// Update stats
	switch (nf_record->prot) {
		case 1:
			stat_record->numflows_icmp++;
			stat_record->numpackets_icmp += _packets;
			stat_record->numbytes_icmp   += _bytes;
			break;
		case 6:
			stat_record->numflows_tcp++;
			stat_record->numpackets_tcp += _packets;
			stat_record->numbytes_tcp   += _bytes;
			break;
		case 17:
			stat_record->numflows_udp++;
			stat_record->numpackets_udp += _packets;
			stat_record->numbytes_udp   += _bytes;
			break;
		default:
			stat_record->numflows_other++;
			stat_record->numpackets_other += _packets;
			stat_record->numbytes_other   += _bytes;
	}
	stat_record->numflows++;
	stat_record->numpackets	+= _packets;
	stat_record->numbytes	+= _bytes;

	if ( verbose ) {
		master_record_t master_record;
		char	*string;
		ExpandRecord((common_record_t *)output_buffer->writeto, &master_record);
	 	format_file_block_record(&master_record, 1, &string, 0);
		printf("%s\n", string);
	}

	output_buffer->writeto = (void *)((pointer_addr_t)output_buffer->writeto + nf_record->size);
	output_buffer->size += nf_record->size;
	output_buffer->count++;

}
			
/*_________________---------------------------__________________
	_________________   read data fns           __________________
	-----------------___________________________------------------
*/

static inline uint32_t getData32(SFSample *sample) {
	if ((u_char *)sample->datap > sample->endp) 
		SFABORT(sample, SF_ABORT_EOS);
	return ntohl(*(sample->datap)++);
} // End of getData32

static inline uint32_t getData32_nobswap(SFSample *sample) {
	if ((u_char *)sample->datap > sample->endp) 
		SFABORT(sample, SF_ABORT_EOS);
	return *(sample->datap)++;
} // End of getData32_nobswap

static inline uint64_t getData64(SFSample *sample) {
uint64_t tmpLo, tmpHi;

	tmpHi = getData32(sample);
	tmpLo = getData32(sample);
	return (tmpHi << 32) + tmpLo;
} // End of getData64

static inline void skipBytes(SFSample *sample, int skip) {
int quads = (skip + 3) / 4;

	sample->datap += quads;
	if ( (u_char *)sample->datap > sample->endp) 
		SFABORT(sample, SF_ABORT_EOS);
} // End of skipBytes

static inline uint32_t sf_log_next32(SFSample *sample, char *fieldName) {
uint32_t val = getData32(sample);

	sf_log("%s %lu\n", fieldName, val);
	return val;
} // End of sf_log_next32

static inline uint64_t sf_log_next64(SFSample *sample, char *fieldName) {
uint64_t val64 = getData64(sample);

	sf_log("%s %llu\n", fieldName, val64);
	return val64;
} // End of sf_log_next64

static inline void sf_log_percentage(SFSample *sample, char *fieldName) {
uint32_t hundredths = getData32(sample);

	if ( hundredths == (uint32_t)-1) 
		sf_log("%s unknown\n", fieldName);
	else {
#ifdef DEBUG
		float percent = (float)hundredths / 10.0;
#endif
		sf_log("%s %.1f\n", fieldName, percent);
	}
} // End of sf_log_percentage


static inline uint32_t getString(SFSample *sample, char *buf, int bufLen) {
uint32_t len, read_len;

	len = getData32(sample);
	// truncate if too long
	read_len = (len >= bufLen) ? (bufLen - 1) : len;
	memcpy(buf, sample->datap, read_len);
	buf[read_len] = '\0';   // null terminate
	skipBytes(sample, len);
	return len;
} // End of getString

static inline uint32_t getAddress(SFSample *sample, SFLAddress *address) {

	address->type = getData32(sample);
	if(address->type == SFLADDRESSTYPE_IP_V4)
		address->address.ip_v4.s_addr = getData32_nobswap(sample);
	else {
		memcpy(&address->address.ip_v6.s6_addr, sample->datap, 16);
		skipBytes(sample, 16);
	}
	return address->type;
} // End of getAddress

static inline char *printTag(uint32_t tag, char *buf, int bufLen) {
	snprintf(buf, bufLen, "%u:%u", (tag >> 12), (tag & 0x00000FFF));
	return buf;
} // End of printTag

static inline void skipTLVRecord(SFSample *sample, uint32_t tag, uint32_t len, char *description) {
#ifdef DEBUG
char buf[51];
#endif

	sf_log("skipping unknown %s: %s len=%d\n", description, printTag(tag, buf, 50), len);
	skipBytes(sample, len);
} // End of skipTLVRecord

/*_________________---------------------------__________________
	_________________    readExtendedSwitch     __________________
	-----------------___________________________------------------
*/

static void readExtendedSwitch(SFSample *sample)
{
	sf_log("extendedType SWITCH\n");
	sample->in_vlan = getData32(sample);
	sample->in_priority = getData32(sample);
	sample->out_vlan = getData32(sample);
	sample->out_priority = getData32(sample);

	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_SWITCH;
	
	sf_log("in_vlan %lu\n", sample->in_vlan);
	sf_log("in_priority %lu\n", sample->in_priority);
	sf_log("out_vlan %lu\n", sample->out_vlan);
	sf_log("out_priority %lu\n", sample->out_priority);
}

/*_________________---------------------------__________________
	_________________    readExtendedRouter     __________________
	-----------------___________________________------------------
*/

static void readExtendedRouter(SFSample *sample)
{
#ifdef DEBUG
char buf[51];
#endif

	sf_log("extendedType ROUTER\n");
	getAddress(sample, &sample->nextHop);
	sample->srcMask = getData32(sample);
	sample->dstMask = getData32(sample);

	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_ROUTER;

	sf_log("nextHop %s\n", printAddress(&sample->nextHop, buf, 50));
	sf_log("srcSubnetMask %lu\n", sample->srcMask);
	sf_log("dstSubnetMask %lu\n", sample->dstMask);
}

/*_________________---------------------------__________________
	_________________  readExtendedGateway_v2   __________________
	-----------------___________________________------------------
*/

static void readExtendedGateway_v2(SFSample *sample)
{
	sf_log("extendedType GATEWAY\n");

	sample->my_as = getData32(sample);
	sample->src_as = getData32(sample);
	sample->src_peer_as = getData32(sample);
	sample->dst_as_path_len = getData32(sample);
	/* just point at the dst_as_path array */
	if(sample->dst_as_path_len > 0) {
		sample->dst_as_path = sample->datap;
		/* and skip over it in the input */
		skipBytes(sample, sample->dst_as_path_len * 4);
		// fill in the dst and dst_peer fields too
		sample->dst_peer_as = ntohl(sample->dst_as_path[0]);
		sample->dst_as = ntohl(sample->dst_as_path[sample->dst_as_path_len - 1]);
	}
	
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
	
	sf_log("my_as %lu\n", sample->my_as);
	sf_log("src_as %lu\n", sample->src_as);
	sf_log("src_peer_as %lu\n", sample->src_peer_as);
	sf_log("dst_as %lu\n", sample->dst_as);
	sf_log("dst_peer_as %lu\n", sample->dst_peer_as);
	sf_log("dst_as_path_len %lu\n", sample->dst_as_path_len);
	if(sample->dst_as_path_len > 0) {
		uint32_t i = 0;
		for(; i < sample->dst_as_path_len; i++) {
			if(i == 0) sf_log("dst_as_path ");
			else sf_log("-");
			sf_log("%lu", ntohl(sample->dst_as_path[i]));
		}
		sf_log("\n");
	}
}

/*_________________---------------------------__________________
	_________________  readExtendedGateway      __________________
	-----------------___________________________------------------
*/

static void readExtendedGateway(SFSample *sample)
{
#ifdef DEBUG
		char buf[51];
#endif
	uint32_t segments;
	int seg;

	sf_log("extendedType GATEWAY\n");

	if(sample->datagramVersion >= 5) {
		getAddress(sample, &sample->bgp_nextHop);
		sf_log("bgp_nexthop %s\n", printAddress(&sample->bgp_nextHop, buf, 50));
	}

	sample->my_as = getData32(sample);
	sample->src_as = getData32(sample);
	sample->src_peer_as = getData32(sample);
	sf_log("my_as %lu\n", sample->my_as);
	sf_log("src_as %lu\n", sample->src_as);
	sf_log("src_peer_as %lu\n", sample->src_peer_as);
	segments = getData32(sample);
	if(segments > 0) {
		sf_log("dst_as_path ");
		for(seg = 0; seg < segments; seg++) {
			uint32_t seg_type;
			uint32_t seg_len;
			int i;
			seg_type = getData32(sample);
			seg_len = getData32(sample);
			for(i = 0; i < seg_len; i++) {
	uint32_t asNumber;
	asNumber = getData32(sample);
	/* mark the first one as the dst_peer_as */
	if(i == 0 && seg == 0) sample->dst_peer_as = asNumber;
	else sf_log("-");
	/* make sure the AS sets are in parentheses */
	if(i == 0 && seg_type == SFLEXTENDED_AS_SET) sf_log("(");
	sf_log("%lu", asNumber);
	/* mark the last one as the dst_as */
	if(seg == (segments - 1) && i == (seg_len - 1)) sample->dst_as = asNumber;
			}
			if(seg_type == SFLEXTENDED_AS_SET) sf_log(")");
		}
		sf_log("\n");
	}
	sf_log("dst_as %lu\n", sample->dst_as);
	sf_log("dst_peer_as %lu\n", sample->dst_peer_as);

	sample->communities_len = getData32(sample);
	/* just point at the communities array */
	if(sample->communities_len > 0) sample->communities = sample->datap;
	/* and skip over it in the input */
	skipBytes(sample, sample->communities_len * 4);
 
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
	if(sample->communities_len > 0) {
		int j = 0;
		for(; j < sample->communities_len; j++) {
			if(j == 0) sf_log("BGP_communities ");
			else sf_log("-");
			sf_log("%lu", ntohl(sample->communities[j]));
		}
		sf_log("\n");
	}

	sample->localpref = getData32(sample);
	sf_log("BGP_localpref %lu\n", sample->localpref);

}

/*_________________---------------------------__________________
	_________________    readExtendedUser       __________________
	-----------------___________________________------------------
*/

static void readExtendedUser(SFSample *sample)
{
	sf_log("extendedType USER\n");

	if(sample->datagramVersion >= 5) {
		sample->src_user_charset = getData32(sample);
		sf_log("src_user_charset %d\n", sample->src_user_charset);
	}

	sample->src_user_len = getString(sample, sample->src_user, SA_MAX_EXTENDED_USER_LEN);

	if(sample->datagramVersion >= 5) {
		sample->dst_user_charset = getData32(sample);
		sf_log("dst_user_charset %d\n", sample->dst_user_charset);
	}

	sample->dst_user_len = getString(sample, sample->dst_user, SA_MAX_EXTENDED_USER_LEN);

	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_USER;
	
	sf_log("src_user %s\n", sample->src_user);
	sf_log("dst_user %s\n", sample->dst_user);
}

/*_________________---------------------------__________________
	_________________    readExtendedUrl        __________________
	-----------------___________________________------------------
*/

static void readExtendedUrl(SFSample *sample)
{
	sf_log("extendedType URL\n");

	sample->url_direction = getData32(sample);
	sf_log("url_direction %lu\n", sample->url_direction);
	sample->url_len = getString(sample, sample->url, SA_MAX_EXTENDED_URL_LEN);
	sf_log("url %s\n", sample->url);
	if(sample->datagramVersion >= 5) {
		sample->host_len = getString(sample, sample->host, SA_MAX_EXTENDED_HOST_LEN);
		sf_log("host %s\n", sample->host);
	}
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_URL;
}


/*_________________---------------------------__________________
	_________________       mplsLabelStack      __________________
	-----------------___________________________------------------
*/

static void mplsLabelStack(SFSample *sample, char *fieldName)
{
	SFLLabelStack lstk;
	uint32_t lab;
	lstk.depth = getData32(sample);
	/* just point at the lablelstack array */
	if(lstk.depth > 0) 
		lstk.stack = (uint32_t *)sample->datap;
	else
		lstk.stack = NULL;
	/* and skip over it in the input */
	skipBytes(sample, lstk.depth * 4);
 
	if(lstk.depth > 0) {
		int j = 0;
		for(; j < lstk.depth; j++) {
			if(j == 0) sf_log("%s ", fieldName);
			else sf_log("-");
			lab = ntohl(lstk.stack[j]);
			sf_log("%lu.%lu.%lu.%lu",
			 (lab >> 12),     // label
			 (lab >> 9) & 7,  // experimental
			 (lab >> 8) & 1,  // bottom of stack
			 (lab &  255));   // TTL
		}
		sf_log("\n");
	}
}

/*_________________---------------------------__________________
	_________________    readExtendedMpls       __________________
	-----------------___________________________------------------
*/

static void readExtendedMpls(SFSample *sample)
{
#ifdef DEBUG
		char buf[51];
#endif
	sf_log("extendedType MPLS\n");
	getAddress(sample, &sample->mpls_nextHop);
	sf_log("mpls_nexthop %s\n", printAddress(&sample->mpls_nextHop, buf, 50));

	mplsLabelStack(sample, "mpls_input_stack");
	mplsLabelStack(sample, "mpls_output_stack");
	
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS;
}

/*_________________---------------------------__________________
	_________________    readExtendedNat        __________________
	-----------------___________________________------------------
*/

static void readExtendedNat(SFSample *sample)
{
#ifdef DEBUG
		char buf[51];
#endif
	sf_log("extendedType NAT\n");
	getAddress(sample, &sample->nat_src);
	sf_log("nat_src %s\n", printAddress(&sample->nat_src, buf, 50));
	getAddress(sample, &sample->nat_dst);
	sf_log("nat_dst %s\n", printAddress(&sample->nat_dst, buf, 50));
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_NAT;
}


/*_________________---------------------------__________________
	_________________    readExtendedMplsTunnel __________________
	-----------------___________________________------------------
*/

static void readExtendedMplsTunnel(SFSample *sample)
{
#define SA_MAX_TUNNELNAME_LEN 100
	char tunnel_name[SA_MAX_TUNNELNAME_LEN+1];
	uint32_t tunnel_id, tunnel_cos;
	
	if(getString(sample, tunnel_name, SA_MAX_TUNNELNAME_LEN) > 0)
		sf_log("mpls_tunnel_lsp_name %s\n", tunnel_name);
	tunnel_id = getData32(sample);
	sf_log("mpls_tunnel_id %lu\n", tunnel_id);
	tunnel_cos = getData32(sample);
	sf_log("mpls_tunnel_cos %lu\n", tunnel_cos);
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL;
}

/*_________________---------------------------__________________
	_________________    readExtendedMplsVC     __________________
	-----------------___________________________------------------
*/

static void readExtendedMplsVC(SFSample *sample)
{
#define SA_MAX_VCNAME_LEN 100
	char vc_name[SA_MAX_VCNAME_LEN+1];
	uint32_t vll_vc_id, vc_cos;
	if(getString(sample, vc_name, SA_MAX_VCNAME_LEN) > 0)
		sf_log("mpls_vc_name %s\n", vc_name);
	vll_vc_id = getData32(sample);
	sf_log("mpls_vll_vc_id %lu\n", vll_vc_id);
	vc_cos = getData32(sample);
	sf_log("mpls_vc_cos %lu\n", vc_cos);
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_VC;
}

/*_________________---------------------------__________________
	_________________    readExtendedMplsFTN    __________________
	-----------------___________________________------------------
*/

static void readExtendedMplsFTN(SFSample *sample)
{
#define SA_MAX_FTN_LEN 100
	char ftn_descr[SA_MAX_FTN_LEN+1];
	uint32_t ftn_mask;
	if(getString(sample, ftn_descr, SA_MAX_FTN_LEN) > 0)
		sf_log("mpls_ftn_descr %s\n", ftn_descr);
	ftn_mask = getData32(sample);
	sf_log("mpls_ftn_mask %lu\n", ftn_mask);
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_FTN;
}

/*_________________---------------------------__________________
	_________________  readExtendedMplsLDP_FEC  __________________
	-----------------___________________________------------------
*/

static void readExtendedMplsLDP_FEC(SFSample *sample)
{
#ifdef DEBUG
	uint32_t fec_addr_prefix_len = getData32(sample);
#endif
	sf_log("mpls_fec_addr_prefix_len %lu\n", fec_addr_prefix_len);
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC;
}

/*_________________---------------------------__________________
	_________________  readExtendedVlanTunnel   __________________
	-----------------___________________________------------------
*/

static void readExtendedVlanTunnel(SFSample *sample)
{
	uint32_t lab;
	SFLLabelStack lstk;
	lstk.depth = getData32(sample);
	/* just point at the lablelstack array */
	if(lstk.depth > 0) 
		lstk.stack = (uint32_t *)sample->datap;
	else
		lstk.stack = NULL;
	/* and skip over it in the input */
	skipBytes(sample, lstk.depth * 4);
 
	if(lstk.depth > 0) {
		int j = 0;
		for(; j < lstk.depth; j++) {
			if(j == 0) sf_log("vlan_tunnel ");
			else sf_log("-");
			lab = ntohl(lstk.stack[j]);
			sf_log("0x%04x.%lu.%lu.%lu",
			 (lab >> 16),       // TPI
			 (lab >> 13) & 7,   // priority
			 (lab >> 12) & 1,   // CFI
			 (lab & 4095));     // VLAN
		}
		sf_log("\n");
	}
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL;
}

/*_________________---------------------------__________________
	_________________    readExtendedProcess    __________________
	-----------------___________________________------------------
*/

static void readExtendedProcess(SFSample *sample)
{
	char pname[51];
	uint32_t num_processes, i;
	sf_log("extendedType process\n");
	num_processes = getData32(sample);
	for(i = 0; i < num_processes; i++) {
#ifdef DEBUG
		uint32_t pid = getData32(sample);
#endif
		if(getString(sample, pname, 50) > 0) sf_log("pid %lu %s\n", pid, pname);
		else sf_log("pid %lu <no_process_name>\n", pid);
	}
}

/*_________________---------------------------__________________
	_________________  readFlowSample_header    __________________
	-----------------___________________________------------------
*/

static void readFlowSample_header(SFSample *sample) {
	sf_log("flowSampleType HEADER\n");
	sample->headerProtocol = getData32(sample);
	sf_log("headerProtocol %lu\n", sample->headerProtocol);
	sample->sampledPacketSize = getData32(sample);
	sf_log("sampledPacketSize %lu\n", sample->sampledPacketSize);
	if(sample->datagramVersion > 4) {
		// stripped count introduced in sFlow version 5
		sample->stripped = getData32(sample);
		sf_log("strippedBytes %lu\n", sample->stripped);
	}
	sample->headerLen = getData32(sample);
	sf_log("headerLen %lu\n", sample->headerLen);
	
	sample->header = (u_char *)sample->datap; /* just point at the header */
	skipBytes(sample, sample->headerLen);
	{
		char scratch[2000];
		printHex(sample->header, sample->headerLen, scratch, 2000, 0, 2000);
		sf_log("headerBytes %s\n", scratch);
	}
	
	switch(sample->headerProtocol) {
		/* the header protocol tells us where to jump into the decode */
	case SFLHEADER_ETHERNET_ISO8023:
		decodeLinkLayer(sample);
		break;
	case SFLHEADER_IPv4: 
		sample->gotIPV4 = YES;
		sample->offsetToIPV4 = 0;
		break;
	case SFLHEADER_ISO88024_TOKENBUS:
	case SFLHEADER_ISO88025_TOKENRING:
	case SFLHEADER_FDDI:
	case SFLHEADER_FRAME_RELAY:
	case SFLHEADER_X25:
	case SFLHEADER_PPP:
	case SFLHEADER_SMDS:
	case SFLHEADER_AAL5:
	case SFLHEADER_AAL5_IP:
	case SFLHEADER_IPv6:
	case SFLHEADER_MPLS:
		sf_log("NO_DECODE headerProtocol=%d\n", sample->headerProtocol);
		break;
	default:
		syslog(LOG_ERR, "undefined headerProtocol = %d\n", sample->headerProtocol);
		exit(-12);
	}
	
	if(sample->gotIPV4) {
		// report the size of the original IPPdu (including the IP header)
		sf_log("IPSize %d\n",  sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4);
		decodeIPV4(sample);
	}
	else if(sample->gotIPV6) {
		// report the size of the original IPPdu (including the IP header)
		sf_log("IPSize %d\n",  sample->sampledPacketSize - sample->stripped - sample->offsetToIPV6);
		decodeIPV6(sample);
	}

}

/*_________________---------------------------__________________
	_________________  readFlowSample_ethernet  __________________
	-----------------___________________________------------------
*/

static void readFlowSample_ethernet(SFSample *sample)
{
	u_char *p;
	sf_log("flowSampleType ETHERNET\n");
	sample->eth_len = getData32(sample);
	memcpy(sample->eth_src, sample->datap, 6);
	skipBytes(sample, 6);
	memcpy(sample->eth_dst, sample->datap, 6);
	skipBytes(sample, 6);
	sample->eth_type = getData32(sample);
	sf_log("ethernet_type %lu\n", sample->eth_type);
	sf_log("ethernet_len %lu\n", sample->eth_len);
	p = sample->eth_src;
	sf_log("ethernet_src %02x%02x%02x%02x%02x%02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);
	p = sample->eth_dst;
	sf_log("ethernet_dst %02x%02x%02x%02x%02x%02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);
}


/*_________________---------------------------__________________
	_________________    readFlowSample_IPv4    __________________
	-----------------___________________________------------------
*/

static void readFlowSample_IPv4(SFSample *sample)
{
	sf_log("flowSampleType IPV4\n");
	sample->headerLen = sizeof(SFLSampled_ipv4);
	sample->header = (u_char *)sample->datap; /* just point at the header */
	skipBytes(sample, sample->headerLen);
	{
#ifdef DEBUG
		char buf[51];
#endif
		SFLSampled_ipv4 nfKey;
		memcpy(&nfKey, sample->header, sizeof(nfKey));
		sample->sampledPacketSize = ntohl(nfKey.length);
		sf_log("sampledPacketSize %lu\n", sample->sampledPacketSize); 
		sf_log("IPSize %d\n",  sample->sampledPacketSize);
		sample->dcd_srcIP = nfKey.src_ip;
		sample->dcd_dstIP = nfKey.dst_ip;
		sample->dcd_ipProtocol = ntohl(nfKey.protocol);
		sample->dcd_ipTos = ntohl(nfKey.tos);
		sf_log("srcIP %s\n", IP_to_a(sample->dcd_srcIP.s_addr, buf, 51));
		sf_log("dstIP %s\n", IP_to_a(sample->dcd_dstIP.s_addr, buf, 51));
		sf_log("IPProtocol %u\n", sample->dcd_ipProtocol);
		sf_log("IPTOS %u\n", sample->dcd_ipTos);
		sample->dcd_sport = ntohl(nfKey.src_port);
		sample->dcd_dport = ntohl(nfKey.dst_port);
		switch(sample->dcd_ipProtocol) {
		case 1: /* ICMP */
			sf_log("ICMPType %u\n", sample->dcd_dport);
			/* not sure about the dest port being icmp type
	 - might be that src port is icmp type and dest
	 port is icmp code.  Still, have seen some
	 implementations where src port is 0 and dst
	 port is the type, so it may be safer to
	 assume that the destination port has the type */
			break;
		case 6: /* TCP */
			sf_log("TCPSrcPort %u\n", sample->dcd_sport);
			sf_log("TCPDstPort %u\n", sample->dcd_dport);
			sample->dcd_tcpFlags = ntohl(nfKey.tcp_flags);
			sf_log("TCPFlags %u\n", sample->dcd_tcpFlags);
			break;
		case 17: /* UDP */
			sf_log("UDPSrcPort %u\n", sample->dcd_sport);
			sf_log("UDPDstPort %u\n", sample->dcd_dport);
			break;
		default: /* some other protcol */
			break;
		}
	}
}

/*_________________---------------------------__________________
	_________________    readFlowSample_IPv6    __________________
	-----------------___________________________------------------
*/

static void readFlowSample_IPv6(SFSample *sample)
{
	sf_log("flowSampleType IPV6\n");
	sample->header = (u_char *)sample->datap; /* just point at the header */
	sample->headerLen = sizeof(SFLSampled_ipv6);
	skipBytes(sample, sample->headerLen);
	{
		SFLSampled_ipv6 nfKey6;
		memcpy(&nfKey6, sample->header, sizeof(nfKey6));
		sample->sampledPacketSize = ntohl(nfKey6.length);
		sf_log("sampledPacketSize %lu\n", sample->sampledPacketSize); 
	}
	/* bug: more decode to do here */
}

/*_________________---------------------------__________________
	_________________    readFlowSample_v2v4    __________________
	-----------------___________________________------------------
*/

static void readFlowSample_v2v4(SFSample *sample, nf_buffer_t *output_buffer) {
	sf_log("sampleType FLOWSAMPLE\n");

	sample->samplesGenerated = getData32(sample);
	sf_log("sampleSequenceNo %lu\n", sample->samplesGenerated);
	{
		uint32_t samplerId = getData32(sample);
		sample->ds_class = samplerId >> 24;
		sample->ds_index = samplerId & 0x00ffffff;
		sf_log("sourceId %lu:%lu\n", sample->ds_class, sample->ds_index);
	}
	
	sample->meanSkipCount = getData32(sample);
	sample->samplePool = getData32(sample);
	sample->dropEvents = getData32(sample);
	sample->inputPort = getData32(sample);
	sample->outputPort = getData32(sample);
	sf_log("meanSkipCount %lu\n", sample->meanSkipCount);
	sf_log("samplePool %lu\n", sample->samplePool);
	sf_log("dropEvents %lu\n", sample->dropEvents);
	sf_log("inputPort %lu\n", sample->inputPort);
	if(sample->outputPort & 0x80000000) {
		uint32_t numOutputs = sample->outputPort & 0x7fffffff;
		if(numOutputs > 0) sf_log("outputPort multiple %d\n", numOutputs);
		else sf_log("outputPort multiple >1\n");
	}
	else sf_log("outputPort %lu\n", sample->outputPort);
	
	sample->packet_data_tag = getData32(sample);
	
	switch(sample->packet_data_tag) {
		
	case INMPACKETTYPE_HEADER: readFlowSample_header(sample); break;
	case INMPACKETTYPE_IPV4: readFlowSample_IPv4(sample); break;
	case INMPACKETTYPE_IPV6: readFlowSample_IPv6(sample); break;
	default: receiveError(sample, "unexpected packet_data_tag", YES); break;
	}

	sample->extended_data_tag = 0;
	{
		uint32_t x;
		sample->num_extended = getData32(sample);
		for(x = 0; x < sample->num_extended; x++) {
			uint32_t extended_tag;
			extended_tag = getData32(sample);
			switch(extended_tag) {
			case INMEXTENDED_SWITCH: readExtendedSwitch(sample); break;
			case INMEXTENDED_ROUTER: readExtendedRouter(sample); break;
			case INMEXTENDED_GATEWAY:
	if(sample->datagramVersion == 2) readExtendedGateway_v2(sample);
	else readExtendedGateway(sample);
	break;
			case INMEXTENDED_USER: readExtendedUser(sample); break;
			case INMEXTENDED_URL: readExtendedUrl(sample); break;
			default: receiveError(sample, "unrecognized extended data tag", YES); break;
			}
		}
	}
	
	if(sample->gotIPV4 || sample->gotIPV6) 
		StoreSflowRecord(sample, output_buffer);

	/* if we are writing tcpdump format, write the next packet record now */
	/* or line-by-line output... */
	if ( verbose ) 
		writeFlowLine(sample);
}

/*_________________---------------------------__________________
	_________________    readFlowSample         __________________
	-----------------___________________________------------------
*/

static void readFlowSample(SFSample *sample, int expanded, nf_buffer_t *output_buffer) {
	uint32_t num_elements, sampleLength;
	u_char *sampleStart;

	sf_log("sampleType FLOWSAMPLE\n");
	sampleLength = getData32(sample);
	sampleStart = (u_char *)sample->datap;
	sample->samplesGenerated = getData32(sample);
	sf_log("sampleSequenceNo %lu\n", sample->samplesGenerated);
	if(expanded) {
		sample->ds_class = getData32(sample);
		sample->ds_index = getData32(sample);
	}
	else {
		uint32_t samplerId = getData32(sample);
		sample->ds_class = samplerId >> 24;
		sample->ds_index = samplerId & 0x00ffffff;
	}
	sf_log("sourceId %lu:%lu\n", sample->ds_class, sample->ds_index);

	sample->meanSkipCount = getData32(sample);
	sample->samplePool = getData32(sample);
	sample->dropEvents = getData32(sample);
	sf_log("meanSkipCount %lu\n", sample->meanSkipCount);
	sf_log("samplePool %lu\n", sample->samplePool);
	sf_log("dropEvents %lu\n", sample->dropEvents);
	if(expanded) {
		sample->inputPortFormat = getData32(sample);
		sample->inputPort = getData32(sample);
		sample->outputPortFormat = getData32(sample);
		sample->outputPort = getData32(sample);
	}
	else {
		uint32_t inp, outp;
		inp = getData32(sample);
		outp = getData32(sample);
		sample->inputPortFormat = inp >> 30;
		sample->outputPortFormat = outp >> 30;
		sample->inputPort = inp & 0x3fffffff;
		sample->outputPort = outp & 0x3fffffff;
	}
	if(sample->inputPortFormat == 3) sf_log("inputPort format==3 %lu\n", sample->inputPort);
	else if(sample->inputPortFormat == 2) sf_log("inputPort multiple %lu\n", sample->inputPort);
	else if(sample->inputPortFormat == 1) sf_log("inputPort dropCode %lu\n", sample->inputPort);
	else if(sample->inputPortFormat == 0) sf_log("inputPort %lu\n", sample->inputPort);
	if(sample->outputPortFormat == 3) sf_log("outputPort format==3 %lu\n", sample->outputPort);
	else if(sample->outputPortFormat == 2) sf_log("outputPort multiple %lu\n", sample->outputPort);
	else if(sample->outputPortFormat == 1) sf_log("outputPort dropCode %lu\n", sample->outputPort);
	else if(sample->outputPortFormat == 0) sf_log("outputPort %lu\n", sample->outputPort);

	num_elements = getData32(sample);
	{
		int el;
		for(el = 0; el < num_elements; el++) {
#ifdef DEBUG
			char buf[51];
#endif
			uint32_t tag, length;
			u_char *start;
			tag = getData32(sample);
			sf_log("flowBlock_tag %s\n", printTag(tag, buf, 50));
			length = getData32(sample);
			start = (u_char *)sample->datap;

			switch(tag) {
			case SFLFLOW_HEADER:     readFlowSample_header(sample); break;
			case SFLFLOW_ETHERNET:   readFlowSample_ethernet(sample); break;
			case SFLFLOW_IPV4:       readFlowSample_IPv4(sample); break;
			case SFLFLOW_IPV6:       readFlowSample_IPv6(sample); break;
			case SFLFLOW_EX_SWITCH:  readExtendedSwitch(sample); break;
			case SFLFLOW_EX_ROUTER:  readExtendedRouter(sample); break;
			case SFLFLOW_EX_GATEWAY: readExtendedGateway(sample); break;
			case SFLFLOW_EX_USER:    readExtendedUser(sample); break;
			case SFLFLOW_EX_URL:     readExtendedUrl(sample); break;
			case SFLFLOW_EX_MPLS:    readExtendedMpls(sample); break;
			case SFLFLOW_EX_NAT:     readExtendedNat(sample); break;
			case SFLFLOW_EX_MPLS_TUNNEL:  readExtendedMplsTunnel(sample); break;
			case SFLFLOW_EX_MPLS_VC:      readExtendedMplsVC(sample); break;
			case SFLFLOW_EX_MPLS_FTN:     readExtendedMplsFTN(sample); break;
			case SFLFLOW_EX_MPLS_LDP_FEC: readExtendedMplsLDP_FEC(sample); break;
			case SFLFLOW_EX_VLAN_TUNNEL:  readExtendedVlanTunnel(sample); break;
			case SFLFLOW_EX_PROCESS:      readExtendedProcess(sample); break;
			default: skipTLVRecord(sample, tag, length, "flow_sample_element"); break;
			}
			lengthCheck(sample, "flow_sample_element", start, length);
		}
	}
	lengthCheck(sample, "flow_sample", sampleStart, sampleLength);
	
	if ( sample->gotIPV4 || sample->gotIPV6 )
		StoreSflowRecord(sample, output_buffer);

	/* or line-by-line output... */
	if ( verbose ) 
		writeFlowLine(sample);
}

/*_________________---------------------------__________________
	_________________  readCounters_generic     __________________
	-----------------___________________________------------------
*/

static void readCounters_generic(SFSample *sample)
{
	/* the first part of the generic counters block is really just more info about the interface. */
	sample->ifCounters.ifIndex = sf_log_next32(sample, "ifIndex");
	sample->ifCounters.ifType = sf_log_next32(sample, "networkType");
	sample->ifCounters.ifSpeed = sf_log_next64(sample, "ifSpeed");
	sample->ifCounters.ifDirection = sf_log_next32(sample, "ifDirection");
	sample->ifCounters.ifStatus = sf_log_next32(sample, "ifStatus");
	/* the generic counters always come first */
	sample->ifCounters.ifInOctets = sf_log_next64(sample, "ifInOctets");
	sample->ifCounters.ifInUcastPkts = sf_log_next32(sample, "ifInUcastPkts");
	sample->ifCounters.ifInMulticastPkts = sf_log_next32(sample, "ifInMulticastPkts");
	sample->ifCounters.ifInBroadcastPkts = sf_log_next32(sample, "ifInBroadcastPkts");
	sample->ifCounters.ifInDiscards = sf_log_next32(sample, "ifInDiscards");
	sample->ifCounters.ifInErrors = sf_log_next32(sample, "ifInErrors");
	sample->ifCounters.ifInUnknownProtos = sf_log_next32(sample, "ifInUnknownProtos");
	sample->ifCounters.ifOutOctets = sf_log_next64(sample, "ifOutOctets");
	sample->ifCounters.ifOutUcastPkts = sf_log_next32(sample, "ifOutUcastPkts");
	sample->ifCounters.ifOutMulticastPkts = sf_log_next32(sample, "ifOutMulticastPkts");
	sample->ifCounters.ifOutBroadcastPkts = sf_log_next32(sample, "ifOutBroadcastPkts");
	sample->ifCounters.ifOutDiscards = sf_log_next32(sample, "ifOutDiscards");
	sample->ifCounters.ifOutErrors = sf_log_next32(sample, "ifOutErrors");
	sample->ifCounters.ifPromiscuousMode = sf_log_next32(sample, "ifPromiscuousMode");
}
 
/*_________________---------------------------__________________
	_________________  readCounters_ethernet    __________________
	-----------------___________________________------------------
*/

static  void readCounters_ethernet(SFSample *sample)
{
	sf_log_next32(sample, "dot3StatsAlignmentErrors");
	sf_log_next32(sample, "dot3StatsFCSErrors");
	sf_log_next32(sample, "dot3StatsSingleCollisionFrames");
	sf_log_next32(sample, "dot3StatsMultipleCollisionFrames");
	sf_log_next32(sample, "dot3StatsSQETestErrors");
	sf_log_next32(sample, "dot3StatsDeferredTransmissions");
	sf_log_next32(sample, "dot3StatsLateCollisions");
	sf_log_next32(sample, "dot3StatsExcessiveCollisions");
	sf_log_next32(sample, "dot3StatsInternalMacTransmitErrors");
	sf_log_next32(sample, "dot3StatsCarrierSenseErrors");
	sf_log_next32(sample, "dot3StatsFrameTooLongs");
	sf_log_next32(sample, "dot3StatsInternalMacReceiveErrors");
	sf_log_next32(sample, "dot3StatsSymbolErrors");
}	  

 
/*_________________---------------------------__________________
	_________________  readCounters_tokenring   __________________
	-----------------___________________________------------------
*/

static void readCounters_tokenring(SFSample *sample)
{
	sf_log_next32(sample, "dot5StatsLineErrors");
	sf_log_next32(sample, "dot5StatsBurstErrors");
	sf_log_next32(sample, "dot5StatsACErrors");
	sf_log_next32(sample, "dot5StatsAbortTransErrors");
	sf_log_next32(sample, "dot5StatsInternalErrors");
	sf_log_next32(sample, "dot5StatsLostFrameErrors");
	sf_log_next32(sample, "dot5StatsReceiveCongestions");
	sf_log_next32(sample, "dot5StatsFrameCopiedErrors");
	sf_log_next32(sample, "dot5StatsTokenErrors");
	sf_log_next32(sample, "dot5StatsSoftErrors");
	sf_log_next32(sample, "dot5StatsHardErrors");
	sf_log_next32(sample, "dot5StatsSignalLoss");
	sf_log_next32(sample, "dot5StatsTransmitBeacons");
	sf_log_next32(sample, "dot5StatsRecoverys");
	sf_log_next32(sample, "dot5StatsLobeWires");
	sf_log_next32(sample, "dot5StatsRemoves");
	sf_log_next32(sample, "dot5StatsSingles");
	sf_log_next32(sample, "dot5StatsFreqErrors");
}

 
/*_________________---------------------------__________________
	_________________  readCounters_vg          __________________
	-----------------___________________________------------------
*/

static void readCounters_vg(SFSample *sample)
{
	sf_log_next32(sample, "dot12InHighPriorityFrames");
	sf_log_next64(sample, "dot12InHighPriorityOctets");
	sf_log_next32(sample, "dot12InNormPriorityFrames");
	sf_log_next64(sample, "dot12InNormPriorityOctets");
	sf_log_next32(sample, "dot12InIPMErrors");
	sf_log_next32(sample, "dot12InOversizeFrameErrors");
	sf_log_next32(sample, "dot12InDataErrors");
	sf_log_next32(sample, "dot12InNullAddressedFrames");
	sf_log_next32(sample, "dot12OutHighPriorityFrames");
	sf_log_next64(sample, "dot12OutHighPriorityOctets");
	sf_log_next32(sample, "dot12TransitionIntoTrainings");
	sf_log_next64(sample, "dot12HCInHighPriorityOctets");
	sf_log_next64(sample, "dot12HCInNormPriorityOctets");
	sf_log_next64(sample, "dot12HCOutHighPriorityOctets");
}


 
/*_________________---------------------------__________________
	_________________  readCounters_vlan        __________________
	-----------------___________________________------------------
*/

static void readCounters_vlan(SFSample *sample)
{
	sample->in_vlan = getData32(sample);
	sf_log("in_vlan %lu\n", sample->in_vlan);
	sf_log_next64(sample, "octets");
	sf_log_next32(sample, "ucastPkts");
	sf_log_next32(sample, "multicastPkts");
	sf_log_next32(sample, "broadcastPkts");
	sf_log_next32(sample, "discards");
}
 
/*_________________---------------------------__________________
	_________________  readCounters_processor   __________________
	-----------------___________________________------------------
*/

static void readCounters_processor(SFSample *sample)
{
	sf_log_percentage(sample, "5s_cpu");
	sf_log_percentage(sample, "1m_cpu");
	sf_log_percentage(sample, "5m_cpu");
	sf_log_next64(sample, "total_memory_bytes");
	sf_log_next64(sample, "free_memory_bytes");
}

/*_________________---------------------------__________________
	_________________  readCountersSample_v2v4  __________________
	-----------------___________________________------------------
*/

static void readCountersSample_v2v4(SFSample *sample, nf_buffer_t *output_buffer)
{
	sf_log("sampleType COUNTERSSAMPLE\n");
	sample->samplesGenerated = getData32(sample);
	sf_log("sampleSequenceNo %lu\n", sample->samplesGenerated);
	{
		uint32_t samplerId = getData32(sample);
		sample->ds_class = samplerId >> 24;
		sample->ds_index = samplerId & 0x00ffffff;
	}
	sf_log("sourceId %lu:%lu\n", sample->ds_class, sample->ds_index);


	sample->statsSamplingInterval = getData32(sample);
	sf_log("statsSamplingInterval %lu\n", sample->statsSamplingInterval);
	/* now find out what sort of counter blocks we have here... */
	sample->counterBlockVersion = getData32(sample);
	sf_log("counterBlockVersion %lu\n", sample->counterBlockVersion);
	
	/* first see if we should read the generic stats */
	switch(sample->counterBlockVersion) {
	case INMCOUNTERSVERSION_GENERIC:
	case INMCOUNTERSVERSION_ETHERNET:
	case INMCOUNTERSVERSION_TOKENRING:
	case INMCOUNTERSVERSION_FDDI:
	case INMCOUNTERSVERSION_VG:
	case INMCOUNTERSVERSION_WAN: readCounters_generic(sample); break;
	case INMCOUNTERSVERSION_VLAN: break;
	default: receiveError(sample, "unknown stats version", YES); break;
	}
	
	/* now see if there are any specific counter blocks to add */
	switch(sample->counterBlockVersion) {
	case INMCOUNTERSVERSION_GENERIC: /* nothing more */ break;
	case INMCOUNTERSVERSION_ETHERNET: readCounters_ethernet(sample); break;
	case INMCOUNTERSVERSION_TOKENRING:readCounters_tokenring(sample); break;
	case INMCOUNTERSVERSION_FDDI: break;
	case INMCOUNTERSVERSION_VG: readCounters_vg(sample); break;
	case INMCOUNTERSVERSION_WAN: break;
	case INMCOUNTERSVERSION_VLAN: readCounters_vlan(sample); break;
	default: receiveError(sample, "unknown INMCOUNTERSVERSION", YES); break;
	}
	/* line-by-line output... */
	writeCountersLine(sample);
}

/*_________________---------------------------__________________
	_________________   readCountersSample      __________________
	-----------------___________________________------------------
*/

static void readCountersSample(SFSample *sample, int expanded, nf_buffer_t *output_buffer) {
	uint32_t sampleLength;
	uint32_t num_elements;
	u_char *sampleStart;
	sf_log("sampleType COUNTERSSAMPLE\n");
	sampleLength = getData32(sample);
	sampleStart = (u_char *)sample->datap;
	sample->samplesGenerated = getData32(sample);
	
	sf_log("sampleSequenceNo %lu\n", sample->samplesGenerated);
	if(expanded) {
		sample->ds_class = getData32(sample);
		sample->ds_index = getData32(sample);
	}
	else {
		uint32_t samplerId = getData32(sample);
		sample->ds_class = samplerId >> 24;
		sample->ds_index = samplerId & 0x00ffffff;
	}
	sf_log("sourceId %lu:%lu\n", sample->ds_class, sample->ds_index);
	
	num_elements = getData32(sample);
	{
		int el;
		for(el = 0; el < num_elements; el++) {
#ifdef DEBUG
			char buf[51];
#endif
			uint32_t tag, length;
			u_char *start;
			tag = getData32(sample);
			sf_log("counterBlock_tag %s\n", printTag(tag, buf, 50));
			length = getData32(sample);
			start = (u_char *)sample->datap;
			
			switch(tag) {
			case SFLCOUNTERS_GENERIC: readCounters_generic(sample); break;
			case SFLCOUNTERS_ETHERNET: readCounters_ethernet(sample); break;
			case SFLCOUNTERS_TOKENRING:readCounters_tokenring(sample); break;
			case SFLCOUNTERS_VG: readCounters_vg(sample); break;
			case SFLCOUNTERS_VLAN: readCounters_vlan(sample); break;
			case SFLCOUNTERS_PROCESSOR: readCounters_processor(sample); break;
			default: skipTLVRecord(sample, tag, length, "counters_sample_element"); break;
			}
			lengthCheck(sample, "counters_sample_element", start, length);
		}
	}
	lengthCheck(sample, "counters_sample", sampleStart, sampleLength);
	/* line-by-line output... */
	writeCountersLine(sample);
}

/*_________________---------------------------__________________
	_________________      readSFlowDatagram    __________________
	-----------------___________________________------------------
*/

static inline void readSFlowDatagram(SFSample *sample, nf_buffer_t *output_buffer) {
uint32_t samplesInPacket;
uint32_t samp = 0;
struct timeval now;
#ifdef DEBUG
char buf[51];
#endif

	/* log some datagram info */
	now.tv_sec = time(NULL);
	now.tv_usec = 0;
	sf_log("datagramSourceIP %s\n", IP_to_a(sample->sourceIP.s_addr, buf, 51));
	sf_log("datagramSize %lu\n", sample->rawSampleLen);
	sf_log("unixSecondsUTC %lu\n", now.tv_sec);

	/* check the version */
	sample->datagramVersion = getData32(sample);
	sf_log("datagramVersion %d\n", sample->datagramVersion);
	if(sample->datagramVersion != 2 &&
		 sample->datagramVersion != 4 &&
		 sample->datagramVersion != 5) {
		receiveError(sample,	"unexpected datagram version number\n", YES);
	}
	
	/* get the agent address */
	getAddress(sample, &sample->agent_addr);

	/* version 5 has an agent sub-id as well */
	if(sample->datagramVersion >= 5) {
		sample->agentSubId = getData32(sample);
		sf_log("agentSubId %lu\n", sample->agentSubId);
	}

	sample->sequenceNo = getData32(sample);	/* this is the packet sequence number */
	sample->sysUpTime = getData32(sample);
	samplesInPacket = getData32(sample);
	sf_log("agent %s\n", printAddress(&sample->agent_addr, buf, 50));
	sf_log("packetSequenceNo %lu\n", sample->sequenceNo);
	sf_log("sysUpTime %lu\n", sample->sysUpTime);
	sf_log("samplesInPacket %lu\n", samplesInPacket);

	/* now iterate and pull out the flows and counters samples */
	for(; samp < samplesInPacket; samp++) {
		// just read the tag, then call the approriate decode fn
		sample->sampleType = getData32(sample);
		sf_log("startSample ----------------------\n");
		sf_log("sampleType_tag %s\n", printTag(sample->sampleType, buf, 50));
		if(sample->datagramVersion >= 5) {
			switch(sample->sampleType) {
				case SFLFLOW_SAMPLE: readFlowSample(sample, NO, output_buffer); 
					break;
				case SFLCOUNTERS_SAMPLE: readCountersSample(sample, NO, output_buffer); 
					break;
				case SFLFLOW_SAMPLE_EXPANDED: readFlowSample(sample, YES, output_buffer); 
					break;
				case SFLCOUNTERS_SAMPLE_EXPANDED: readCountersSample(sample, YES, output_buffer); 
					break;
				default: skipTLVRecord(sample, sample->sampleType, getData32(sample), "sample"); 
					break;
			}
		} else {
			switch(sample->sampleType) {
				case FLOWSAMPLE: readFlowSample_v2v4(sample, output_buffer); 
					break;
				case COUNTERSSAMPLE: readCountersSample_v2v4(sample, output_buffer); 
					break;
				default: receiveError(sample, "unexpected sample type", YES); 
					break;
			}
		}
		sf_log("endSample	 ----------------------\n");
	}
} // readSFlowDatagram

void Init_sflow(void) {

	sfConfig.disableNetFlowScale = 0;
	sfConfig.netFlowPeerAS = 0;

} // End of Init_sflow

void *Process_sflow(void *in_buff, ssize_t in_buff_cnt, data_block_header_t *data_header, void *writeto, 
		stat_record_t *stat_record, uint64_t *first_seen, uint64_t *last_seen) {

SFSample 	sample;
nf_buffer_t	output_buffer;
int 		exceptionVal;

	memset(&sample, 0, sizeof(sample));
	sample.rawSample = in_buff;
	sample.rawSampleLen = in_buff_cnt;
	sample.sourceIP.s_addr = 0;

	output_buffer.writeto     = writeto; 
	output_buffer.stat_record = stat_record; 
	output_buffer.data_header = data_header; 
	output_buffer.first_seen  = *first_seen; 
	output_buffer.last_seen   = *last_seen;
	output_buffer.size		  = 0;
	output_buffer.count		  = 0;

	sf_log("startDatagram =================================\n");
	if((exceptionVal = setjmp(sample.env)) == 0)	{
		// TRY
		sample.datap = (uint32_t *)sample.rawSample;
		sample.endp = (u_char *)sample.rawSample + sample.rawSampleLen;
		readSFlowDatagram(&sample, &output_buffer );
	} else {
		// CATCH
		syslog(LOG_ERR, "caught exception: %d\n", exceptionVal);
	}
	sf_log("endDatagram	 =================================\n");

	data_header->size 		+= output_buffer.size;
	data_header->NumBlocks 	+= output_buffer.count;
	*first_seen				= output_buffer.first_seen;
	*last_seen				= output_buffer.last_seen;

	return output_buffer.writeto;

} // End of Process_sflow
