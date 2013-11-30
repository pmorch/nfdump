/*
 *  This file is part of the nfdump project.
 *
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
 *  $Id: nf_common.c 53 2005-11-17 07:45:34Z peter $
 *
 *  $LastChangedRevision: 53 $
 *	
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nf_common.h"
#include "panonymizer.h"

/* locals */
#define STRINGSIZE	1024

static char string[STRINGSIZE];

static const double _1KB = 1024.0;
static const double _1MB = 1024.0 * 1024.0;
static const double _1GB = 1024.0 * 1024.0 * 1024.0;
static const double _1TB = 1024.0 * 1024.0 * 1024.0 * 1024.0;

extern int byte_mode, packet_mode;
enum { NONE, LESS, MORE };

#ifdef __SUNPRO_C
extern
#endif
inline int TimeMsec_CMP(time_t t1, uint16_t offset1, time_t t2, uint16_t offset2 ) {

    if ( t1 > t2 )
        return 1;
    if ( t2 > t1 ) 
        return 2;
    // else t1 == t2 - offset is now relevant
    if ( offset1 > offset2 )
        return 1;
    if ( offset2 > offset1 )
        return 2;
    else
        // both times are the same
        return 0;
} // End of TimeMsec_CMP

void flow_header_raw(void *header, uint64_t numflows, uint64_t pkts, uint64_t bytes, char ** s, int anon) {
	/* Allocates and fills a string with a verbose representation of
		 the header pased as argument.
		 Result: 0 on success, !=0 on error
	*/  
char * t;
flow_header_t *h = (flow_header_t *)header;
time_t	now;
	
	now = h->unix_secs;
	t = ctime(&now);
	t[strlen(t)-1] = 0; 

	snprintf(string,STRINGSIZE-1 ,""
"Flow Header: binary version %2u\n"
"  count         =  %10u\n"
"  SysUptime     =  %10u\n"
"  unix_secs     =  %10d   [%s]\n"
"  unix_nsecs    =  %10d\n"
"  flow_sequence = %11u\n"
"  engine_type   =          %2d\n"
"  engine_id     =          %2d\n",
		h->layout_version,
		h->count,
		h->SysUptime,h->unix_secs,t,h->unix_nsecs,
		h->flow_sequence,h->engine_type,h->engine_id);
	*s = string;

} // End of flow_header_raw


void flow_record_raw(void *record, uint64_t numflows, uint64_t pkts, uint64_t bytes, char ** s, int anon) {
struct in_addr a,d,n;
char as[16], ds[16], ns[16], datestr1[64], datestr2[64];
char * str;
time_t	when;
struct tm *ts;
flow_record_t *r = (flow_record_t *)record;

	if ( anon ) {
		if ( r->srcaddr ) 
			r->srcaddr = anonymize(r->srcaddr);
		if ( r->dstaddr ) 
			r->dstaddr = anonymize(r->dstaddr);

		r->nexthop = anonymize(r->nexthop);
	}
	a.s_addr = htonl(r->srcaddr);
	d.s_addr = htonl(r->dstaddr);
	n.s_addr = htonl(r->nexthop);
	str = inet_ntoa(a);
	strncpy(as, inet_ntoa(a), 15);
	str = inet_ntoa(d);
	strncpy(ds, str, 15);
	str = inet_ntoa(n);
	strncpy(ns, str, 15);
	as[15] = 0;
	ds[15] = 0;
	ns[15] = 0;

	when = r->First;
	ts = localtime(&when);
	strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);

	when = r->Last;
	ts = localtime(&when);
	strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);

	snprintf(string, STRINGSIZE-1, "\n"
"Flow Record: \n"
"  addr        = %15s\n"
"  dstaddr     = %15s\n"
"  nexthop     = %15s\n"
"  input       =           %5u\n"
"  output      =           %5u\n"
"  dPkts       =      %10llu\n"
"  dOctets     =      %10llu\n"
"  First       =      %10u [%s]\n"
"  Last        =      %10u [%s]\n"
"  port        =           %5u\n"
"  dstport     =           %5u\n"
"  tcp_flags   =             %3u\n"
"  prot        =             %3u\n"
"  tos         =             %3u\n"
"  src_as      =           %5u\n"
"  dst_as      =           %5u\n"
"  msec_first  =           %5u\n"
"  msec_last   =           %5u"
, 
		as, ds, ns,
		r->input, r->output, pkts, bytes, r->First, datestr1, 
		r->Last, datestr2, r->srcport, r->dstport, r->tcp_flags, r->prot, r->tos,
		r->src_as, r->dst_as, r->msec_first, r->msec_last );

	string[STRINGSIZE-1] = 0;

	*s = string;

} // End of flow_record_raw

void flow_record_to_line(void *record, uint64_t numflows, uint64_t pkts, uint64_t bytes, char ** s, int anon) {
double	duration;
time_t 	tt;
struct 	in_addr a,d;
char 	as[16], ds[16], bytes_str[32], packets_str[32];
char 	*str;
char 	*prot;
char 	prot_long[16], datestr[64];
struct tm *ts;
flow_record_t *r = (flow_record_t *)record;

	if ( anon ) {
		if ( r->srcaddr ) 
			r->srcaddr = anonymize(r->srcaddr);
		if ( r->dstaddr ) 
			r->dstaddr = anonymize(r->dstaddr);
	}

	a.s_addr = htonl(r->srcaddr);
	d.s_addr = htonl(r->dstaddr);
	str = inet_ntoa(a);
	strncpy(as, inet_ntoa(a), 15);
	str = inet_ntoa(d);
	strncpy(ds, str, 15);
	as[15] = 0;
	ds[15] = 0;

	duration = r->Last - r->First;
	duration += ((double)r->msec_last - (double)r->msec_first) / 1000.0;

	tt = r->First;
	ts = localtime(&tt);
	strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", ts);

	switch (r->prot) { 
	case 1:
		prot = "ICMP";
		break;
	case 6:
		prot = "TCP ";
		break;
	case 17:
		prot = "UDP ";
		break;
	case 41:
		prot = "IPv6";
		break;
	case 46:
		prot = "RSVP";
		break;
	case 47:
		prot = "GRE ";
		break;
	case 50:
		prot = "ESP ";    // Encap Security Payload
		break;
	case 51:
		prot = "AH  ";    // Authentication Header 
		break;
	case 58:
		prot = "ICM6";
		break;
	case 89:
		prot = "OSPF";
		break;
	case 94:
		prot = "IPIP";
		break;
	case 103:
		prot = "PIM ";
		break;
	default:
		snprintf(prot_long,15,"%4d",r->prot);
		prot = prot_long;
	}

	format_number(bytes, bytes_str);
	format_number(pkts, packets_str);

	snprintf(string, STRINGSIZE-1 ,"%s.%03u %8.3f %s %15s:%-5i -> %15s:%-5i %8s %8s %5llu",
		datestr, r->msec_first, duration, prot, as, r->srcport, ds, r->dstport, packets_str, bytes_str, numflows);
	string[STRINGSIZE-1] = 0;

	*s = string;

} // End of flow_record_to_line


void flow_record_to_line_long(void *record, uint64_t numflows, uint64_t pkts, uint64_t bytes, char ** s, int anon) {
double	duration;
time_t 	tt;
struct 	in_addr a,d;
char 	as[16], ds[16], TCP_flags[7], bytes_str[32], packets_str[32];
char 	*str;
char 	*prot;
char 	prot_long[16], datestr[64];
struct tm * ts;
flow_record_t *r = (flow_record_t *)record;

	if ( anon ) {
		if ( r->srcaddr ) 
			r->srcaddr = anonymize(r->srcaddr);
		if ( r->dstaddr ) 
			r->dstaddr = anonymize(r->dstaddr);
	}
	a.s_addr = htonl(r->srcaddr);
	d.s_addr = htonl(r->dstaddr);
	str = inet_ntoa(a);
	strncpy(as, inet_ntoa(a), 15);
	str = inet_ntoa(d);
	strncpy(ds, str, 15);
	as[15] = 0;
	ds[15] = 0;

	duration = r->Last - r->First;
	duration += ((double)r->msec_last - (double)r->msec_first) / 1000.0;

	tt = r->First;
	ts = localtime(&tt);
	strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", ts);

	switch (r->prot) { 
	case 1:
		prot = "ICMP";
		break;
	case 6:
		prot = "TCP ";
		break;
	case 17:
		prot = "UDP ";
		break;
	case 41:
		prot = "IPv6";
		break;
	case 46:
		prot = "RSVP";
		break;
	case 47:
		prot = "GRE ";
		break;
	case 50:
		prot = "ESP ";    // Encap Security Payload
		break;
	case 51:
		prot = "AH  ";    // Authentication Header 
		break;
	case 58:
		prot = "ICM6";
		break;
	case 94:
		prot = "IPIP";
		break;
	case 89:
		prot = "OSPF";
		break;
	case 103:
		prot = "PIM ";
		break;
	default:
		snprintf(prot_long,15,"%4d",r->prot);
		prot = prot_long;
	}

	format_number(bytes, bytes_str);
	format_number(pkts, packets_str);

	TCP_flags[0] = r->tcp_flags & 32 ? 'U' : '.';
	TCP_flags[1] = r->tcp_flags & 16 ? 'A' : '.';
	TCP_flags[2] = r->tcp_flags &  8 ? 'P' : '.';
	TCP_flags[3] = r->tcp_flags &  4 ? 'R' : '.';
	TCP_flags[4] = r->tcp_flags &  2 ? 'S' : '.';
	TCP_flags[5] = r->tcp_flags &  1 ? 'F' : '.';
	TCP_flags[6] = '\0';

	snprintf(string, STRINGSIZE-1 ,"%s.%03u %8.3f %s %15s:%-5i -> %15s:%-5i %s %3i %8s %8s %5llu",
		datestr, r->msec_first, duration, prot, as, r->srcport, ds, r->dstport, TCP_flags, r->tos, packets_str, 
		bytes_str, numflows);
	string[STRINGSIZE-1] = 0;

	*s = string;

} // End of flow_record_to_line_long

void flow_record_to_line_extended(void *record, uint64_t numflows, uint64_t pkts, uint64_t bytes, char ** s, int anon) {
uint32_t 	Bpp; 
uint64_t	pps, bps;
double		duration;
time_t 		tt;
struct 		in_addr a,d;
char 		as[16], ds[16], TCP_flags[7], bytes_str[32], packets_str[32], pps_str[32], bps_str[32];
char 		*str;
char 		*prot;
char 		prot_long[16], datestr[64];
struct tm *ts;
flow_record_t *r = (flow_record_t *)record;


	if ( anon ) {
		if ( r->srcaddr ) 
			r->srcaddr = anonymize(r->srcaddr);
		if ( r->dstaddr ) 
			r->dstaddr = anonymize(r->dstaddr);
	}
	a.s_addr = htonl(r->srcaddr);
	d.s_addr = htonl(r->dstaddr);
	str = inet_ntoa(a);
	strncpy(as, inet_ntoa(a), 15);
	str = inet_ntoa(d);
	strncpy(ds, str, 15);
	as[15] = 0;
	ds[15] = 0;

	duration = r->Last - r->First;
	duration += ((double)r->msec_last - (double)r->msec_first) / 1000.0;

	tt = r->First;
	ts = localtime(&tt);
	strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", ts);

	switch (r->prot) { 
	case 1:
		prot = "ICMP";
		break;
	case 6:
		prot = "TCP ";
		break;
	case 17:
		prot = "UDP ";
		break;
	case 41:
		prot = "IPv6";
		break;
	case 46:
		prot = "RSVP";
		break;
	case 47:
		prot = "GRE ";
		break;
	case 50:
		prot = "ESP ";    // Encap Security Payload
		break;
	case 51:
		prot = "AH  ";    // Authentication Header 
		break;
	case 58:
		prot = "ICM6";
		break;
	case 94:
		prot = "IPIP";
		break;
	case 89:
		prot = "OSPF";
		break;
	case 103:
		prot = "PIM ";
		break;
	default:
		snprintf(prot_long,15,"%4d",r->prot);
		prot = prot_long;
	}

	TCP_flags[0] = r->tcp_flags & 32 ? 'U' : '.';
	TCP_flags[1] = r->tcp_flags & 16 ? 'A' : '.';
	TCP_flags[2] = r->tcp_flags &  8 ? 'P' : '.';
	TCP_flags[3] = r->tcp_flags &  4 ? 'R' : '.';
	TCP_flags[4] = r->tcp_flags &  2 ? 'S' : '.';
	TCP_flags[5] = r->tcp_flags &  1 ? 'F' : '.';
	TCP_flags[6] = '\0';

	if ( duration ) {
		pps = pkts / duration;				// packets per second
		bps = ( bytes << 3 ) / duration;	// bits per second. ( >> 3 ) -> * 8 to convert octets into bits
	} else {
		pps = bps = 0;
	}
	Bpp = bytes / pkts;			// Bytes per Packet
	format_number(bytes, bytes_str);
	format_number(pkts, packets_str);
	format_number(pps, pps_str);
	format_number(bps, bps_str);
	format_number(bps, bps_str);

	snprintf(string, STRINGSIZE-1 ,"%s.%03u %8.3f %s %15s:%-5i -> %15s:%-5i %s %3i %8s %8s %8s %8s %6u %5llu",
				datestr, r->msec_first, duration, prot, as, r->srcport, ds, r->dstport, TCP_flags, r->tos, packets_str, 
				bytes_str, pps_str, bps_str, Bpp, numflows);
	string[STRINGSIZE-1] = 0;

	*s = string;

} // End of flow_record_line_extended

void flow_record_to_pipe(void *record, uint64_t numflows, uint64_t pkts, uint64_t bytes, char ** s, int anon) {
flow_record_t *r = (flow_record_t *)record;

	if ( anon ) {
		if ( r->srcaddr ) 
			r->srcaddr = anonymize(r->srcaddr);
		if ( r->dstaddr ) 
			r->dstaddr = anonymize(r->dstaddr);
	}
	snprintf(string, STRINGSIZE-1 ,"%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%llu|%llu",
				r->First, r->msec_first ,r->Last, r->msec_last, r->prot, r->srcaddr, r->srcport, r->dstaddr, r->dstport, 
				r->tcp_flags, r->tos, pkts, bytes);

	string[STRINGSIZE-1] = 0;

	*s = string;

} // End of flow_record_pipe

#ifdef __SUNPRO_C
extern
#endif
inline void format_number(uint64_t num, char *s) {
double f = num;

	if ( f >= _1TB ) {
		snprintf(s, 31, "%5.1f T", f / _1TB );
	} else if ( f >= _1GB ) {
		snprintf(s, 31, "%5.1f G", f / _1GB );
	} else if ( f >= _1MB ) {
		snprintf(s, 31, "%5.1f M", f / _1MB );
/*
	} else if ( f >= _1KB ) {
		snprintf(s, 31, "%5.1f K", f / _1KB );
*/
	} else  {
		snprintf(s, 31, "%4.0f", f );
	} 

} // End of format_number

