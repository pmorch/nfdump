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
 *  $Id: netflow_v5.c 15 2004-12-20 12:43:36Z peter $
 *
 *  $LastChangedRevision: 15 $
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

#include "netflow_v5.h"

/* locals */
#define STRINGSIZE	1024

static char string[STRINGSIZE];

static const double _1KB = 1024.0;
static const double _1MB = 1024.0 * 1024.0;
static const double _1GB = 1024.0 * 1024.0 * 1024.0;

extern int byte_mode, packet_mode;
enum { NONE, LESS, MORE };

void netflow_v5_header_to_string(void *header, char ** s) {
	/* Allocates and fills a string with a verbose representation of
		 the header pased as argument.
		 Result: 0 on success, !=0 on error
	*/  
char * t;
netflow_v5_header_t *h = (netflow_v5_header_t *)header;
time_t	now;
	
	now = h->unix_secs;
	t = ctime(&now);
	t[strlen(t)-1] = 0; 

	snprintf(string,STRINGSIZE-1 ,""
"Header Netflow Version 5:\n"
"  count         =  %10u\n"
"  SysUptime     =  %10u\n"
"  unix_secs     =  %10d   [%s]\n"
"  unix_nsecs    =  %10d\n"
"  flow_sequence = %11u\n"
"  engine_type   =          %2d\n"
"  engine_id     =          %2d\n"
"  reserved      =          %2u\n",
		h->count,
		h->SysUptime,h->unix_secs,t,h->unix_nsecs,
		h->flow_sequence,h->engine_type,h->engine_id,h->reserved);
	*s = string;

} // End of netflow_v5_header_to_string


void netflow_v5_record_to_block(void *record, char ** s) {
struct in_addr a,d,n;
char as[16], ds[16], ns[16];
char * str;
netflow_v5_record_t *r = (netflow_v5_record_t *)record;

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


	snprintf(string, STRINGSIZE-1, "\n"
"Record Netflow Version 5: \n"
"  addr      = %15s\n"
"  dstaddr   = %15s\n"
"  nexthop   = %15s\n"
"  input     =           %5u\n"
"  output    =           %5u\n"
"  dPkts     =      %10u\n"
"  dOctets   =      %10u\n"
"  First     =      %10u\n"
"  Last      =      %10u\n"
"  port      =           %5u\n"
"  dstport   =           %5u\n"
"  pad1      =             %3u\n"
"  tcp_flags =             %3u\n"
"  prot      =             %3u\n"
"  tos       =             %3u\n"
"  src_as    =           %5u\n"
"  dst_as    =           %5u\n"
"  src_mask  =             %3u\n"
"  dst_mask  =             %3u\n"
"  pad2      =           %5u"
, 
		as, ds, ns,
		r->input, r->output, r->dPkts, r->dOctets, r->First, r->Last,
		r->srcport, r->dstport, r->pad1, r->tcp_flags, r->prot, r->tos,
		r->src_as, r->dst_as, r->src_mask, r->dst_mask, r->pad2 );

	string[STRINGSIZE-1] = 0;

	*s = string;

}

void netflow_v5_record_to_line(void *record, char ** s) {
uint32_t 	usize, duration;
double		fsize;
time_t tt;
struct in_addr a,d;
char as[16], ds[16];
char * str;
char * prot;
char prot_long[16], datestr1[64] , datestr2[64], scale;
struct tm * ts, * te;
netflow_v5_record_t *r = (netflow_v5_record_t *)record;


	usize = 0;
	fsize = 0;
	a.s_addr = htonl(r->srcaddr);
	d.s_addr = htonl(r->dstaddr);
	str = inet_ntoa(a);
	strncpy(as, inet_ntoa(a), 15);
	str = inet_ntoa(d);
	strncpy(ds, str, 15);
	as[15] = 0;
	ds[15] = 0;

	duration = r->Last - r->First;
	tt = r->First;
	ts = localtime(&tt);
	strftime(datestr1, 63, "%b %d %Y %T", ts);

	tt = r->Last;
	te = localtime(&tt);
	strftime(datestr2, 63, "%b %d %Y %T", te);

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
	case 103:
		prot = "PIM ";
		break;
	default:
		snprintf(prot_long,15,"%4d",r->prot);
		prot = prot_long;
	}

	if ( r->dOctets >= _1GB ) {
		fsize = (double)r->dOctets / _1GB;
		scale = 'G';
	} else if ( r->dOctets >= _1MB ) {
		fsize = (double)r->dOctets / _1MB;
		scale = 'M';
	} else if ( r->dOctets >= _1KB ) {
		fsize = (double)r->dOctets / _1KB;
		scale = 'K';
	} else  {
		usize = r->dOctets;
		scale = ' ';
	} 

	if ( scale == ' ' ) 
		snprintf(string, STRINGSIZE-1 ,"%s %5i %s %15s:%-5i -> %15s:%-5i %7u %5u %cB",
					datestr1, duration, prot, as, r->srcport, ds, r->dstport, r->dPkts, usize, scale);
	else 
		snprintf(string, STRINGSIZE-1 ,"%s %5i %s %15s:%-5i -> %15s:%-5i %7u %5.1f %cB",
					datestr1, duration, prot, as, r->srcport, ds, r->dstport, r->dPkts, fsize, scale);
	string[STRINGSIZE-1] = 0;

	*s = string;

} // End of netflow_v5_record_line


void netflow_v5_record_to_line_long(void *record, char ** s) {
uint32_t 	usize, duration;
double		fsize;
time_t tt;
struct in_addr a,d;
char as[16], ds[16], TCP_flags[7];
char * str;
char * prot;
char prot_long[16], datestr1[64] , datestr2[64], scale;
struct tm * ts, * te;
netflow_v5_record_t *r = (netflow_v5_record_t *)record;


	usize = 0;
	fsize = 0;
	a.s_addr = htonl(r->srcaddr);
	d.s_addr = htonl(r->dstaddr);
	str = inet_ntoa(a);
	strncpy(as, inet_ntoa(a), 15);
	str = inet_ntoa(d);
	strncpy(ds, str, 15);
	as[15] = 0;
	ds[15] = 0;

	duration = r->Last - r->First;
	tt = r->First;
	ts = localtime(&tt);
	strftime(datestr1, 63, "%b %d %Y %T", ts);

	tt = r->Last;
	te = localtime(&tt);
	strftime(datestr2, 63, "%b %d %Y %T", te);

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
	case 103:
		prot = "PIM ";
		break;
	default:
		snprintf(prot_long,15,"%4d",r->prot);
		prot = prot_long;
	}

	if ( r->dOctets >= _1GB ) {
		fsize = (double)r->dOctets / _1GB;
		scale = 'G';
	} else if ( r->dOctets >= _1MB ) {
		fsize = (double)r->dOctets / _1MB;
		scale = 'M';
	} else if ( r->dOctets >= _1KB ) {
		fsize = (double)r->dOctets / _1KB;
		scale = 'K';
	} else  {
		usize = r->dOctets;
		scale = ' ';
	} 

	TCP_flags[0] = r->tcp_flags & 32 ? 'U' : '.';
	TCP_flags[1] = r->tcp_flags & 16 ? 'A' : '.';
	TCP_flags[2] = r->tcp_flags &  8 ? 'P' : '.';
	TCP_flags[3] = r->tcp_flags &  4 ? 'R' : '.';
	TCP_flags[4] = r->tcp_flags &  2 ? 'S' : '.';
	TCP_flags[5] = r->tcp_flags &  1 ? 'F' : '.';
	TCP_flags[6] = '\0';

	if ( scale == ' ' ) 
		snprintf(string, STRINGSIZE-1 ,"%s %5i %s %15s:%-5i -> %15s:%-5i %s %3i %7u %5u %cB",
					datestr1, duration, prot, as, r->srcport, ds, r->dstport, TCP_flags, r->tos, r->dPkts, usize, scale);
	else 
		snprintf(string, STRINGSIZE-1 ,"%s %5i %s %15s:%-5i -> %15s:%-5i %s %3i %7u %5.1f %cB",
					datestr1, duration, prot, as, r->srcport, ds, r->dstport, TCP_flags, r->tos, r->dPkts, fsize, scale);
	string[STRINGSIZE-1] = 0;

	*s = string;

} // End of netflow_v5_record_line_long

void netflow_v5_record_to_pipe(void *record, char ** s) {
uint32_t 	duration;
netflow_v5_record_t *r = (netflow_v5_record_t *)record;

	duration = r->Last - r->First;

	snprintf(string, STRINGSIZE-1 ,"%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u",
				r->First, r->Last, r->prot, r->srcaddr, r->srcport, r->dstaddr, r->dstport, 
				r->tcp_flags, r->tos, r->dPkts, r->dOctets);

	string[STRINGSIZE-1] = 0;

	*s = string;

} // End of netflow_v5_record_pipe

