/*  This file is part of the nfdump project.
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
 *  $Id: nfstat.c 2 2004-09-20 18:12:36Z peter $
 *
 *  $LastChangedRevision: 2 $
 *	
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "netflow_v5.h"
#include "netflow_v7.h"
#include "nf_common.h"
#include "util.h"
#include "nfstat.h"

extern uint32_t	byte_limit, packet_limit;
extern int byte_mode, packet_mode;
enum { NONE, LESS, MORE };


#define MaxMemBlocks	256

/* function prototypes */
static FlowTableRecord_t *hash_lookup_FlowTable(uint32_t *index_cache, 
				uint32_t addr, uint32_t dstaddr, uint16_t port, uint16_t dstport);

static FlowTableRecord_t *hash_insert_FlowTable(uint32_t index_cache,
				uint32_t addr, uint32_t dstaddr, uint16_t port, uint16_t dstport);

static IPDataRecord_t *hash_lookup_ip(uint32_t addr);

static IPDataRecord_t *hash_insert_ip(uint32_t addr);

static void Expand_FlowTable_Blocks(void);

static void Expand_IPTable_Blocks(void);

static void PrintLine_aggrigated(FlowTableRecord_t *StatData);

static void PrintLine_ip(IPDataRecord_t *StatData);

static void Make_TopN_aggrigated(SortElement_t **topN_pkg, SortElement_t **topN_bytes, int topN, uint32_t *count );

// static SortElement_t *Make_TopN_packets(int topN, uint32_t *count);

// static SortElement_t *Make_TopN_bytes(int topN, uint32_t *count);

static SortElement_t *StatTopN_ip(int topN, uint32_t *count );

static void heapSort(SortElement_t *topN_ip, uint32_t array_size, int topN);

static void siftDown(SortElement_t *topN_ip, uint32_t root, uint32_t bottom);

/* locals */
static hash_FlowTable FlowTable;
static hash_IPTable IPTable;

static const double _1KB = 1024.0;
static const double _1MB = 1024.0 * 1024.0;
static const double _1GB = 1024.0 * 1024.0 * 1024.0;

#define mix(a,b,c) { \
	    a -= b; a -= c; a ^= (c>>13); \
	    b -= c; b -= a; b ^= (a<<8); \
	    c -= a; c -= b; c ^= (b>>13); \
	    a -= b; a -= c; a ^= (c>>12);  \
	    b -= c; b -= a; b ^= (a<<16); \
	    c -= a; c -= b; c ^= (b>>5); \
	    a -= b; a -= c; a ^= (c>>3);  \
	    b -= c; b -= a; b ^= (a<<10); \
	    c -= a; c -= b; c ^= (b>>15); \
}

/* Functions */
int Init_FlowTable(uint16_t NumBits, uint32_t Prealloc) {
uint32_t maxindex;

	if ( NumBits == 0 || NumBits > 31 ) {
		fprintf(stderr, "Numbits outside 1..31\n");
		exit(255);
	}
	maxindex = (1 << NumBits);
	FlowTable.IndexMask   = maxindex -1;
	FlowTable.NumBits     = NumBits;
	FlowTable.Prealloc    = Prealloc;
	FlowTable.bucket	  = (FlowTableRecord_t **)calloc(maxindex, sizeof(FlowTableRecord_t *));
	FlowTable.bucketcache = (FlowTableRecord_t **)calloc(maxindex, sizeof(FlowTableRecord_t *));
	if ( !FlowTable.bucket ) {
		perror("Can't allocate memory");
		return 0;
	}
	FlowTable.memblocks = (FlowTableRecord_t **)calloc(MaxMemBlocks, sizeof(FlowTableRecord_t *));
	if ( !FlowTable.memblocks ) {
		perror("Can't allocate memory");
		return 0;
	}
	FlowTable.memblocks[0] = (FlowTableRecord_t *)calloc(Prealloc, sizeof(FlowTableRecord_t));

	FlowTable.NumBlocks = 1;
	FlowTable.MaxBlocks = MaxMemBlocks;
	FlowTable.NextBlock = 0;
	FlowTable.NextElem  = 0;
	
	return 1;

} // End of Init_FlowTable

int Init_IPTable(uint16_t NumBits, uint32_t Prealloc) {
uint32_t maxindex;

	if ( NumBits == 0 || NumBits > 31 ) {
		fprintf(stderr, "Numbits outside 1..31n");
		exit(255);
	}
	maxindex = (1 << NumBits);
	IPTable.IndexMask   = maxindex -1;
	IPTable.NumBits     = NumBits;
	IPTable.Prealloc    = Prealloc;
	IPTable.bucket	    = (IPDataRecord_t **)calloc(maxindex, sizeof(IPDataRecord_t *));
	IPTable.bucketcache = (IPDataRecord_t **)calloc(maxindex, sizeof(IPDataRecord_t *));
	if ( !IPTable.bucket || !IPTable.bucketcache ) {
		perror("Init_IPTable memory error");
		return 0;
	}
	IPTable.memblocks = (IPDataRecord_t **)calloc(MaxMemBlocks, sizeof(IPDataRecord_t *));
	if ( !IPTable.memblocks ) {
		perror("Init_IPTable Memory error");
		return 0;
	}
	IPTable.memblocks[0] = (IPDataRecord_t *)calloc(Prealloc, sizeof(IPDataRecord_t));
	if ( !IPTable.memblocks[0] ) {
		perror("Init_IPTable Memory error");
		return 0;
	}

	IPTable.NumBlocks = 1;
	IPTable.MaxBlocks = MaxMemBlocks;
	IPTable.NextBlock = 0;
	IPTable.NextElem  = 0;
	
	return 1;

} // End of Init_IPTable

void Dispose_Tables(int flow_stat, int ip_stat) {
unsigned int i;

	if ( flow_stat ) {
		free((void *)FlowTable.bucket);
		free((void *)FlowTable.bucketcache);
		for ( i=0; i<FlowTable.NumBlocks; i++ ) 
			free((void *)FlowTable.memblocks[i]);
		free((void *)FlowTable.memblocks);
	}

	if ( ip_stat ) {
		free((void *)IPTable.bucket);
		for ( i=0; i<IPTable.NumBlocks; i++ ) 
			free((void *)IPTable.memblocks[i]);
		free((void *)IPTable.memblocks);
	}

} // End of Dispose_Tables

inline FlowTableRecord_t *hash_lookup_FlowTable(uint32_t *index_cache,
				uint32_t addr, uint32_t dstaddr, uint16_t port, uint16_t dstport ) {
uint32_t			index, a1, a2;
FlowTableRecord_t	*record;

	index = port ^ dstport;
	a1 = addr; a2 = dstaddr;
	mix(a1, a2, index);

	index = (index ^ ( index >> ( 32 - FlowTable.NumBits ))) & FlowTable.IndexMask;
	*index_cache = index;

	if ( FlowTable.bucket[index] == NULL )
		return NULL;

	record = FlowTable.bucket[index];
	while ( record ) {
		if ( ( record->ip1   == addr && record->ip2   == dstaddr &&
			   record->port1 == port && record->port2 == dstport ) )
			return record;
		record = record->next;
	}
	return NULL;

} // End of hash_lookup_FlowTable

inline IPDataRecord_t *hash_lookup_ip(uint32_t addr) {
uint32_t		index;
IPDataRecord_t	*record;

	index = addr & IPTable.IndexMask;
	if ( IPTable.bucket[index] == NULL )
		return NULL;

	record = IPTable.bucket[index];
	while ( record && ( record->ip1 != addr ) ) {
		record = record->next;
	}
	return record;

} // End of hash_lookup_ip

static void Expand_FlowTable_Blocks(void) {

	if ( FlowTable.NumBlocks >= FlowTable.MaxBlocks ) {
		FlowTable.MaxBlocks += MaxMemBlocks;
		FlowTable.memblocks = (FlowTableRecord_t **)realloc(FlowTable.memblocks,
						FlowTable.MaxBlocks * sizeof(FlowTableRecord_t *));
		if ( !FlowTable.memblocks ) {
			perror("Expand_FlowTable_Blocks Memory error");
			exit(250);
		}
	}
	FlowTable.memblocks[FlowTable.NumBlocks] = 
			(FlowTableRecord_t *)calloc(FlowTable.Prealloc, sizeof(FlowTableRecord_t));

	if ( !FlowTable.memblocks[FlowTable.NumBlocks] ) {
		perror("Expand_FlowTable_Blocks Memory error");
		exit(250);
	}
	FlowTable.NextBlock = FlowTable.NumBlocks++;
	FlowTable.NextElem  = 0;

} // End of Expand_FlowTable_Blocks

static void Expand_IPTable_Blocks(void) {

	if ( IPTable.NumBlocks >= IPTable.MaxBlocks ) {
		IPTable.MaxBlocks += MaxMemBlocks;
		IPTable.memblocks = (IPDataRecord_t **)realloc(IPTable.memblocks,
						IPTable.MaxBlocks * sizeof(IPDataRecord_t *));
		if ( !IPTable.memblocks ) {
			perror("Expand_IPTable_Blocks Memory error");
			exit(250);
		}
	}
	IPTable.memblocks[IPTable.NumBlocks] = 
			(IPDataRecord_t *)calloc(IPTable.Prealloc, sizeof(IPDataRecord_t));

	if ( !IPTable.memblocks[IPTable.NumBlocks] ) {
		perror("Expand_IPTable_Blocks Memory error");
		exit(250);
	}
	IPTable.NextBlock = IPTable.NumBlocks++;
	IPTable.NextElem  = 0;

} // End of Expand_IPTable_Blocks

inline static FlowTableRecord_t *hash_insert_FlowTable(uint32_t index_cache,
				uint32_t addr, uint32_t dstaddr, uint16_t port, uint16_t dstport) {
FlowTableRecord_t	*record;

	if ( FlowTable.NextElem >= FlowTable.Prealloc )
		Expand_FlowTable_Blocks();

	record = &(FlowTable.memblocks[FlowTable.NextBlock][FlowTable.NextElem]);
	FlowTable.NextElem++;
	record->next  = NULL;
	record->ip1   = addr;
	record->ip2   = dstaddr;
	record->port1 = port;
	record->port2 = dstport;

	if ( FlowTable.bucket[index_cache] == NULL ) 
		FlowTable.bucket[index_cache] = record;
	else 
		FlowTable.bucketcache[index_cache]->next = record;
	FlowTable.bucketcache[index_cache] = record;

	return record;

} // End of hash_insert_FlowTable

void list_insert(nf_record_t *nf_record) {
FlowTableRecord_t	*record;

	if ( FlowTable.NextElem >= FlowTable.Prealloc )
		Expand_FlowTable_Blocks();

	record = &(FlowTable.memblocks[FlowTable.NextBlock][FlowTable.NextElem]);
	FlowTable.NextElem++;

	record->next  		= NULL;
	record->ip1   		= nf_record->srcaddr;
	record->ip2   		= nf_record->dstaddr;
	record->port1 		= nf_record->srcport;
	record->port2 		= nf_record->dstport;
	record->bytes	   	= nf_record->dOctets;
	record->pkts	   	= nf_record->dPkts;
	record->first	   	= nf_record->First;
	record->last	   	= nf_record->Last;
	record->proto	   	= nf_record->prot;
	record->numflows 	= 1;

} // End of list_insert


inline static IPDataRecord_t *hash_insert_ip(uint32_t addr) {
uint32_t		index;
IPDataRecord_t	*record;

	if ( IPTable.NextElem >= IPTable.Prealloc )
		Expand_IPTable_Blocks();

	record = &(IPTable.memblocks[IPTable.NextBlock][IPTable.NextElem]);
	IPTable.NextElem++;
	record->next  = NULL;
	record->ip1   = addr;

	index = addr & IPTable.IndexMask;
	if ( IPTable.bucket[index] == NULL ) 
		IPTable.bucket[index] = record;
	else
		IPTable.bucketcache[index]->next = record;
	IPTable.bucketcache[index] = record;
	
	return record;

} // End of hash_insert_ip

int AddStat(nf_header_t *nf_header, nf_record_t *nf_record, 
				int flow_stat, int src_ip_stat, int dst_ip_stat) {
FlowTableRecord_t	*IPTable_record;
IPDataRecord_t		*ip_record;
time_t				start_time, end_time;
uint32_t			index_cache;

	start_time = nf_record->First;
	end_time   = nf_record->Last;
	
	if ( flow_stat ) {
		// Update netflow statistics
		IPTable_record = hash_lookup_FlowTable(&index_cache, 
						nf_record->srcaddr, nf_record->dstaddr, nf_record->srcport, nf_record->dstport);
		if ( IPTable_record ) {
			IPTable_record->bytes += nf_record->dOctets;
			IPTable_record->pkts  += nf_record->dPkts;
			if ( start_time < IPTable_record->first ) 
				IPTable_record->first = start_time;
			if ( end_time > IPTable_record->last ) 
				IPTable_record->last = end_time;
			IPTable_record->numflows++;
	
		} else {
			IPTable_record = hash_insert_FlowTable(index_cache, 
							nf_record->srcaddr, nf_record->dstaddr, nf_record->srcport, nf_record->dstport);
			if ( !IPTable_record )
				return -1;
	
			IPTable_record->bytes	 = nf_record->dOctets;
			IPTable_record->pkts	 = nf_record->dPkts;
			IPTable_record->first	 = start_time;
			IPTable_record->last	 = end_time;
			IPTable_record->proto	 = nf_record->prot;
			IPTable_record->numflows = 1;
		}
	}

	// Update IP statistics
	if ( src_ip_stat ) {
		// SRC IP addr
		ip_record = hash_lookup_ip(nf_record->srcaddr);
		if ( ip_record ) {
			ip_record->bytes += nf_record->dOctets;
			ip_record->pkts  += nf_record->dPkts;
			if ( start_time < ip_record->first ) 
				ip_record->first = start_time;
			if ( end_time > ip_record->last ) 
				ip_record->last = end_time;
			ip_record->numflows++;
	
		} else {
			ip_record = hash_insert_ip(nf_record->srcaddr);
			if ( !ip_record )
				return -1;
	
			ip_record->bytes    = nf_record->dOctets;
			ip_record->pkts	    = nf_record->dPkts;
			ip_record->first    = start_time;
			ip_record->last	    = end_time;
			ip_record->proto	= nf_record->prot;
			ip_record->numflows = 1;
		}
	}

	if ( dst_ip_stat ) {
		// DST IP addr
		ip_record = hash_lookup_ip(nf_record->dstaddr);
		if ( ip_record ) {
			ip_record->bytes += nf_record->dOctets;
			ip_record->pkts  += nf_record->dPkts;
			if ( start_time < ip_record->first ) 
				ip_record->first = start_time;
			if ( end_time > ip_record->last ) 
				ip_record->last = end_time;
			ip_record->numflows++;
	
		} else {
			ip_record = hash_insert_ip(nf_record->dstaddr);
			if ( !ip_record )
				return -1;
	
			ip_record->bytes    = nf_record->dOctets;
			ip_record->pkts	    = nf_record->dPkts;
			ip_record->first    = start_time;
			ip_record->last	    = end_time;
			ip_record->proto	= nf_record->prot;
			ip_record->numflows = 1;
		}
	}

	return 0;

} // End of AddStat

static void PrintLine_aggrigated(FlowTableRecord_t *StatData) {
u_char		*ip1, *ip2; 
char		ipstr1[32], ipstr2[32], protostr[8], datestr[64];
double		fsize;
uint32_t	duration, usize;
char		scale, *ProtoStr;
struct tm	*tbuff;

	ip1 = (u_char *)&StatData->ip1;
	ip2 = (u_char *)&StatData->ip2;
	// For other protocol nubers see http://www.iana.org/assignments/protocol-numbers
	switch ( StatData->proto ) {
		case 1:
			ProtoStr = "ICMP  ";	// ICMP v4
			break;
		case 6:
			ProtoStr = "TCP   ";	// TCP
			break;
		case 17:
			ProtoStr = "UDP   ";	// UDP
			break;
		case 41:
			ProtoStr = "IPv6  ";	// Ipv6
			break;
		case 46:
			ProtoStr = "RSVP  ";	// Reservation Protocol
			break;
		case 47:
			ProtoStr = "GRE   ";	// General Routing Encapsulation
			break;
		case 50:
			ProtoStr = "ESP   ";	// Encap Security Payload
			break;
		case 51:
			ProtoStr = "AH    ";	// Authentication Header 
			break;
		case 58:
			ProtoStr = "ICMPv6";	// ICMP for IPv6 
			break;
		case 94:
			ProtoStr = "IPIP  ";	// IP-within-IP Encapsulation Protocol
			break;
		case 103:
			ProtoStr = "PIM   ";	// Protocol Independent Multicast
			break;

		default:
			snprintf(protostr,7,"%4d", StatData->proto);
			ProtoStr = protostr;
	}

	fsize = 0; usize = 0;
	if ( StatData->bytes >= _1GB ) {
		fsize = (double)StatData->bytes / _1GB;
		scale = 'G';
	} else if ( StatData->bytes >= _1MB ) {
		fsize = (double)StatData->bytes / _1MB;
		scale = 'M';
	} else if ( StatData->bytes >= _1KB ) {
		fsize = (double)StatData->bytes / _1KB;
		scale = 'K';
	} else  {
		usize = StatData->bytes;
		scale = ' ';
	} 
	duration = StatData->last - StatData->first;

#ifdef WORDS_BIGENDIAN
	snprintf(ipstr1, 31, "%d.%d.%d.%d",  ip1[0] & 0xFF, ip1[1] & 0xFF, ip1[2] & 0xFF, ip1[3] & 0xFF );
	snprintf(ipstr2, 31, "%d.%d.%d.%d",  ip2[0] & 0xFF, ip2[1] & 0xFF, ip2[2] & 0xFF, ip2[3] & 0xFF );
#else
	snprintf(ipstr1, 31, "%d.%d.%d.%d",  ip1[3] & 0xFF, ip1[2] & 0xFF, ip1[1] & 0xFF, ip1[0] & 0xFF );
	snprintf(ipstr2, 31, "%d.%d.%d.%d",  ip2[3] & 0xFF, ip2[2] & 0xFF, ip2[1] & 0xFF, ip2[0] & 0xFF );
#endif
	tbuff = localtime(&StatData->first);
	if ( !tbuff ) {
		perror("Error time convert");
		exit(250);
	}
	strftime(datestr, 63, "%b %d %Y %T", tbuff);

	// Date			Time	  Dur Proto  Souce IP				 Dest IP		   Packets  BytesA  NumFlows
	// Dec 11 2003 16:00:13	 1 TCP	131.152.95.93:61959 ->   193.230.228.3:80		4   651B   2
	if ( scale == ' ' ) 
		printf("%s %8i %s %15s:%-5i -> %15s:%-5i %8llu %6u %cB %3llu\n", datestr, duration, ProtoStr,  
						ipstr1, StatData->port1, 
						ipstr2, StatData->port2, 
						StatData->pkts, usize, scale, StatData->numflows );
	else 
		printf("%s %8i %s %15s:%-5i -> %15s:%-5i %8llu %6.1f %cB %3llu\n", datestr, duration, ProtoStr, 
						ipstr1, StatData->port1, 
						ipstr2, StatData->port2, 
						StatData->pkts, fsize, scale, StatData->numflows );

} // End of PrintLine_aggrigated

static void PrintLine_ip(IPDataRecord_t *StatData) {
u_char		*ip1; 
char		ipstr1[32], datestr[64];
double		fsize;
uint32_t	duration, usize;
char		scale;
struct tm	*tbuff;

	fsize = 0;
	usize = 0;
	ip1 = (u_char *)&StatData->ip1;

	if ( StatData->bytes >= _1GB ) {
		fsize = (double)StatData->bytes / _1GB;
		scale = 'G';
	} else if ( StatData->bytes >= _1MB ) {
		fsize = (double)StatData->bytes / _1MB;
		scale = 'M';
	} else if ( StatData->bytes >= _1KB ) {
		fsize = (double)StatData->bytes / _1KB;
		scale = 'K';
	} else  {
		usize = StatData->bytes;
		scale = ' ';
	} 
	duration = StatData->last - StatData->first;
	snprintf(ipstr1, 31, "%d.%d.%d.%d",  ip1[3] & 0xFF, ip1[2] & 0xFF, ip1[1] & 0xFF, ip1[0] & 0xFF );
	tbuff = localtime(&StatData->first);
	if ( !tbuff ) {
		perror("Error time convert");
		exit(250);
	}
	strftime(datestr, 63, "%b %d %Y %T", tbuff);

	// Date			Time	  Dur Proto  Souce IP				 Dest IP		   Packets  BytesA  NumFlows
	// Dec 11 2003 16:00:13	 1 TCP	131.152.95.93:61959 ->   193.230.228.3:80		4   651B   2
	if ( scale == ' ' ) 
		printf("%s %8i %15s %8llu %6u %cB %7llu\n", datestr, duration, 
						ipstr1, StatData->pkts, usize, scale, StatData->numflows );
	else
		printf("%s %8i %15s %8llu %6.1f %cB %7llu\n", datestr, duration, 
						ipstr1, StatData->pkts, fsize, scale, StatData->numflows );

} // End of PrintLine_ip

void ReportAggregated(uint32_t limitflows, int date_sorted) {
FlowTableRecord_t	*r;
SortElement_t 		*SortList;
uint32_t 			i, j, tmp;
uint32_t			maxindex, c;

	maxindex = ( FlowTable.NextBlock * FlowTable.Prealloc ) + FlowTable.NextElem;
	if ( date_sorted ) {
		// Sort according the date
		SortList = (SortElement_t *)calloc(maxindex+1, sizeof(SortElement_t));

		if ( !SortList ) {
			perror("Can't allocate Top N lists: \n");
			return;
		}

		// preset SortList table - still unsorted
		c = 0;
		for ( i=0; i <= FlowTable.IndexMask; i++ ) {
			r = FlowTable.bucket[i];
			// foreach elem in this bucket
			while ( r ) {

				// we want to sort only those flows which pass the packet or byte limits
				if ( byte_limit ) {
					if (( byte_mode == LESS && r->bytes > byte_limit ) ||
						( byte_mode == MORE && r->pkts  < byte_limit ) ) {
						r = r->next;
						continue;
					}
				}
				if ( packet_limit ) {
					if (( packet_mode == LESS && r->bytes > packet_limit ) ||
						( packet_mode == MORE && r->pkts  < packet_limit ) ) {
						r = r->next;
						continue;
					}
				}

				SortList[c].count  = r->first;	// sort according the date
				SortList[c].record = (void *)r;
				r = r->next;
				c++;
			}
		}

		SortList[maxindex].count = 0;
		heapSort(SortList, maxindex, 0);

		if ( limitflows && limitflows < maxindex )
			maxindex = limitflows;
		for ( i = 0; i < maxindex; i++ ) {
			PrintLine_aggrigated(SortList[i].record);
		}

	} else {
		// print them as they came
		c = 0;
		for ( i=0; i < FlowTable.NumBlocks; i++ ) {
			tmp = i * FlowTable.Prealloc;
			for ( j=0; j < FlowTable.Prealloc; j++ ) {
				r = &(FlowTable.memblocks[i][j]);
				if ( (tmp + j) < maxindex ) {
					if ( limitflows && c >= limitflows )
						return;

					// we want to print only those flows which pass the packet or byte limits
					if ( byte_limit ) {
						if (( byte_mode == LESS && r->bytes > byte_limit ) ||
							( byte_mode == MORE && r->pkts  < byte_limit ) ) {
							continue;
						}
					}
					if ( packet_limit ) {
						if (( packet_mode == LESS && r->bytes > packet_limit ) ||
							( packet_mode == MORE && r->pkts  < packet_limit ) ) {
							continue;
						}
					}

					PrintLine_aggrigated(r);
					c++;
				}
			}
		}
	}

} // End of ReportAggregated

void ReportStat(int topN, int flow_stat, int ip_stat){
SortElement_t 	*topN_pkg;
SortElement_t 	*topN_bytes;
SortElement_t	*topN_list;
uint32_t		numflows;
int 			i, j;

	if ( flow_stat ) {
		Make_TopN_aggrigated(&topN_pkg, &topN_bytes, topN, &numflows);
		printf("Aggrigated flows %u\n", numflows);
		printf("Time window: %s\n", TimeString());
		if ( !topN_pkg || !topN_bytes ) 
			return;
	
		printf("Top %i flows packet count:\n", topN);
		//      Feb 04 2004 10:45:30      903 TCP    81.208.60.206:33187 ->  129.132.211.34:22670   152176      195 MB     1
		printf("Date first seen      Duration Proto Src IP Address:Port      Dst IP Address:Port   Packets     Bytes Flows\n");

		for ( i=topN-1; i>=0; i--) {
			if ( !topN_pkg[i].count )
				break;
			PrintLine_aggrigated(topN_pkg[i].record);
		}

		printf("\nTop %i flows byte count:\n", topN);
		printf("Date first seen      Duration Proto Src IP Address:Port      Dst IP Address:Port   Packets     Bytes Flows\n");

		for ( i=topN-1; i>=0; i--) {
			if ( !topN_bytes[i].count )
				break;
			PrintLine_aggrigated(topN_bytes[i].record);
		}
		printf("\n");
	}

	if ( ip_stat ) {
		topN_list = StatTopN_ip(topN, &numflows);
		printf("Number of IP addr %u\n", numflows);
		printf("Time window: %s\n", TimeString());
		switch(ip_stat) {
			case(1):
				printf("Top %i IP SRC addresse counts:\n", topN);
				break;
			case(2):
				printf("Top %i IP DST addresse counts:\n", topN);
				break;
			case(3):
				printf("Top %i IP SRC/DST addresse counts:\n", topN);
				break;
		}
		//      Feb 04 2004 10:54:23      631    129.132.2.21   103090        7 MB 92604
		printf("Date first seen      Duration IP address       Packets     Bytes Flows\n");

		j = numflows - topN;
		j = j < 0 ? 0 : j;
		if ( topN == 0 )
			j = 0;

		for ( i=numflows-1; i>=j ; i--) {
			if ( !topN_list[i].count )
				break;

			PrintLine_ip((IPDataRecord_t *)topN_list[i].record);
		}
		free((void *)topN_list);
	}

} // End of ReportStat

/*
 * Generate the top N lists for packets and bytes in one run
 */
void Make_TopN_aggrigated(SortElement_t **topN_pkg, SortElement_t **topN_bytes, int topN, uint32_t *count) {
FlowTableRecord_t	*r, *r1, *r2;
unsigned int		i;
int					j;
uint64_t	   		c1, c2, c;

	*topN_pkg   = (SortElement_t *)calloc(topN, sizeof(SortElement_t));
	*topN_bytes = (SortElement_t *)calloc(topN, sizeof(SortElement_t));
	if ( !*topN_pkg || !*topN_bytes ) {
		perror("Can't allocate Top N lists: \n");
		*topN_pkg = *topN_bytes = NULL;
		return ;
	}

	c = 0;
	// Iterate through all buckets
	for ( i=0; i <= FlowTable.IndexMask; i++ ) {
		r = FlowTable.bucket[i];
		// foreach elem in this bucket
		while ( r ) {

			// we want to sort only those flows which pass the packet or byte limits
			if ( byte_limit ) {
				if (( byte_mode == LESS && r->bytes > byte_limit ) ||
					( byte_mode == MORE && r->pkts  < byte_limit ) ) {
					r = r->next;
					continue;
				}
			}
			if ( packet_limit ) {
				if (( packet_mode == LESS && r->bytes > packet_limit ) ||
					( packet_mode == MORE && r->pkts  < packet_limit ) ) {
					r = r->next;
					continue;
				}
			}

			c++;
			/* packet top N list */
			if ( r->pkts > (*topN_pkg)[0].count ) {
				/* element value is bigger than smallest value in topN */
				c1 = r->pkts;
				r1 = r;
				for (j=topN-1; j>=0; j-- ) {
					if ( c1 > (*topN_pkg)[j].count ) {
						c2 = (*topN_pkg)[j].count;
						r2 = (*topN_pkg)[j].record;
						(*topN_pkg)[j].count 	= c1;
						(*topN_pkg)[j].record	= r1;
						c1 = c2; r1 = r2;
					}
				}
			} // if pkts

			/* byte top N list */
			if ( r->bytes > (*topN_bytes)[0].count ) {
				/* element value is bigger than smallest value in topN */
				c1 = r->bytes;
				r1 = r;
				for (j=topN-1; j>=0; j-- ) {
					if ( c1 > (*topN_bytes)[j].count ) {
						c2 = (*topN_bytes)[j].count;
						r2 = (*topN_bytes)[j].record;
						(*topN_bytes)[j].count 	= c1;
						(*topN_bytes)[j].record = r1;
						c1 = c2; r1 = r2;
					}
				}
			} // if bytes

			// next elem in bucket
			r = r->next;
		} // foreach element
	}
	*count = c;

} // End of Make_TopN_aggrigated

void PrintSortedFlows(void) {
FlowTableRecord_t	*r;
SortElement_t 		*SortList;
nf_record_t			nf_record;
unsigned int		i, j, tmp;
uint32_t			maxindex, c;
char				*string;

	maxindex = ( FlowTable.NextBlock * FlowTable.Prealloc ) + FlowTable.NextElem;
	SortList = (SortElement_t *)calloc(maxindex+1, sizeof(SortElement_t));

	if ( !SortList ) {
		perror("Can't allocate Top N lists: \n");
		return;
	}

	// preset SortList table - still unsorted
	c = 0;
	for ( i=0; i < FlowTable.NumBlocks; i++ ) {
		tmp = i * FlowTable.Prealloc;
		for ( j=0; j < FlowTable.Prealloc; j++ ) {
			r = &(FlowTable.memblocks[i][j]);
			if ( (tmp + j) < maxindex ) {
				SortList[c].count  = r->first;	// sort according the date
				SortList[c].record = (void *)r;
				c++;
			}
		}
	}

	SortList[maxindex].count = 0;
	heapSort(SortList, maxindex, 0);

	for ( i=0; i<maxindex; i++ ) {
		r = SortList[i].record;

		nf_record.srcaddr = r->ip1;
		nf_record.dstaddr = r->ip2;
		nf_record.srcport = r->port1;
		nf_record.dstport = r->port2;
		nf_record.dOctets = r->bytes;
		nf_record.dPkts   = r->pkts;
		nf_record.First   = r->first;
		nf_record.Last    = r->last;
		nf_record.prot    = r->proto;

		netflow_v5_record_to_line((void *)&nf_record, &string);

		if ( string )
			printf("%s", string);
	}
	
	free(SortList);

} // End of PrintSortedFlows

/* 
 * Some different implementation of statistics
 *
static SortElement_t *Make_TopN_packets(int topN, uint32_t *count) {
FlowTableRecord_t	*r;
SortElement_t 		*topN_SortList;
unsigned int		i;
uint32_t			maxindex, c;

	maxindex = ( FlowTable.NextBlock * FlowTable.Prealloc ) + FlowTable.NextElem;
	topN_SortList = (SortElement_t *)calloc(maxindex+1, sizeof(SortElement_t));

	if ( !topN_SortList ) {
		perror("Can't allocate Top N lists: \n");
		return NULL;
	}

	// preset topN_SortList table - still unsorted
	c = 0;
	// Iterate through all buckets
	for ( i=0; i <= FlowTable.IndexMask; i++ ) {
		r = FlowTable.bucket[i];
		// foreach elem in this bucket
		while ( r ) {
			// next elem in bucket
			topN_SortList[c].count  = r->pkts;
			topN_SortList[c].record = (void *)r;
			r = r->next;
			c++;
		}
	}
	*count = c;

	topN_SortList[maxindex].count = 0;
	heapSort(topN_SortList, maxindex, topN);
	return topN_SortList;

} // End of Make_TopN_packets

static SortElement_t *Make_TopN_bytes(int topN, uint32_t *count) {
SortElement_t 		*topN_bytes_list;
FlowTableRecord_t	*r;
unsigned int		i;
uint32_t			maxindex, c;

	maxindex = ( FlowTable.NextBlock * FlowTable.Prealloc ) + FlowTable.NextElem;
	topN_bytes_list = (SortElement_t *)calloc(maxindex+1, sizeof(SortElement_t));

	if ( !topN_bytes_list ) {
		perror("Can't allocate Top N lists: \n");
		return NULL;
	}

	// preset topN_SortList table - still unsorted
	c = 0;
	// Iterate through all buckets
	for ( i=0; i <= FlowTable.IndexMask; i++ ) {
		r = FlowTable.bucket[i];
		// foreach elem in this bucket
		while ( r ) {
			// next elem in bucket
			topN_bytes_list[c].count  = r->pkts;
			topN_bytes_list[c].record = (void *)r;
			r = r->next;
			c++;
		}
	}
	*count = c;

	topN_bytes_list[maxindex].count = 0;
	heapSort(topN_bytes_list, maxindex, topN);
	return topN_bytes_list;

} // End of Make_TopN_bytes

*/

static SortElement_t *StatTopN_ip(int topN, uint32_t *count ) {
SortElement_t 		*topN_ip_list;
IPDataRecord_t		*r;
unsigned int		i;
uint32_t	   		c, maxindex;

	maxindex = ( IPTable.NextBlock * IPTable.Prealloc ) + IPTable.NextElem;
	topN_ip_list   = (SortElement_t *)calloc(maxindex+1, sizeof(SortElement_t));

	if ( !topN_ip_list ) {
		perror("Can't allocate Top N lists: \n");
		return NULL;
	}

	// preset topN_ip_list table - still unsorted
	c = 0;
	// Iterate through all buckets
	for ( i=0; i <= IPTable.IndexMask; i++ ) {
		r = IPTable.bucket[i];
		// foreach elem in this bucket
		while ( r ) {
			// next elem in bucket

			// we want to sort only those flows which pass the packet or byte limits
			if ( byte_limit ) {
				if (( byte_mode == LESS && r->bytes > byte_limit ) ||
					( byte_mode == MORE && r->pkts  < byte_limit ) ) {
					r = r->next;
					continue;
				}
			}
			if ( packet_limit ) {
				if (( packet_mode == LESS && r->bytes > packet_limit ) ||
					( packet_mode == MORE && r->pkts  < packet_limit ) ) {
					r = r->next;
					continue;
				}
			}

			topN_ip_list[c].count  = r->numflows;
			topN_ip_list[c].record = (void *)r;
			r = r->next;
			c++;
		} // foreach element
	}
	*count = c;
	// printf ("Sort %u flows\n", c);
	
	topN_ip_list[maxindex].count = 0;
	heapSort(topN_ip_list, maxindex, topN);

/*
	for ( i = 0; i < maxindex; i++ ) 
		printf("%i, %llu\n", i, topN_ip_list[i].count);
*/
	return topN_ip_list;
	
} // End of StatTopN_ip


static void heapSort(SortElement_t *SortElement, uint32_t array_size, int topN) {
int32_t		i;
uint32_t	top_count;
SortElement_t temp;

	for (i = (array_size >> 1)-1; i >= 0; i--)
		siftDown(SortElement, i, array_size);

	top_count = 1;
	for (i = array_size-1; i >= 1; i--) {
		temp = SortElement[0];
		SortElement[0] = SortElement[i];
		SortElement[i] = temp;
		siftDown(SortElement, 0, i-1);
		/* 
		 * if we need to know only the first top N skip
		 * the sorting of the rest. For topN == 0 -> all gets sorted
		 * as top_count is never 0
		 */
		if ( top_count == topN ) {
			return;
		}
	}

} // End of heapSort

static void siftDown(SortElement_t *SortElement, uint32_t root, uint32_t bottom) {
uint32_t	maxChild;
SortElement_t temp;
int done;

	done = 0;
	while (((root << 1) <= bottom) && (!done)) {
		if ((root << 1) == bottom)
			maxChild = root << 1;
		else if (SortElement[root << 1].count > SortElement[(root << 1) + 1].count)
			maxChild = root << 1;
		else
			maxChild = (root << 1) + 1;

		if (SortElement[root].count < SortElement[maxChild].count) {
			temp = SortElement[root];
			SortElement[root] = SortElement[maxChild];
			SortElement[maxChild] = temp;
			root = maxChild;
		} else
			done = 1;
	}
} // End of siftDown

