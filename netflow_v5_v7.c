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
 *  $Id: netflow_v5_v7.c 92 2007-08-24 12:10:24Z peter $
 *
 *  $LastChangedRevision: 92 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <netinet/in.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfnet.h"
#include "nf_common.h"
#include "netflow_v5_v7.h"

extern int verbose;

/* module limited globals */
static int64_t	last_sequence, sequence, distance, last_count;

static int first;

// for sending netflow v5
static netflow_v5_header_t	*v5_output_header;
static netflow_v5_record_t	*v5_output_record;

typedef struct v5_block_s {
	uint32_t	srcaddr;
	uint32_t	dstaddr;
	uint32_t	dPkts;
	uint32_t	dOctets;
	uint8_t		data[4];	// link to next record
} v5_block_t;

/* functions */
void Init_v5_v7_input(void) {
	first = 1;
} // End of Init_v5_input

/*
 * functions used for receiving netflow v5 records
 */

void *Process_v5_v7(void *in_buff, ssize_t in_buff_cnt, data_block_header_t *data_header, void *writeto, 
	stat_record_t *stat_record, uint64_t *first_seen, uint64_t *last_seen) {

netflow_v5_header_t	*v5_header;
netflow_v5_record_t *v5_record;
common_record_t		*common_record;
v5_block_t			*v5_block;
uint64_t			start_time, end_time, boot_time;
uint32_t    		First, Last;
uint16_t			count;
int					i, done, version, record_length, output_record_length;
ssize_t				size_left;
pointer_addr_t 		bsize;
char				*string;

		/* Init
		 * v7 is treated as v5. It differes only in the record length, for what we process.
		 */

		// map v5 data structure to input buffer
		v5_header 	= (netflow_v5_header_t *)in_buff;

		// map file record to output buffer
		common_record	= (common_record_t *)writeto;
		v5_block		= (v5_block_t *)common_record->data;

		// sanity check for buffer size
		bsize = (pointer_addr_t)writeto - (pointer_addr_t)data_header;
		// The save margin is a full data record. The master record is a bit more
		// as no record will use more space than this master_record
		if ( bsize > (BUFFSIZE-sizeof(master_record_t))  ) {
			syslog(LOG_WARNING,"Process_v5: Outputbuffer full. Flush buffer but have to skip records.");
			return writeto;
		}

		// common size + 2 * 32bit ip addresses + 2 * 32bit counters
		output_record_length = sizeof(common_record_t) + sizeof(v5_block_t) - 2 * sizeof(uint8_t[4]);

		
		version = ntohs(v5_header->version);
		record_length = version == 5 ? NETFLOW_V5_RECORD_LENGTH : NETFLOW_V7_RECORD_LENGTH;

		// this many data to process
		size_left	= in_buff_cnt;

		done = 0;
		while ( !done ) {
			/* Process header */
	
			// count and buffer size check
	  		count	= ntohs(v5_header->count);
			if ( count > NETFLOW_V5_MAX_RECORDS ) {
				syslog(LOG_ERR,"Process_v5: Unexpected record count in header: %i. Abort v5/v7 record processing", count);
				return (void *)common_record;
			}
			if ( size_left < ( NETFLOW_V5_HEADER_LENGTH + count * record_length) ) {
				syslog(LOG_ERR,"Process_v5: Not enough data to process v5 record. Abort v5/v7 record processing");
				return (void *)common_record;
			}
	
			// output buffer size check
			if ( (data_header->size + count * output_record_length) > OUTPUT_BUFF_SIZE ) {
				// this should really never occur, because the buffer gets flushed ealier
				syslog(LOG_ERR,"Process_v5: output buffer size error. Abort v5/v7 record processing");
				return (void *)common_record;
			}
	
			// sequence check
			if ( first ) {
				last_sequence = ntohl(v5_header->flow_sequence);
				sequence 	  = last_sequence;
				first 		  = 0;
			} else {
				last_sequence = sequence;
				sequence 	  = ntohl(v5_header->flow_sequence);
				distance 	  = sequence - last_sequence;
				// handle overflow
				if (distance < 0) {
					distance = 0xffffffff + distance  +1;
				}
				if (distance != last_count) {
#define delta(a,b) ( (a)>(b) ? (a)-(b) : (b)-(a) )
					stat_record->sequence_failure++;
					/*
						syslog(LOG_ERR,"Flow sequence mismatch. Missing: %lli flows", delta(last_count,distance));
						syslog(LOG_ERR,"sequence %llu. last sequence: %lli", sequence, last_sequence);
					if ( report_seq ) 
						syslog(LOG_ERR,"Flow sequence mismatch. Missing: %lli flows", delta(last_count,distance));
					*/
				}
			}
			last_count  = count;
	
	  		v5_header->SysUptime	 = ntohl(v5_header->SysUptime);
	  		v5_header->unix_secs	 = ntohl(v5_header->unix_secs);
	  		v5_header->unix_nsecs	 = ntohl(v5_header->unix_nsecs);
	
			/* calculate boot time in msec */
			boot_time  = ((uint64_t)(v5_header->unix_secs)*1000 + 
					((uint64_t)(v5_header->unix_nsecs) / 1000000) ) - (uint64_t)(v5_header->SysUptime);
	
			// process all records
			v5_record	= (netflow_v5_record_t *)((pointer_addr_t)v5_header + NETFLOW_V5_HEADER_LENGTH);

			/* loop over each records associated with this header */
			for (i = 0; i < count; i++) {
	  			common_record->srcport	= ntohs(v5_record->srcport);
	  			common_record->dstport	= ntohs(v5_record->dstport);
	  			common_record->input  	= ntohs(v5_record->input);
	  			common_record->output 	= ntohs(v5_record->output);
	  			common_record->srcas	= ntohs(v5_record->src_as);
	  			common_record->dstas	= ntohs(v5_record->dst_as);
	  			common_record->tcp_flags= v5_record->tcp_flags;
	  			common_record->prot		= v5_record->prot;
	  			common_record->tos		= v5_record->tos;
	  			common_record->dir		= 0;
	  			common_record->flags	= 0;
	  			common_record->mark		= 0;
	  			common_record->size		= output_record_length;

	  			v5_block->srcaddr	= ntohl(v5_record->srcaddr);
	  			v5_block->dstaddr	= ntohl(v5_record->dstaddr);
	  			v5_block->dPkts  	= ntohl(v5_record->dPkts);
	  			v5_block->dOctets	= ntohl(v5_record->dOctets);
	
				// Time issues
	  			First	 				= ntohl(v5_record->First);
	  			Last		 			= ntohl(v5_record->Last);
				if ( First > Last )
					/* Last in msec, in case of msec overflow, between start and end */
					end_time = 0x100000000LL + Last + boot_time;
				else
					end_time = (uint64_t)Last + boot_time;
	
				/* start time in msecs */
				start_time = (uint64_t)First + boot_time;
	
				common_record->first 		= start_time/1000;
				common_record->msec_first	= start_time - common_record->first*1000;
	
				common_record->last 		= end_time/1000;
				common_record->msec_last	= end_time - common_record->last*1000;
	
				// update first_seen, last_seen
				if ( start_time < *first_seen )
					*first_seen = start_time;
				if ( end_time > *last_seen )
					*last_seen = end_time;
	
	
				// Update stats
				switch (common_record->prot) {
					case 1:
						stat_record->numflows_icmp++;
						stat_record->numpackets_icmp += v5_block->dPkts;
						stat_record->numbytes_icmp   += v5_block->dOctets;
						break;
					case 6:
						stat_record->numflows_tcp++;
						stat_record->numpackets_tcp += v5_block->dPkts;
						stat_record->numbytes_tcp   += v5_block->dOctets;
						break;
					case 17:
						stat_record->numflows_udp++;
						stat_record->numpackets_udp += v5_block->dPkts;
						stat_record->numbytes_udp   += v5_block->dOctets;
						break;
					default:
						stat_record->numflows_other++;
						stat_record->numpackets_other += v5_block->dPkts;
						stat_record->numbytes_other   += v5_block->dOctets;
				}
				stat_record->numflows++;
				stat_record->numpackets	+= v5_block->dPkts;
				stat_record->numbytes	+= v5_block->dOctets;
	
				if ( verbose ) {
					master_record_t master_record;
					ExpandRecord((common_record_t *)common_record, &master_record);
				 	format_file_block_record(&master_record, 1, &string, 0, 0);
					printf("%s\n", string);
				}

				v5_record		= (netflow_v5_record_t *)((pointer_addr_t)v5_record + record_length);
				common_record	= (common_record_t *)v5_block->data;
				v5_block		= (v5_block_t *)common_record->data;
				
				// buffer size sanity check
				bsize = (pointer_addr_t)common_record - (pointer_addr_t)data_header;
				if ( bsize >= OUTPUT_BUFF_SIZE ) {
					syslog(LOG_ERR,"Process_v5: Output buffer overflow! Flush buffer and skip records.");
					return (void *)common_record;
				}

			} // End of foreach v5 record

		// update file record size ( -> output buffer size )
		data_header->NumBlocks 	+= count;
		data_header->size 		+= count * output_record_length;

		// still to go for
		size_left 	-= NETFLOW_V5_HEADER_LENGTH + count * record_length;

		// next header
		v5_header	= (netflow_v5_header_t *)v5_record;

		done = size_left <= 0;

	} // End of while !done

	return (void *)common_record;

} /* End of Process_v5 */

/*
 * functions used for sending netflow v5 records
 */
void Init_v5_v7_output(send_peer_t *peer) {

	v5_output_header = (netflow_v5_header_t *)peer->send_buffer;
	v5_output_header->version 		= htons(5);
	v5_output_header->SysUptime		= 0;
	v5_output_header->unix_secs		= 0;
	v5_output_header->unix_nsecs	= 0;
	v5_output_header->count 		= 0;
	first							= 1;

	sequence		 = 0;
	last_sequence	 = 0;
	last_count	 	 = 0;
	v5_output_record = (netflow_v5_record_t *)((pointer_addr_t)v5_output_header + (pointer_addr_t)sizeof(netflow_v5_header_t));	

} // End of Init_v5_v7_output

int Add_v5_output_record(master_record_t *master_record, send_peer_t *peer) {
static uint64_t	boot_time;	// in msec
static int	cnt;
uint32_t	t1, t2;
// char	*s;

	// Skip IPv6 records
	if ( (master_record->flags & FLAG_IPV6_ADDR ) != 0 )
		return 0;

//format_file_block_record(master_record, 1, &s, 0);
//printf("%s\n", s);

	if ( first ) {	// first time a record is added
		// boot time is set one day back - assuming that the start time of every flow does not start ealier
		boot_time  			 		= (uint64_t)(master_record->first - 86400)*1000;
		v5_output_header->unix_secs = htonl(master_record->first - 86400);
		cnt   	 = 0;
		first 	 = 0;
	}
	if ( cnt == 0 ) {
		peer->writeto  = (void *)((pointer_addr_t)peer->send_buffer + NETFLOW_V5_HEADER_LENGTH);
		v5_output_record = (netflow_v5_record_t *)((pointer_addr_t)v5_output_header + (pointer_addr_t)sizeof(netflow_v5_header_t));	
		sequence = last_sequence + last_count;
		v5_output_header->flow_sequence	= htonl(sequence);
		last_sequence = sequence;
	}
	v5_output_record->srcaddr	= htonl(master_record->v4.srcaddr);
  	v5_output_record->dstaddr	= htonl(master_record->v4.dstaddr);
  	v5_output_record->input		= htons(master_record->input);
  	v5_output_record->output	= htons(master_record->output);

	// the 64bit counters are cut down to 32 bits for v5
  	v5_output_record->dPkts		= htonl((uint32_t)master_record->dPkts);
  	v5_output_record->dOctets	= htonl((uint32_t)master_record->dOctets);

	t1 	= (uint32_t)(1000LL * (uint64_t)master_record->first + (uint64_t)master_record->msec_first - boot_time);
	t2	= (uint32_t)(1000LL * (uint64_t)master_record->last  + (uint64_t)master_record->msec_last - boot_time);
  	v5_output_record->First		= htonl(t1);
  	v5_output_record->Last		= htonl(t2);

  	v5_output_record->srcport	= htons(master_record->srcport);
  	v5_output_record->dstport	= htons(master_record->dstport);
  	v5_output_record->src_as	= htons(master_record->srcas);
  	v5_output_record->dst_as	= htons(master_record->dstas);
  	v5_output_record->tcp_flags = master_record->tcp_flags;
  	v5_output_record->prot		= master_record->prot;
  	v5_output_record->tos		= master_record->tos;
	v5_output_record->src_mask 	= 0;
	v5_output_record->dst_mask 	= 0;
	v5_output_record->pad1 		= 0;
	v5_output_record->pad2 		= 0;
  	v5_output_record->nexthop	= 0;

	cnt++;

	v5_output_header->count 	= htons(cnt);
	peer->writeto = (void *)((pointer_addr_t)peer->writeto + NETFLOW_V5_RECORD_LENGTH);
	v5_output_record++;
	if ( cnt == NETFLOW_V5_MAX_RECORDS ) {
		peer->flush = 1;
		last_count 	  = cnt;
		cnt = 0; 
	}

	return 0;

} // End of Add_v5_output_record
