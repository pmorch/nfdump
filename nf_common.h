/*
 *  nfcapd : Reads netflow data from socket and saves the
 *  data into a file. The file gets automatically rotated
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
 *  $Id: nf_common.h 34 2005-08-22 12:01:31Z peter $
 *
 *  $LastChangedRevision: 34 $
 *	
 *
 */

#include "config.h"

typedef void (*printer_t)(void *, uint64_t, char **, int);

#if ( SIZEOF_VOID_P == 8 )
typedef uint64_t	pointer_addr_t;
#else
typedef uint32_t	pointer_addr_t;
#endif

typedef struct msec_time_s {
	time_t		sec;
	uint16_t	msec;
} msec_time_tt;

/*
 * binary file layout:
 * mostly compatible with v5 format
 * flow_header is identical to the v5 header
 * flow_record has some changes, to speed up flow processing
 * and overcome the ugly netflow time format ...
 */

#define FLOW_HEADER_LENGTH sizeof(flow_header_t)
#define FLOW_RECORD_LENGTH sizeof(flow_record_t)


/* max records in binary files */
#define MAX_RECORDS		30

typedef struct flow_header {
  uint16_t  version;
  uint16_t  count;
  uint32_t  SysUptime;
  uint32_t  unix_secs;
  uint32_t  unix_nsecs;
  uint32_t  flow_sequence;
  uint8_t   engine_type;
  uint8_t   engine_id;
  uint16_t  layout_version;	/* binary layout version */
} flow_header_t;

typedef struct flow_record {
  uint32_t  srcaddr;
  uint32_t  dstaddr;
  uint32_t  nexthop;
  uint16_t  input;
  uint16_t  output;
  uint32_t  dPkts;
  uint32_t  dOctets;
  uint32_t  First;		/* First seen timestamp in UNIX time format. msec offset at end of record */
  uint32_t  Last;		/* Last seen timestamp in UNIX time format. msec offset at end of record */
  uint16_t  srcport;
  uint16_t  dstport;
  uint8_t   pad;	
  uint8_t   tcp_flags;
  uint8_t   prot;
  uint8_t   tos;
  uint16_t  src_as;
  uint16_t  dst_as;
  uint16_t  msec_first;	/* msec offset from First */
  uint16_t  msec_last;		/* msec offset from Last */
} flow_record_t;

/* prototypes */

void flow_header_raw(void *header, uint64_t numflows, char **s, int anon);

void flow_record_raw(void *record, uint64_t numflows, char **s, int anon);

void flow_record_to_line(void *record, uint64_t numflows, char **s, int anon);

void flow_record_to_line_long(void *record, uint64_t numflows, char **s, int anon);

void flow_record_to_line_extended(void *record, uint64_t numflows, char ** s, int anon);

void flow_record_to_pipe(void *record, uint64_t numflows, char ** s, int anon);

#ifdef __SUNPRO_C
extern 
#endif
inline int TimeMsec_CMP(time_t t1, uint16_t offset1, time_t t2, uint16_t offset2 );

#ifdef __SUNPRO_C
extern 
#endif
inline void format_number(uint64_t num, char *s);
