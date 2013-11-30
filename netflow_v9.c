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
 *  $Id: netflow_v9.c 62 2006-03-08 12:59:51Z peter $
 *
 *  $LastChangedRevision: 62 $
 *	
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>

#include "config.h"
#include "nffile.h"
#include "nfnet.h"
#include "nf_common.h"
#include "util.h"
#include "netflow_v5_v7.h"
#include "netflow_v9.h"


#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "inline.c"

extern int verbose;

typedef struct translation_element_s {
	uint16_t	input_offset;
	uint16_t	output_offset;
	uint16_t	length;
} translation_element_t;

typedef struct input_translation_s {
	struct input_translation_s	*next;
	uint32_t	flags;
	time_t		updated;
	uint32_t	id;
	uint32_t	input_record_size;
	uint32_t	output_record_size;
	uint32_t	input_index;
	uint32_t	zero_index;
	uint32_t    packet_offset;
	uint32_t    byte_offset;
	translation_element_t element[NumElements];
} input_translation_t;

typedef struct exporter_domain_s {
	struct exporter_domain_s	*next;
	// identifier
	uint32_t	exporter_id;
	// exporter parameters
	uint64_t	boot_time;
	// sequence
	int64_t		last_sequence;
	int64_t		sequence;
	int			first;
	input_translation_t	*input_translation_table; 
	input_translation_t *current_table;
} exporter_domain_t;

/* module limited globals */
static struct element_info_s {
	uint16_t	min;
	uint16_t	max;
} element_info[128] = {
	{ 0, 0 }, 	//  0 - empty
	{ 4, 8 }, 	//  1 - NF9_IN_BYTES
	{ 4, 8 }, 	//  2 - NF9_IN_PACKETS
	{ 4, 8 }, 	//  3 - NF9_FLOWS
	{ 1, 1 }, 	//  4 - NF9_IN_PROTOCOL
	{ 1, 1 },	//  5 - NF9_SRC_TOS
	{ 1, 1 },	//  6 - NF9_TCP_FLAGS
	{ 2, 2 },	//  7 - NF9_L4_SRC_PORT
	{ 4, 4 },	//  8 - NF9_IPV4_SRC_ADDR
	{ 2, 2 },	//  9 - NF9_SRC_MASK
	{ 2, 2 },	// 10 - NF9_INPUT_SNMP
	{ 2, 2 },	// 11 - NF9_L4_DST_PORT
	{ 4, 4 },	// 12 - NF9_IPV4_DST_ADDR
	{ 2, 2 },	// 13 - NF9_DST_MASK
	{ 2, 2 },	// 14 - NF9_OUTPUT_SNMP
	{ 4, 4 },	// 15 - NF9_IPV4_NEXT_HOP
	{ 2, 2 },	// 16 - NF9_SRC_AS
	{ 2, 2 },	// 17 - NF9_DST_AS

	{ 0, 0 }, { 0, 0 }, { 0, 0 }, 				// 18 - 20 not implemented

	{ 4, 4 },	// 21 - NF9_LAST_SWITCHED
	{ 4, 4 },	// 22 - NF9_FIRST_SWITCHED
	{ 4, 8 },	// 23 - NF9_OUT_BYTES
	{ 4, 8 },	// 24 - NF9_OUT_PKTS

	{ 0, 0 }, { 0, 0 }, 					// 25 - 26 not implemented

	{ 16, 16 },	// 27 - NF9_IPV6_SRC_ADDR
	{ 16, 16 },	// 28 - NF9_IPV6_DST_ADDR
	{ 4, 4 },	// 29 - NF9_IPV6_SRC_MASK
	{ 4, 4 },	// 30 - NF9_IPV6_DST_MASK
	{ 4, 4 },	// 31 - NF9_IPV6_FLOW_LABEL
	{ 4, 4 },	// 32 - NF9_ICMP_TYPE

	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, 			// 33 - 37 not implemented

	{ 4, 4 },	// 38 - NF9_ENGINE_TYPE
	{ 4, 4 },	// 39 - NF9_ENGINE_ID

	// 40 - 47   not implemented
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, 
	// 48 - 55   not implemented
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, 
	// 56 - 60   not implemented
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, 

	{ 1, 1 }, 	// 61 - NF9_DIRECTION

	// 62 - 63   not implemented
	{ 0, 0 }, { 0, 0 }, 
	// 64 - 71   not implemented
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, 
	// 72 - 79   not implemented
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, 
	// 80 - 87   not implemented
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, 
	// 88 - 95   not implemented
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, 
	// 96 - 103  not implemented
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, 
	// 104 - 111 not implemented
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, 
	// 112 - 119 not implemented
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, 
	// 120 - 127 not implemented
	{ 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }  

};

#define CheckElementLength(a, b)	( (b) == element_info[(a)].min || (b) == element_info[(a)].max )

typedef struct output_templates_s {
	struct output_templates_s 	*next;
	uint32_t			flags;
	time_t				time_sent;
	uint32_t			record_length;	// length of the data record resulting from this template
	uint32_t			flowset_length;	// length of the flowset record
	template_flowset_t *template_flowset;
} output_template_t;

#define MAX_LIFETIME 60

static output_template_t	*output_templates;
static uint16_t				template_id;

static uint32_t	processed_records;
static exporter_domain_t *exporter;

/* local function prototypes */
static inline void FillElement(input_translation_t *table, int element, uint32_t *offset);

static inline void Process_v9_templates(exporter_domain_t *exporter, template_flowset_t *template_flowset);

static inline void *Process_v9_data(exporter_domain_t *exporter, data_flowset_t *data_flowset, data_block_header_t *data_header, 
	void *writeto, stat_record_t *stat_record, uint64_t *first_seen, uint64_t *last_seen);

static inline exporter_domain_t *GetExporter(uint32_t exporter_id);

static inline input_translation_t *GetTranslationTable(exporter_domain_t *exporter, uint16_t id);

static void setup_translation_table (exporter_domain_t *exporter, uint16_t id, uint16_t input_record_size);

static input_translation_t *add_translation_table(exporter_domain_t *exporter, uint16_t id);

static output_template_t *GetOutputTemplate(uint32_t flags);

static uint16_t	Get_val16(void *p);

static uint32_t	Get_val32(void *p);

static uint64_t	Get_val64(void *p);

/* local variables */

static struct input_table_s {
	uint16_t	offset;
	uint16_t	length;
} input_template[128];

// for sending netflow v9
static netflow_v9_header_t	*v9_output_header;

/* functions */


void Init_v9(void) {
	exporter 	 	 = NULL;
	output_templates = NULL;
	template_id	 	 = NF9_MIN_RECORD_FLOWSET_ID;
} // End of Init_v9

static inline exporter_domain_t *GetExporter(uint32_t exporter_id) {
exporter_domain_t **e;

	e = &exporter;
	while ( *e ) {
		if ( (*e)->exporter_id == exporter_id )
			return *e;
		e = &((*e)->next);
	}

	syslog(LOG_INFO, "Process_v9: New exporter domain %u\n", exporter_id);

	// nothing found
	*e = (exporter_domain_t *)malloc(sizeof(exporter_domain_t));
	if ( !(*e)) {
		syslog(LOG_ERR, "Process_v9: Panic! %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
		return NULL;
	}
	memset((void *)(*e), 0, sizeof(exporter_domain_t));
	(*e)->exporter_id 	= exporter_id;
	(*e)->first	 		= 1;
	(*e)->next	 		= NULL;
	return (*e);

} // End of GetExporter

static inline input_translation_t *GetTranslationTable(exporter_domain_t *exporter, uint16_t id) {
input_translation_t *table;

	if ( exporter->current_table && ( exporter->current_table->id == id ) )
		return exporter->current_table;

	table = exporter->input_translation_table;
	while ( table ) {
		if ( table->id == id ) {
			exporter->current_table = table;
			return table;
		}

		table = table->next;
	}

	// printf("[%u] Get translation table %u: %s\n", exporter->exporter_id, id, table == NULL ? "not found" : "found");

	exporter->current_table = table;
	return table;

} // End of GetTranslationTable

static input_translation_t *add_translation_table(exporter_domain_t *exporter, uint16_t id) {
input_translation_t **table;

	table = &(exporter->input_translation_table);
	while ( *table ) {
		table = &((*table)->next);
	}
	*table = malloc(sizeof(input_translation_t));
	if ( !(*table) ) {
			syslog(LOG_ERR, "Process_v9: Panic! %s line %d: %s\n", __FILE__, __LINE__, strerror (errno));
			return NULL;
	}
	(*table)->id   = id;
	(*table)->next = NULL;

	// printf("[%u] Get new translation table %u\n", exporter->exporter_id, id);
	return *table;

} // End of add_translation_table

static inline void FillElement(input_translation_t *table, int element, uint32_t *offset) {
uint32_t	input_index = table->input_index;
uint32_t	zero_index  = table->zero_index;

	if ( CheckElementLength(element, input_template[element].length) ) { 
	/*
		printf("Index: %u Elem %i, IO %u, OO %u, len: %u\n", 
			input_index, element, input_template[element].offset, *offset, input_template[element].length);
	*/
		table->element[input_index].output_offset 	= *offset;
		table->element[input_index].input_offset 	= input_template[element].offset;
		table->element[input_index].length 			= input_template[element].length;
		table->input_index++;
		(*offset)	+= input_template[element].length;
	} else {
	/*
		printf("Zero: %u, Elem: %i,  OO %u, len: %u\n", 
			zero_index, element, *offset, element_info[element].min);
	*/
		table->element[zero_index].output_offset 	= *offset;
		table->element[zero_index].length 			= element_info[element].min;
		table->zero_index--;
		(*offset)	+= element_info[element].min;
	}

} // End of FillElement

static void setup_translation_table (exporter_domain_t *exporter, uint16_t id, uint16_t input_record_size) {
input_translation_t *table;
uint32_t			offset;

	table = GetTranslationTable(exporter, id);
	if ( !table ) {
		syslog(LOG_INFO, "Process_v9: [%u] Add template %u\n", exporter->exporter_id, id);
		table = add_translation_table(exporter, id);
 	} else
		syslog(LOG_INFO, "Process_v9: [%u] Refresh template %u\n", exporter->exporter_id, id);

	if ( !table ) {
		return;
	}

	// clear current table
	memset((void *)table->element, 0, NumElements * sizeof(translation_element_t));
	table->updated  = time(NULL);
	table->flags	= 0;

	// printf("[%u] Fill translation table %u\n", exporter->exporter_id, id);

	// fill table

	table->id 			= id;
	table->input_index 	= 0;
	table->zero_index 	= NumElements - 1;

	/* 
	 * common data block: The common record is expected in the output stream. If not available
	 * in the template, fill values with 0
	 */

	offset = BYTE_OFFSET_first;
	FillElement( table, NF9_FIRST_SWITCHED, &offset);
	FillElement( table, NF9_LAST_SWITCHED, &offset);
	FillElement( table, NF9_DIRECTION, &offset);
	FillElement( table, NF9_TCP_FLAGS, &offset);
	FillElement( table, NF9_IN_PROTOCOL, &offset);
	FillElement( table, NF9_SRC_TOS, &offset);
	FillElement( table, NF9_INPUT_SNMP, &offset);
	FillElement( table, NF9_OUTPUT_SNMP, &offset);
	FillElement( table, NF9_L4_SRC_PORT, &offset);
	FillElement( table, NF9_L4_DST_PORT, &offset);
	FillElement( table, NF9_SRC_AS, &offset);
	FillElement( table, NF9_DST_AS, &offset);

	/* IP addresss record
	 * This record is expected in the output stream. If not available
	 * in the template, assume empty v4 address.
	 */
	if ( input_template[NF9_IPV4_SRC_ADDR].length ) {
		// IPv4 addresses 
		FillElement( table, NF9_IPV4_SRC_ADDR, &offset);
		FillElement( table, NF9_IPV4_DST_ADDR, &offset);
	} else if ( input_template[NF9_IPV6_SRC_ADDR].length == 16 ) {
		// IPv6 addresses 
		FillElement( table, NF9_IPV6_SRC_ADDR, &offset);
		FillElement( table, NF9_IPV6_DST_ADDR, &offset);
		// mark IPv6 
		table->flags	|= FLAG_IPV6_ADDR;
	} else {
		// should not happen, assume empty IPv4 addresses
		FillElement( table, NF9_IPV4_SRC_ADDR, &offset);
		FillElement( table, NF9_IPV4_DST_ADDR, &offset);
	}

	
	/* packet record
	 * This record is expected in the output stream. If not available
	 * in the template, assume empty 4 bytes value
	 */
	if ( input_template[NF9_IN_PACKETS].length ) {
		table->packet_offset = offset;
		FillElement( table, NF9_IN_PACKETS, &offset);
		if ( input_template[NF9_IN_PACKETS].length == 8 )
			table->flags	|= FLAG_PKG_64;
	} else
		table->packet_offset = 0;

	/* byte record
	 * This record is expected in the output stream. If not available
	 * in the template, assume empty 4 bytes value
	 */
	if ( input_template[NF9_IN_BYTES].length ) {
		table->byte_offset = offset;
		FillElement( table, NF9_IN_BYTES, &offset);
		if ( input_template[NF9_IN_BYTES].length == 8 )
			table->flags	|= FLAG_BYTES_64;
	} else 
		table->byte_offset = 0;

	table->input_record_size  = input_record_size;
	table->output_record_size = offset;

	/*
	printf("Table %u Flags: %u, index: %u, Zero: %u input_size: %u, output_size: %u\n", 
		table->id, table->flags, table->input_index, table->zero_index, table->input_record_size, table->output_record_size);
	*/

} // End of setup_translation_table

static inline void Process_v9_templates(exporter_domain_t *exporter, template_flowset_t *template_flowset) {
template_record_t	*template;
uint16_t	id, count, field_type, field_length, offset;
uint32_t	size_left, template_size;
int			i;

	size_left = ntohs(template_flowset->length) - 4; // -4 for flowset header -> id and length
	template = template_flowset->fields;

	// process all templates in flowset, as long as any bytes are left
	template_size = 0;
	while (size_left) {
		template = (template_record_t *)((pointer_addr_t)template + template_size);

		id 	  = ntohs(template->template_id);
		count = ntohs(template->count);
	// printf("\n[%u] Template ID: %u\n", exporter->exporter_id, id);

		template_size = 4 + 4 * count;	// id + count = 4 bytes, and 2 x 2 bytes for each entry
	// printf("template size: %u buffersize: %u\n", template_size, size_left);

		if ( size_left < template_size ) {
			syslog(LOG_ERR, "Process_v9: [%u] buffer size error: expected %u available %u\n", 
				exporter->exporter_id, template_size, size_left);
			size_left = 0;
			continue;
		}

		offset = 0;
		memset((void *)&input_template, 0, sizeof(input_template));
		for(i=0; i<count; i++ ) {
			field_type   = ntohs(template->record[i].type) & 0x007f;	// make sure field < 128
			field_length = ntohs(template->record[i].length);
			input_template[field_type].offset = offset;
			input_template[field_type].length = field_length;
			offset += field_length;

	// printf("Type: %u, Length %u\n", field_type, field_length);
		}
		setup_translation_table(exporter, id, offset);
		size_left -= template_size;
		processed_records++;
	// printf("\n");

	} // End of while size_left

} // End of Process_v9_templates

inline void *Process_v9_data(exporter_domain_t *exporter, data_flowset_t *data_flowset, data_block_header_t *data_header, void *writeto, 
	stat_record_t *stat_record, uint64_t *first_seen, uint64_t *last_seen) {

input_translation_t *table;
common_record_t		*data_record;
uint64_t			start_time, end_time, packets, bytes;
uint32_t			size_left, First, Last;
uint8_t				*in, *out;
pointer_addr_t 		bsize;
int					i;
char				*string;

	data_flowset->flowset_id = ntohs(data_flowset->flowset_id);
	table = GetTranslationTable(exporter, data_flowset->flowset_id);
	if ( !table ) {
//		syslog(LOG_WARNING,"Process v9: [%u] No table for id %u -> Skip record\n", 
//			exporter->exporter_id, data_flowset->flowset_id);
		return writeto;
	}

	// map file record to output buffer
	data_record	= (common_record_t *)writeto;

	// sanity check for buffer size
	bsize = (pointer_addr_t)writeto - (pointer_addr_t)data_header;
	if ( bsize > OUTPUT_FLUSH_LIMIT ) {
		syslog(LOG_WARNING,"Process v9: Outputbuffer full. Flush buffer but have to skip records.");
		return writeto;
	}


	size_left = ntohs(data_flowset->length) - 4; // -4 for data flowset header -> id and length

	// map byte arrays
	in  	  = (uint8_t *)data_flowset->data;
	out 	  = (uint8_t *)data_record;

	// printf("[%u] Process data flowset size: %u\n", exporter->exporter_id, size_left);
	
	while (size_left) {
		
		if ( (size_left < table->input_record_size) ) {
			if ( size_left > 3 )
				syslog(LOG_WARNING,"Process_v9: Corrupt data flowset? Pad bytes: %u\n", size_left);
			size_left = 0;
			continue;
		}

		// check for enough space in output buffer
		if ( (data_header->size + table->output_record_size) > OUTPUT_BUFF_SIZE ) {
			// this should really never occur, because the buffer gets flushed ealier
			syslog(LOG_ERR,"Process_v9: output buffer size error. Abort v9 record processing");
			return writeto;
		}
		processed_records++;

		/*
		printf("[%u] Process data record: %u addr: %u %u buffersize: %u\n", 
			exporter->exporter_id, processed_records, (uint32_t)in - (uint32_t)data_flowset, table->input_record_size, size_left);
		*/

		// fill the data record
		data_record->flags 	= table->flags;
		data_record->size  	= table->output_record_size;
		data_record->mark	= 0;

		// pop up the table to fill the data record
		for ( i=0; i<table->input_index; i++ ) {
			int input_offset  = table->element[i].input_offset;
			int output_offset = table->element[i].output_offset;
			switch ( table->element[i].length ) {
				case 1:
					out[output_offset] = in[input_offset];
					break;
				case 2:
					*((uint16_t *)&out[output_offset]) = ntohs(Get_val16((void *)&in[input_offset]));
					break;
				case 4:
					*((uint32_t *)&out[output_offset]) = ntohl(Get_val32((void *)&in[input_offset]));
					break;
				case 8:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;

						t.val.val64 = ntohll(Get_val64((void *)&in[input_offset]));
						*((uint32_t *)&out[output_offset]) 	 = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4]) = t.val.val32[1];
					}
					break;
				case 16:
					/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
					{ type_mask_t t;
					  
						t.val.val64 = ntohll(Get_val64((void *)&in[input_offset]));
						*((uint32_t *)&out[output_offset]) 	  = t.val.val32[0];
						*((uint32_t *)&out[output_offset+4])  = t.val.val32[1];

						t.val.val64 = ntohll(Get_val64((void *)&in[input_offset+8]));
						*((uint32_t *)&out[output_offset+8])  = t.val.val32[0];
						*((uint32_t *)&out[output_offset+12]) = t.val.val32[1];
					}
					break;
				default:
					memcpy((void *)&out[output_offset], (void *)&in[input_offset], table->element[i].length);
			}
		} // End for

		// pop down the table to zero unavailable elements
		for ( i=NumElements - 1; i>table->zero_index; i-- ) {
			int output_offset 	= table->element[i].output_offset;
			switch ( table->element[i].length ) {
				case 1:
					out[output_offset] = 0;
					break;
				case 2:
					*((uint16_t *)&out[output_offset]) = 0;
					break;
				case 4:
					*((uint32_t *)&out[output_offset]) = 0;
					break;
				case 8:
					*((uint64_t *)&out[output_offset]) = 0;
					break;
				case 16:
					memset((void *)&out[output_offset], 0, 16);
					break;
				default:
					memset((void *)&out[output_offset], 0, table->element[i].length);
			}
		} // End for

		First = data_record->first;
		Last  = data_record->last;

		if ( First > Last )
			/* Last in msec, in case of msec overflow, between start and end */
			end_time = 0x100000000LL + Last + exporter->boot_time;
		else
			end_time = (uint64_t)Last + exporter->boot_time;
	
		/* start time in msecs */
		start_time = (uint64_t)First + exporter->boot_time;
	
		data_record->first 		= start_time/1000;
		data_record->msec_first	= start_time - data_record->first*1000;
	
		data_record->last 		= end_time/1000;
		data_record->msec_last	= end_time - data_record->last*1000;
	
		// update first_seen, last_seen
		if ( start_time < *first_seen )
			*first_seen = start_time;
		if ( end_time > *last_seen )
			*last_seen = end_time;

		// Update stats
		if ( table->packet_offset ) {
			if ( (data_record->flags & FLAG_PKG_64 ) == 0 ) // 32bit packet counter
				packets = *((uint32_t *)&(out[table->packet_offset]));
			else {
				/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
				value64_t	v;
				uint32_t	*ptr = (uint32_t *)&(out[table->packet_offset]);

				v.val.val32[0] = ptr[0];
				v.val.val32[1] = ptr[1];
				packets = v.val.val64;
			}
		} else
			packets = 0;

		if ( table->byte_offset ) {
			if ( (data_record->flags & FLAG_BYTES_64 ) == 0 ) // 32bit byte counter
				bytes = *((uint32_t *)&(out[table->byte_offset]));
			else {
				/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
				value64_t	v;
				uint32_t	*ptr = (uint32_t *)&(out[table->byte_offset]);

				v.val.val32[0] = ptr[0];
				v.val.val32[1] = ptr[1];
				bytes = v.val.val64;
			}
		} else
			bytes = 0;

		switch (data_record->prot ) { // switch protocol of
			case 1:
				stat_record->numflows_icmp++;
				stat_record->numpackets_icmp += packets;
				stat_record->numbytes_icmp   += bytes;
				break;
			case 6:
				stat_record->numflows_tcp++;
				stat_record->numpackets_tcp += packets;
				stat_record->numbytes_tcp   += bytes;
				break;
			case 17:
				stat_record->numflows_udp++;
				stat_record->numpackets_udp += packets;
				stat_record->numbytes_udp   += bytes;
				break;
			default:
				stat_record->numflows_other++;
				stat_record->numpackets_other += packets;
				stat_record->numbytes_other   += bytes;
		}
		stat_record->numflows++;
		stat_record->numpackets	+= packets;
		stat_record->numbytes	+= bytes;
	
		if ( verbose ) {
			master_record_t master_record;
			ExpandRecord((common_record_t *)data_record, &master_record);
		 	format_file_block_record(&master_record, 1, &string, 0);
			printf("%s\n", string);
		}

		data_header->size  += data_record->size;
		data_header->NumBlocks++;
		size_left 		   -= table->input_record_size;
		in  	  		   += table->input_record_size;
		data_record			= (common_record_t *)((pointer_addr_t)data_record + data_record->size);
		out = (uint8_t *)data_record;

		// buffer size sanity check
		bsize = (pointer_addr_t)data_record - (pointer_addr_t)data_header;
		if ( bsize >= OUTPUT_BUFF_SIZE ) {
			syslog(LOG_ERR,"Process v9: Output buffer overflow! Flush buffer and skip records.");
			return (void *)data_record;
		}

	}
	return (void *)data_record;

} // End of Process_v9_data

void *Process_v9(void *in_buff, ssize_t in_buff_cnt, data_block_header_t *data_header, void *writeto, 
	stat_record_t *stat_record, uint64_t *first_seen, uint64_t *last_seen) {

exporter_domain_t	*exporter;
common_header_t		*common_header;
option_template_flowset_t	*option_flowset;
netflow_v9_header_t	*v9_header;
int64_t 			distance;
uint32_t 			expected_records, flowset_id, flowset_length, exporter_id;
ssize_t				size_left;

	size_left = in_buff_cnt;
	if ( size_left < NETFLOW_V9_HEADER_LENGTH ) {
		syslog(LOG_ERR, "Process_v9: Too little data for v9 packets: '%u'\n", size_left);
		return writeto;
	}

	// map v9 data structure to input buffer
	v9_header 	= (netflow_v9_header_t *)in_buff;
	exporter_id = ntohl(v9_header->source_id);

	exporter	= GetExporter(exporter_id);
	if ( !exporter )
		return writeto;

	/* calculate boot time in msec */
  	v9_header->SysUptime 	= ntohl(v9_header->SysUptime);
  	v9_header->unix_secs	= ntohl(v9_header->unix_secs);
	exporter->boot_time  	= (uint64_t)1000 * (uint64_t)(v9_header->unix_secs) - (uint64_t)v9_header->SysUptime;
	
	expected_records 		= ntohs(v9_header->count);
	common_header 			= (common_header_t *)((pointer_addr_t)v9_header + NETFLOW_V9_HEADER_LENGTH);

	size_left -= NETFLOW_V9_HEADER_LENGTH;

	// printf("\n[%u] Next packet: %u records, buffer: %u \n", exporter_id, expected_records, size_left);

	// sequence check
	if ( exporter->first ) {
		exporter->last_sequence = ntohl(v9_header->sequence);
		exporter->sequence 	  	= exporter->last_sequence;
		exporter->first			= 0;
	} else {
		exporter->last_sequence = exporter->sequence;
		exporter->sequence 	  = ntohl(v9_header->sequence);
		distance 	  = exporter->sequence - exporter->last_sequence;
		// handle overflow
		if (distance < 0) {
			distance = 0xffffffff + distance  +1;
		}
		if (distance != 1) {
			stat_record->sequence_failure++;
			/*
			printf("[%u] Sequence error: last seq: %lli, seq %lli dist %lli\n", 
				exporter->exporter_id, exporter->last_sequence, exporter->sequence, distance);
			*/
			/*
			if ( report_seq ) 
				syslog(LOG_ERR,"Flow sequence mismatch. Missing: %lli packets", delta(last_count,distance));
			*/
		}
	}

	processed_records = 0;

	// iterate over all flowsets in export packet, while there are bytes left
	flowset_length = 0;
	while (size_left) {
		common_header = (common_header_t *)((pointer_addr_t)common_header + flowset_length);

		flowset_id 		= ntohs(common_header->flowset_id);
		flowset_length 	= ntohs(common_header->length);
			
		/*
		printf("[%u] Next flowset: %u, length: %u buffersize: %u addr: %u\n", 
			exporter->exporter_id, flowset_id, flowset_length, size_left, 
			(uint32_t)common_header - (uint32_t)in_buff );
		*/

		if ( flowset_length <= 4 ) {
			/* 	this should never happen, as 4 is an empty flowset 
				and smaller is an illegal flowset anyway ...
				if it happends, we can't determine the next flowset, so skip the entire export packet
			 */
			syslog(LOG_ERR,"Process_v9: flowset length error. '%u' is too short for a flowset", flowset_length);
			// printf("Process_v9: flowset length error. '%u' is too short for a flowset\n", flowset_length);
			return writeto;
		}

		if ( flowset_length > size_left ) {
			syslog(LOG_ERR,"Process_v9: flowset length error. Expected bytes: %u but buffersize: %u\n", flowset_length, size_left);
			size_left = 0;
			continue;
		}

		switch (flowset_id) {
			case NF9_TEMPLATE_FLOWSET_ID:
					Process_v9_templates(exporter, (template_flowset_t *)common_header);
				break;
			case NF9_OPTIONS_FLOWSET_ID:
				option_flowset = (option_template_flowset_t *)common_header;
				syslog(LOG_DEBUG,"Process_v9: Ignore options flowset: template %u\n", ntohs(option_flowset->template_id));
				break;
			default:
				if ( flowset_id < NF9_MIN_RECORD_FLOWSET_ID ) {
			// printf("Invalid flowset id: %u\n", flowset_id);
					syslog(LOG_ERR,"Process_v9: Invalid flowset id: %u\n", flowset_id);
				}

			// printf("[%u] ID %u Data flowset\n", exporter->exporter_id, flowset_id);
				writeto = Process_v9_data(exporter, (data_flowset_t *)common_header, data_header, writeto, stat_record, first_seen, last_seen);
		}

		// next flowset
		size_left -= flowset_length;

	} // End of while 

/*
	if ( processed_records != expected_records ) {
		syslog(LOG_INFO,"Process_v9: Processed records %u, expected %u\n", processed_records, expected_records);
	}
*/
	return writeto;
	
} /* End of Process_v9 */

/*
 * functions for sending netflow v9 records
 */

void Init_v9_output(send_peer_t *peer) {

	v9_output_header = (netflow_v9_header_t *)peer->send_buffer;
	v9_output_header->version 		= htons(9);
	v9_output_header->SysUptime		= 0;
	v9_output_header->unix_secs		= 0;
	v9_output_header->count 		= 0;
	v9_output_header->source_id 	= htonl(1);
	template_id						= NF9_MIN_RECORD_FLOWSET_ID;
	peer->writeto = (void *)((pointer_addr_t)v9_output_header + (pointer_addr_t)sizeof(netflow_v9_header_t));	

} // End of Init_v9_output

static output_template_t *GetOutputTemplate(uint32_t flags) {
output_template_t **t;
template_record_t	*fields;
uint32_t	count, record_length;

	t = &output_templates;
	// search for the template, which corresponds to our flags
	while ( *t ) {
		if ( (*t)->flags == flags ) 
			return *t;
		t = &((*t)->next);
	}

	// nothing found, otherwise we would not get here
	*t = (output_template_t *)malloc(sizeof(output_template_t));
	if ( !(*t)) {
		fprintf(stderr, "Memory error:%s\n", strerror (errno));
		return NULL;
	}
	memset((void *)(*t), 0, sizeof(output_template_t));
	(*t)->next	 		= NULL;
	(*t)->flags	 		= flags;
	(*t)->template_flowset = malloc(sizeof(template_flowset_t) + ((MAX_TEMPLATE_ELEMENTS * 4)));

	count 			= 0;
	record_length 	= 0;
	fields = (*t)->template_flowset->fields;
	// index 0 and 1 are filled in at the end
	fields->record[count].type	 = htons(NF9_FIRST_SWITCHED);
	fields->record[count].length = htons(element_info[NF9_FIRST_SWITCHED].min);
	record_length 				+= element_info[NF9_FIRST_SWITCHED].min;
	count++;

	fields->record[count].type   = htons(NF9_LAST_SWITCHED);
	fields->record[count].length = htons(element_info[NF9_LAST_SWITCHED].min);
	record_length 				+= element_info[NF9_LAST_SWITCHED].min;
	count++;

	fields->record[count].type   = htons(NF9_DIRECTION);
	fields->record[count].length = htons(element_info[NF9_DIRECTION].min);
	record_length 				+= element_info[NF9_DIRECTION].min;
	count++;

	fields->record[count].type   = htons(NF9_TCP_FLAGS);
	fields->record[count].length = htons(element_info[NF9_TCP_FLAGS].min);
	record_length 				+= element_info[NF9_TCP_FLAGS].min;
	count++;

	fields->record[count].type   = htons(NF9_IN_PROTOCOL);
	fields->record[count].length = htons(element_info[NF9_IN_PROTOCOL].min);
	record_length 				+= element_info[NF9_IN_PROTOCOL].min;
	count++;

	fields->record[count].type   = htons(NF9_SRC_TOS);
	fields->record[count].length = htons(element_info[NF9_SRC_TOS].min);
	record_length 				+= element_info[NF9_SRC_TOS].min;
	count++;

	fields->record[count].type   = htons(NF9_INPUT_SNMP);
	fields->record[count].length = htons(element_info[NF9_INPUT_SNMP].min);
	record_length 				+= element_info[NF9_INPUT_SNMP].min;
	count++;

	fields->record[count].type   = htons(NF9_OUTPUT_SNMP);
	fields->record[count].length = htons(element_info[NF9_OUTPUT_SNMP].min);
	record_length 				+= element_info[NF9_OUTPUT_SNMP].min;
	count++;

	fields->record[count].type   = htons(NF9_L4_SRC_PORT);
	fields->record[count].length = htons(element_info[NF9_L4_SRC_PORT].min);
	record_length 				+= element_info[NF9_L4_SRC_PORT].min;
	count++;

	fields->record[count].type   = htons(NF9_L4_DST_PORT);
	fields->record[count].length = htons(element_info[NF9_L4_DST_PORT].min);
	record_length 				+= element_info[NF9_L4_DST_PORT].min;
	count++;

	fields->record[count].type   = htons(NF9_SRC_AS);
	fields->record[count].length = htons(element_info[NF9_SRC_AS].min);
	record_length 				+= element_info[NF9_SRC_AS].min;
	count++;

	fields->record[count].type   = htons(NF9_DST_AS);
	fields->record[count].length = htons(element_info[NF9_DST_AS].min);
	record_length 				+= element_info[NF9_DST_AS].min;
	count++;

	if ( (flags & FLAG_IPV6_ADDR) != 0 ) { // IPv6 addresses
		fields->record[count].type   = htons(NF9_IPV6_SRC_ADDR);
		fields->record[count].length = htons(element_info[NF9_IPV6_SRC_ADDR].min);
		record_length 				+= element_info[NF9_IPV6_SRC_ADDR].min;
		count++;
		fields->record[count].type   = htons(NF9_IPV6_DST_ADDR);
		fields->record[count].length = htons(element_info[NF9_IPV6_DST_ADDR].min);
		record_length 				+= element_info[NF9_IPV6_DST_ADDR].min;
	} else { // IPv4 addresses
		fields->record[count].type   = htons(NF9_IPV4_SRC_ADDR);
		fields->record[count].length = htons(element_info[NF9_IPV4_SRC_ADDR].min);
		record_length 				+= element_info[NF9_IPV4_SRC_ADDR].min;
		count++;
		fields->record[count].type   = htons(NF9_IPV4_DST_ADDR);
		fields->record[count].length = htons(element_info[NF9_IPV4_DST_ADDR].min);
		record_length 				+= element_info[NF9_IPV4_DST_ADDR].min;
	}
	count++;

	fields->record[count].type  = htons(NF9_IN_PACKETS);
	if ( (flags & FLAG_PKG_64) != 0 ) {  // 64bit packet counter
		fields->record[count].length = htons(element_info[NF9_IN_PACKETS].max);
		record_length 				+= element_info[NF9_IN_PACKETS].max;
	} else {
		fields->record[count].length = htons(element_info[NF9_IN_PACKETS].min);
		record_length 				+= element_info[NF9_IN_PACKETS].min;
	}
	count++;

	fields->record[count].type  = htons(NF9_IN_BYTES);
	if ( (flags & FLAG_BYTES_64) != 0 ) { // 64bit byte counter
		fields->record[count].length = htons(element_info[NF9_IN_BYTES].max);
		record_length 				+= element_info[NF9_IN_BYTES].max;
	} else {
		fields->record[count].length = htons(element_info[NF9_IN_BYTES].min);
		record_length 				+= element_info[NF9_IN_BYTES].min;
	}
	count++;

	(*t)->template_flowset->flowset_id   = htons(NF9_TEMPLATE_FLOWSET_ID);
	(*t)->flowset_length				 = 4 * (2+count); // + 2 for the header
	(*t)->template_flowset->length  	 = htons((*t)->flowset_length);
	(*t)->record_length					 = record_length;

	fields->template_id		= htons(template_id++);
	fields->count			= htons(count);

	return *t;

} // End of GetOutputTemplate

int Add_v9_output_record(master_record_t *master_record, send_peer_t *peer) {
static data_flowset_t		*data_flowset;
static output_template_t	*template;
static uint64_t	boot_time;	// in msec
static uint32_t	last_flags, common_block_size;
static int	record_count, template_count, flowset_count, packet_count;
uint32_t	required_size, t1, t2;
void		*endwrite;
time_t		now = time(NULL);

/*
	char		*string;
	format_file_block_record(master_record, 1, &string, 0);
	printf("%s\n", string);
*/
	if ( !v9_output_header->unix_secs ) {	// first time a record is added
		// boot time is set one day back - assuming that the start time of every flow does not start ealier
		boot_time	   = (uint64_t)(master_record->first - 86400)*1000;
		v9_output_header->unix_secs = htonl(master_record->first - 86400);
		v9_output_header->sequence  = 0;
		peer->writeto  = (void *)((pointer_addr_t)peer->send_buffer + NETFLOW_V9_HEADER_LENGTH);
		record_count   = 0;
		template_count = 0;
		flowset_count  = 0;
		packet_count   = 0;
		data_flowset   = NULL;

		// write common blocksize from frst up to including dstas for one write (memcpy)
		common_block_size = (pointer_addr_t)&master_record->fill - (pointer_addr_t)&master_record->first;

	} else if ( flowset_count == 0 ) {	// after a buffer flush
		packet_count++;
		v9_output_header->sequence = htonl(packet_count);
	}

	if ( data_flowset ) {
		// output buffer contains already a data flowset
		if ( last_flags == master_record->flags ) {
			// same id as last record
			// if ( now - template->time_sent > MAX_LIFETIME )
			if ( (record_count & 0xFFF) == 0 ) {	// every 4096 flow records
				// template refresh is needed
				// terminate the current data flowset
				data_flowset = NULL;
				if ( (pointer_addr_t)peer->writeto + template->flowset_length > (pointer_addr_t)peer->endp ) {
					// not enough space for template flowset => flush buffer first
					record_count   = 0;
					flowset_count  = 0;
					template_count = 0;
					peer->flush = 1;
					return 1;	// return to flush buffer
				}
				memcpy(peer->writeto, (void *)template->template_flowset, template->flowset_length);
				peer->writeto = (void *)((pointer_addr_t)peer->writeto + template->flowset_length);
				template->time_sent = now;
				flowset_count++;
				template_count++;

				// open a new data flow set at this point in the output buffer
				data_flowset = (data_flowset_t *)peer->writeto;
				data_flowset->flowset_id = template->template_flowset->fields[0].template_id;
				peer->writeto = (void *)data_flowset->data;
				flowset_count++;
			} // else Add record

		} else {
			// record with different id
			// terminate the current data flowset
			data_flowset = NULL;

			last_flags 	= master_record->flags;
			template 	= GetOutputTemplate(last_flags);
			if ( now - template->time_sent > MAX_LIFETIME ) {
				// refresh template is needed
				endwrite= (void *)((pointer_addr_t)peer->writeto + template->flowset_length + sizeof(data_flowset_t));
				if ( endwrite > peer->endp ) {
					// not enough space for template flowset => flush buffer first
					record_count   = 0;
					flowset_count  = 0;
					template_count = 0;
					peer->flush = 1;
					return 1;	// return to flush the buffer
				}
				memcpy(peer->writeto, (void *)template->template_flowset, template->flowset_length);
				peer->writeto = (void *)((pointer_addr_t)peer->writeto + template->flowset_length);
				template->time_sent = now;
				flowset_count++;
				template_count++;
			}
			// open a new data flow set at this point in the output buffer
			data_flowset = (data_flowset_t *)peer->writeto;
			data_flowset->flowset_id = template->template_flowset->fields[0].template_id;
			peer->writeto = (void *)data_flowset->data;
			flowset_count++;
		}
	} else {
		// output buffer does not contain a data flowset
		peer->writeto = (void *)((pointer_addr_t)v9_output_header + (pointer_addr_t)sizeof(netflow_v9_header_t));	
		last_flags = master_record->flags;
		template = GetOutputTemplate(last_flags);
		if ( now - template->time_sent > MAX_LIFETIME ) {
			// refresh template
			endwrite= (void *)((pointer_addr_t)peer->writeto + template->flowset_length + sizeof(data_flowset_t));
			if ( endwrite > peer->endp ) {
				// this must never happen!
				fprintf(stderr, "Panic: Software error in %s line %d\n", __FILE__, __LINE__);
				fprintf(stderr, "buffer %p, writeto %p template length %lx, endbuff %p\n", 
					peer->send_buffer, peer->writeto, template->flowset_length + sizeof(data_flowset_t), peer->endp );
				exit(255);
			}
			memcpy(peer->writeto, (void *)template->template_flowset, template->flowset_length);
			peer->writeto = (void *)((pointer_addr_t)peer->writeto + template->flowset_length);
			template->time_sent = now;
			flowset_count++;
			template_count++;
		}
		// open a new data flow set at this point in the output buffer
		data_flowset = (data_flowset_t *)peer->writeto;
		data_flowset->flowset_id = template->template_flowset->fields[0].template_id;
		peer->writeto = (void *)data_flowset->data;
		flowset_count++;
	}
	// now add the record

	required_size = template->record_length;

	endwrite = (void *)((pointer_addr_t)peer->writeto + required_size);
	if ( endwrite > peer->endp ) {
		uint16_t length = (pointer_addr_t)peer->writeto - (pointer_addr_t)data_flowset;
		// flush the buffer
		data_flowset->length = htons(length);
		if ( length == 4 ) {	// empty flowset
			peer->writeto = (void *)data_flowset;
		} 
		data_flowset = NULL;
		v9_output_header->count = htons(record_count+template_count);
		record_count   = 0;
		template_count = 0;
		flowset_count  = 0;
		peer->flush    = 1;
		return 1;	// return to flush buffer
	}

	// this was a long way up to here, now we can add the data

  	master_record->input	= htons(master_record->input);
  	master_record->output	= htons(master_record->output);

	t1 	= (uint32_t)(1000LL * (uint64_t)master_record->first + master_record->msec_first - boot_time);
	t2	= (uint32_t)(1000LL * (uint64_t)master_record->last  + master_record->msec_last - boot_time);
  	master_record->first	= htonl(t1);
  	master_record->last		= htonl(t2);

  	master_record->srcport	= htons(master_record->srcport);
  	master_record->dstport	= htons(master_record->dstport);
  	master_record->srcas	= htons(master_record->srcas);
  	master_record->dstas	= htons(master_record->dstas);

	memcpy(peer->writeto, (void *)&master_record->first,common_block_size);
	peer->writeto = (void *)((pointer_addr_t)peer->writeto + common_block_size);

	if ((master_record->flags & FLAG_IPV6_ADDR) != 0 ) { // IPv6
		master_record->v6.srcaddr[0] = htonll(master_record->v6.srcaddr[0]);
		master_record->v6.srcaddr[1] = htonll(master_record->v6.srcaddr[1]);
		master_record->v6.dstaddr[0] = htonll(master_record->v6.dstaddr[0]);
		master_record->v6.dstaddr[1] = htonll(master_record->v6.dstaddr[1]);
		memcpy(peer->writeto, master_record->v6.srcaddr, sizeof(ipv6_block_t));
		peer->writeto = (void *)((pointer_addr_t)peer->writeto + sizeof(ipv6_block_t));
	} else {
		uint32_t	*addr = (uint32_t *)peer->writeto;
		addr[0]	= htonl(master_record->v4.srcaddr);
		addr[1]	= htonl(master_record->v4.dstaddr);
		peer->writeto = (void *)((pointer_addr_t)peer->writeto + 2*sizeof(uint32_t));
	}

	if ((master_record->flags & FLAG_PKG_64) != 0 ) { // 64bit counters
		/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
		uint32_t	*outbuffer = (uint32_t *)peer->writeto;
		value64_t	v;

		v.val.val64 = htonll(master_record->dPkts);
		outbuffer[0]	= v.val.val32[0];
		outbuffer[1]	= v.val.val32[1];
		peer->writeto = (void *)((pointer_addr_t)peer->writeto + sizeof(uint64_t));
	} else {
		uint32_t	*v = (uint32_t *)peer->writeto;
		*v = htonl(master_record->dPkts);
		peer->writeto = (void *)((pointer_addr_t)peer->writeto + sizeof(uint32_t));
	}

	if ((master_record->flags & FLAG_BYTES_64) != 0 ) { // 64bit counters
		/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
		uint32_t	*outbuffer = (uint32_t *)peer->writeto;
		value64_t	v;

		v.val.val64 = htonll(master_record->dOctets);
		outbuffer[0]	= v.val.val32[0];
		outbuffer[1]	= v.val.val32[1];
		peer->writeto = (void *)((pointer_addr_t)peer->writeto + sizeof(uint64_t));
	} else {
		uint32_t	*v = (uint32_t *)peer->writeto;
		*v = htonl(master_record->dOctets);
		peer->writeto = (void *)((pointer_addr_t)peer->writeto + sizeof(uint32_t));
	}

	data_flowset->length = htons((pointer_addr_t)peer->writeto - (pointer_addr_t)data_flowset);
	record_count++;
	v9_output_header->count = htons(record_count+template_count);

	return 0;

} // End of Add_v9_output_record

