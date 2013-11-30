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
 *  $Id: nfdump.h 84 2007-01-09 09:22:50Z peter $
 *
 *  $LastChangedRevision: 84 $
 *	
 */

#define BuffNumRecords	1024

/* 
 * Offset definitions for filter engine. Offsets must agree with the defined
 * flow record definition data_block_record_t in nffile.h
 */

#include "config.h"

typedef struct FilterParam {
	uint32_t	scale;
	uint16_t	comp;
	uint16_t	direction;
	uint16_t	proto;
	uint32_t	data;
	uint64_t	ip[2];
	uint32_t	netmask;
	uint32_t	netbits;
	uint32_t	self;
} FilterParam_t;

/* IP tree type */
typedef RB_HEAD(IPtree, ListNode) IPlist_t;

/* parser/scanner prototypes */
int yyparse(void);

int yylex(void);

void lex_cleanup(void);

void lex_init(char *buf);

// Insert the RB prototypes here
RB_PROTOTYPE(IPtree, ListNode, entry, NodeCMP);

