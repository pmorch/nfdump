
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
 *  $Id: nfdump.h 5 2004-11-29 15:50:44Z peter $
 *
 *  $LastChangedRevision: 5 $
 *	
 */

#define BuffNumRecords	1024

/* 
 * Defines for offsets into netflow record 
 */

#include "config.h"

#ifdef WORDS_BIGENDIAN

#define OffsetSrcIP 0
#define OffsetDstIP 1
#define OffsetNext	2
#define MaskIP  	(uint32_t)0xffffffff

#define OffsetInOut 3
#define MaskInput	(uint32_t)0xffff0000
#define MaskOutput	(uint32_t)0x0000ffff
#define ShiftInput 	16
#define ShiftOutput	0

#define OffsetPackets 4
#define OffsetBytes	  5
#define MaskSize  	(uint32_t)0xffffffff

#define OffsetPort 	8
#define MaskDstPort (uint32_t)0x0000ffff
#define MaskSrcPort (uint32_t)0xffff0000
#define ShiftDstPort 0
#define ShiftSrcPort 16

#define OffsetTos	9
#define MaskTos	   	(uint32_t)0x000000ff
#define ShiftTos  	0

#define OffsetProto 9
#define MaskProto   (uint32_t)0x0000ff00
#define ShiftProto  8

#define OffsetFlags 9
#define MaskFlags   (uint32_t)0x00ff0000
#define ShiftFlags  16

#define OffsetAS 	10
#define MaskDstAS 	(uint32_t)0x0000ffff
#define MaskSrcAS 	(uint32_t)0xffff0000
#define ShiftSrcAS 	16
#define ShiftDstAS 	0

#else

#define OffsetSrcIP 0
#define OffsetDstIP 1
#define OffsetNext	2
#define MaskIP		(uint32_t)0xffffffff

#define OffsetInOut	3
#define MaskInput 	(uint32_t)0x0000ffff
#define MaskOutput 	(uint32_t)0xffff0000
#define ShiftInput 	0
#define ShiftOutput	16

#define OffsetPackets 4
#define OffsetBytes	  5
#define MaskSize  	(uint32_t)0xffffffff

#define OffsetTos	9
#define MaskTos		(uint32_t)0xff000000
#define ShiftTos	24

#define OffsetProto	9
#define MaskProto	(uint32_t)0x00ff0000
#define ShiftProto	16

#define OffsetFlags	9
#define MaskFlags	(uint32_t)0x0000ff00
#define ShiftFlags	8

#define OffsetPort 	8
#define MaskDstPort (uint32_t)0xffff0000
#define MaskSrcPort (uint32_t)0x0000ffff
#define ShiftSrcPort 0
#define ShiftDstPort 16

#define OffsetAS 	10
#define MaskDstAS 	(uint32_t)0xffff0000
#define MaskSrcAS 	(uint32_t)0x0000ffff
#define ShiftSrcAS 	0
#define ShiftDstAS 	16

#endif

typedef struct FilterParam {
	uint16_t	comp;
	uint16_t	direction;
	uint16_t	proto;
	uint32_t	data;
	uint32_t	ip;
	uint32_t	netmask;
	uint32_t	netbits;
	uint32_t	self;
} FilterParam_t;


/* parser/scanner prototypes */
int yyparse(void);

int yylex(void);

void lex_cleanup(void);

void lex_init(char *buf);

