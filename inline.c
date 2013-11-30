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
 *  $Author: haag $
 *
 *  $Id: inline.c 9 2009-05-07 08:59:31Z haag $
 *
 *  $LastChangedRevision: 9 $
 *	
 */

static uint16_t	Get_val16(void *p);

static uint32_t	Get_val24(void *p);

static uint32_t	Get_val32(void *p);

static uint64_t	Get_val40(void *p);

static uint64_t	Get_val48(void *p);

static uint64_t	Get_val56(void *p);

static uint64_t	Get_val64(void *p);

static uint16_t	Get_val16(void *p) {
uint8_t		*in = (uint8_t *)p;
type_mask_t mask;

	mask.val.val8[0] = in[0];
	mask.val.val8[1] = in[1];
	return mask.val.val16[0];

} // End of Get_val16

static uint32_t	Get_val24(void *p) {
uint8_t		*in = (uint8_t *)p;
type_mask_t mask;

	mask.val.val8[0] = 0;
	mask.val.val8[1] = in[0];
	mask.val.val8[2] = in[1];
	mask.val.val8[3] = in[2];
	return mask.val.val32[0];

} // End of Get_val24

static uint32_t	Get_val32(void *p) {
uint8_t		*in = (uint8_t *)p;
type_mask_t mask;

	mask.val.val8[0] = in[0];
	mask.val.val8[1] = in[1];
	mask.val.val8[2] = in[2];
	mask.val.val8[3] = in[3];
	return mask.val.val32[0];

} // End of Get_val32

static uint64_t	Get_val64(void *p) {
uint8_t		*in = (uint8_t *)p;
type_mask_t mask;

	mask.val.val8[0] = in[0];
	mask.val.val8[1] = in[1];
	mask.val.val8[2] = in[2];
	mask.val.val8[3] = in[3];
	mask.val.val8[4] = in[4];
	mask.val.val8[5] = in[5];
	mask.val.val8[6] = in[6];
	mask.val.val8[7] = in[7];
	return mask.val.val64;

} // End of Get_val64

static uint64_t	Get_val40(void *p) {
uint8_t		*in = (uint8_t *)p;
type_mask_t mask;

	mask.val.val8[0] = 0;
	mask.val.val8[1] = 0;
	mask.val.val8[2] = 0;
	mask.val.val8[3] = in[0];
	mask.val.val8[4] = in[1];
	mask.val.val8[5] = in[2];
	mask.val.val8[6] = in[3];
	mask.val.val8[7] = in[4];
	return mask.val.val64;

} // End of Get_val40

static uint64_t	Get_val48(void *p) {
uint8_t		*in = (uint8_t *)p;
type_mask_t mask;

	mask.val.val8[0] = 0;
	mask.val.val8[1] = 0;
	mask.val.val8[2] = in[0];
	mask.val.val8[3] = in[1];
	mask.val.val8[4] = in[2];
	mask.val.val8[5] = in[3];
	mask.val.val8[6] = in[4];
	mask.val.val8[7] = in[5];
	return mask.val.val64;

} // End of Get_val48

static uint64_t	Get_val56(void *p) {
uint8_t		*in = (uint8_t *)p;
type_mask_t mask;

	mask.val.val8[0] = 0;
	mask.val.val8[1] = in[0];
	mask.val.val8[2] = in[1];
	mask.val.val8[3] = in[2];
	mask.val.val8[4] = in[3];
	mask.val.val8[5] = in[4];
	mask.val.val8[6] = in[5];
	mask.val.val8[7] = in[6];
	return mask.val.val64;

} // End of Get_val56

