
/*
 *  nfprofile : Reads netflow data from files, saved by nfcapd
 *              Data can be view, filtered and saved to 
 *              files.
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
 *  $Id: profile.h 2 2004-09-20 18:12:36Z peter $
 *
 *  $LastChangedRevision: 2 $
 *      
*/

typedef struct profileinfo_s {
	FilterEngine_data_t	*engine;
	char		*name;
	char		*wfile;
	uint64_t	numflows, numbytes, numpackets;
	uint32_t	first_seen, last_seen;
	uint64_t	numflows_tcp, numflows_udp, numflows_icmp, numflows_other;
	uint64_t	numbytes_tcp, numbytes_udp, numbytes_icmp, numbytes_other;
	uint64_t	numpackets_tcp, numpackets_udp, numpackets_icmp, numpackets_other;
	short		*ftrue;
	uint16_t	cnt;
	int			wfd;
} profileinfo_t;

profileinfo_t	*GetProfiles(void);

int InitProfiles(char *profiledir, char *subdir, char *filterfile, char *filename, int veryfy_only );

void CloseProfiles (void);
