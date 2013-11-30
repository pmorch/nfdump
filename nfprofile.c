/*
 *  nfprofile : Reads netflow data from files, saved by nfcapd
 *  		 	Data can be view, filtered and saved to 
 *  		 	files.
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
 *  $Id: nfprofile.c 55 2006-01-13 10:04:34Z peter $
 *
 *  $LastChangedRevision: 55 $
 *	
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif


#include "version.h"
#include "nf_common.h"
#include "nftree.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfstat.h"
#include "util.h"
#include "profile.h"

/* Global Variables */
uint32_t	byte_limit, packet_limit;
int 		byte_mode, packet_mode;

/* Local Variables */
static char const *rcsid 		  = "$Id: nfprofile.c 55 2006-01-13 10:04:34Z peter $";

/* Function Prototypes */
static void usage(char *name);

static void process_data(profile_channel_info_t *profiles, unsigned int num_profiles, time_t twin_start, time_t twin_end, int zero_flows);


/* Functions */
static void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here\n"
					"-V\t\tPrint version and exit.\n"
					"-M <expr>\tRead input from multiple directories.\n"
					"-r\t\tread input from file\n"
					"-f\t\tfilename with filter syntaxfile\n"
					"-p\t\tprofile dir.\n"
					"-s\t\tprofile subdir.\n"
					"-Z\t\tCheck filter syntax and exit.\n"
					"-q\t\tSuppress profile working info\n"
					"-z\t\tZero flows - dumpfile contains only statistics record.\n"
					"-t <time>\ttime window for filtering packets\n"
					"\t\tyyyy/MM/dd.hh:mm:ss[-yyyy/MM/dd.hh:mm:ss]\n", name);
} /* usage */

static void process_data(profile_channel_info_t *profiles, unsigned int num_profiles, time_t twin_start, time_t twin_end, int zero_flows) {
data_block_header_t in_flow_header;					
common_record_t 		*flow_record, *in_buff;
master_record_t		master_record;
FilterEngine_data_t	*engine;
uint32_t	NumRecords, buffer_size;
int 		i, j, rfd, done, ret ;

#ifdef COMPAT14
extern int	Format14;
#endif

	rfd = GetNextFile(0, twin_start, twin_end, NULL);
	if ( rfd < 0 ) {
		if ( rfd == FILE_ERROR )
			fprintf(stderr, "Can't open file for reading: %s\n", strerror(errno));
		return;
	}

#ifdef COMPAT14
	if ( Format14 ) {
		fprintf(stderr, "nfprofile does not support nfdump <= v1.4 old style file format!\n");
		return;
	}
#endif

	// allocate buffer suitable for netflow version
	buffer_size = BUFFSIZE;
	in_buff = (common_record_t *) malloc(buffer_size);
	if ( !in_buff ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(rfd);
		return;
	}

	for ( j=0; j < num_profiles; j++ ) {
		profiles[j].stat_record.first_seen 	= 0x7fffffff;
		profiles[j].stat_record.last_seen  	= 0;
		profiles[j].flow_header 			= (data_block_header_t *)malloc(OUTPUT_BUFF_SIZE);
		if ( !profiles[j].flow_header ) {
			fprintf(stderr, "Buffer allocation error: %s", strerror(errno));
			return;
		}
		profiles[j].flow_header->size 		= 0;
		profiles[j].flow_header->NumBlocks 	= 0;
		profiles[j].flow_header->pad 		= 0;
		profiles[j].flow_header->id	  	 	= DATA_BLOCK_TYPE_1;
		profiles[j].writeto 				= (void *)((pointer_addr_t)profiles[j].flow_header + sizeof(data_block_header_t));

		(profiles[j].engine)->nfrecord 		= (uint64_t *)&master_record;
	}

	done = 0;
	while ( !done ) {
		ret = read(rfd, &in_flow_header, sizeof(data_block_header_t));
		if ( ret == 0 ) {
			// EOF of rfd
			rfd = GetNextFile(rfd, twin_start, twin_end, NULL);
			if ( rfd < 0 ) {
				if ( rfd == FILE_ERROR )
					fprintf(stderr, "Can't read from file '%s': %s\n",GetCurrentFilename(), strerror(errno) );
				done = 1;
			} 
			continue;

		} else if ( ret == -1 ) {
			fprintf(stderr, "Can't read from file '%s': %s\n",GetCurrentFilename(), strerror(errno) );
			close(rfd);
			return;
		}

		if ( in_flow_header.id != DATA_BLOCK_TYPE_1 ) {
			fprintf(stderr, "Can't process block type %u\n", in_flow_header.id);
			continue;
		}

		NumRecords = in_flow_header.NumBlocks;

		if ( in_flow_header.size > buffer_size ) {
			void *tmp;
			// Actually, this should never happen, but catch it anyway
			if ( in_flow_header.size > MAX_BUFFER_SIZE ) {
				// this is most likely corrupt
				fprintf(stderr, "Corrupt data file: Requested buffer size %u exceeds max. buffer size.\n", in_flow_header.size);
				break;
			}
			// make it at least the requested size
			buffer_size = in_flow_header.size;
			tmp = realloc((void *)in_buff, buffer_size);
			if ( !tmp ) {
				fprintf(stderr, "Can't reallocate buffer to %u bytes: %s\n", buffer_size, strerror(errno));
				break;
			}
			in_buff = (common_record_t *)tmp;
		}
		ret = read(rfd, in_buff, in_flow_header.size );
		if ( ret == 0 ) {
			done = 1;
			break;
		} else if ( ret == -1 ) {
			fprintf(stderr, "Can't read from file '%s': %s\n",GetCurrentFilename(), strerror(errno) );
			close(rfd);
			return;
		}


		flow_record = in_buff;
		for ( i=0; i < NumRecords; i++ ) {
			ExpandRecord( flow_record, &master_record);

			// Time filter
			// if no time filter is given, the result is always true
			flow_record->mark = twin_start && (flow_record->first < twin_start || flow_record->last > twin_end) ? 0 : 1;

			// if outside given time window 
			if ( !flow_record->mark ) {
				flow_record = (void *)((pointer_addr_t)flow_record + flow_record->size);
				continue;
			}

			for ( j=0; j < num_profiles; j++ ) {

				// apply profile filter
				engine = profiles[j].engine;
				flow_record->mark = (*engine->FilterEngine)(engine);

				// if profile filter failed -> next profile
				if ( !flow_record->mark )
					continue;

				// filter was successful -> continue record processing
				flow_record->mark = 0;

				if ( (profiles[j].flow_header->size + flow_record->size) > OUTPUT_BUFF_SIZE ) {
					// this should really never happen
					fprintf(stderr, "Record size overflow in %s line %d: skip record.\n", __FILE__, __LINE__);
					continue;
				}

				// update statistics
				switch (master_record.prot) {
					case 1:
						profiles[j].stat_record.numflows_icmp++;
						profiles[j].stat_record.numpackets_icmp += master_record.dPkts;
						profiles[j].stat_record.numbytes_icmp   += master_record.dOctets;
						break;
					case 6:
						profiles[j].stat_record.numflows_tcp++;
						profiles[j].stat_record.numpackets_tcp += master_record.dPkts;
						profiles[j].stat_record.numbytes_tcp   += master_record.dOctets;
						break;
					case 17:
						profiles[j].stat_record.numflows_udp++;
						profiles[j].stat_record.numpackets_udp += master_record.dPkts;
						profiles[j].stat_record.numbytes_udp   += master_record.dOctets;
						break;
					default:
						profiles[j].stat_record.numflows_other++;
						profiles[j].stat_record.numpackets_other += master_record.dPkts;
						profiles[j].stat_record.numbytes_other   += master_record.dOctets;
				}
				profiles[j].stat_record.numflows++;
				profiles[j].stat_record.numpackets 	+= master_record.dPkts;
				profiles[j].stat_record.numbytes 	+= master_record.dOctets;

				if ( master_record.first < profiles[j].stat_record.first_seen ) {
					profiles[j].stat_record.first_seen = master_record.first;
					profiles[j].stat_record.msec_first = master_record.msec_first;
				}
				if ( master_record.first == profiles[j].stat_record.first_seen && 
				 	master_record.msec_first < profiles[j].stat_record.msec_first ) 
						profiles[j].stat_record.msec_first = master_record.msec_first;
	
				if ( master_record.last > profiles[j].stat_record.last_seen ) {
					profiles[j].stat_record.last_seen = master_record.last;
					profiles[j].stat_record.msec_last = master_record.msec_last;
				}
				if ( master_record.last == profiles[j].stat_record.last_seen && 
				 	master_record.msec_last > profiles[j].stat_record.msec_last ) 
						profiles[j].stat_record.msec_last = master_record.msec_last;

				// write record to output buffer
				memcpy(profiles[j].writeto, (void *)flow_record, flow_record->size);
				profiles[j].flow_header->NumBlocks++;
				profiles[j].flow_header->size += flow_record->size;
				profiles[j].writeto = (void *)((pointer_addr_t)profiles[j].writeto + flow_record->size);

				// check if we need to flush the output buffer
				if ( (profiles[j].flow_header->size + flow_record->size) > OUTPUT_FLUSH_LIMIT && !zero_flows) {
					if ( write(profiles[j].wfd, (void *)profiles[j].flow_header, 
							sizeof(data_block_header_t) + profiles[j].flow_header->size) <= 0 ) {
						fprintf(stderr, "Failed to write output buffer to disk: '%s'" , strerror(errno));
					} else {
						profiles[j].flow_header->size 		= 0;
						profiles[j].flow_header->NumBlocks 	= 0;
						profiles[j].writeto = (void *)((pointer_addr_t)profiles[j].flow_header + sizeof(data_block_header_t));
						profiles[j].file_blocks++;
					}
				} 

			} // End of for all profiles

			flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);

		} // End of for all NumRecords
	} // End of while !done

	for ( j=0; j < num_profiles; j++ ) {
		// flush output buffer
		if ( profiles[j].flow_header->NumBlocks && !zero_flows) {
			if ( write(profiles[j].wfd, (void *)profiles[j].flow_header, 
					sizeof(data_block_header_t) + profiles[j].flow_header->size) <= 0 ) {
				fprintf(stderr, "Failed to write output buffer to disk: '%s'" , strerror(errno));
			} else {
				free((void *)profiles[j].flow_header);
				profiles[j].writeto = NULL;
				profiles[j].file_blocks++;
			}
		} 
	}
	free((void *)in_buff);

} // End of process_data


int main( int argc, char **argv ) {
unsigned int		num_profiles, quiet, zero_flows;
struct stat stat_buf;
char c, *rfile, *ffile, *filename, *Mdirs, *tstring, *profiledir, *subdir;
int syntax_only;
time_t t_start, t_end;

	tstring = NULL;
	profiledir = subdir = Mdirs = NULL;
	t_start = t_end = 0;
	syntax_only	    = 0;
	quiet			= 0;
	zero_flows		= 0;

	// default file names
	ffile = "filter.txt";
	rfile = NULL;
	while ((c = getopt(argc, argv, "p:s:hf:r:M:Zt:Vqz")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'Z':
				syntax_only = 1;
				break;
			case 'p':
				profiledir = optarg;
				break;
			case 's':
				subdir = optarg;
				break;
			case 'V':
				printf("%s: Version: %s %s\n%s\n",argv[0], nfdump_version, nfdump_date, rcsid);
				exit(0);
				break;
			case 'f':
				ffile = optarg;
				break;
			case 't':
				tstring = optarg;
				break;
			case 'M':
				Mdirs = optarg;
				break;
			case 'r':
				rfile = optarg;
				break;
			case 'q':
				quiet = 1;
				break;
			case 'z':
				zero_flows = 1;
				break;
			default:
				usage(argv[0]);
				exit(0);
		}
	}


	if ( !profiledir ) {
		fprintf(stderr, "Profile directory required!\n");
		exit(255);
	}

	SetLimits(0,NULL, NULL);

	if ( stat(profiledir, &stat_buf) || !S_ISDIR(stat_buf.st_mode) ) {
		fprintf(stderr, "'%s' not a directory\n", profiledir);
		exit(255);
	}

	if ( syntax_only ) {
		filename = NULL;
		rfile = NULL;
	} else {
		char *p;
		p = strrchr(rfile, '/');
		filename = p == NULL ? rfile : ++p;
		if ( strlen(filename) == 0 ) {
			fprintf(stderr, "Filename error");
			exit(254);
		}
	} 

	num_profiles = InitProfiles(profiledir, subdir, ffile, filename, syntax_only, quiet);

	if ( !num_profiles ) 
		exit(254);

	if ( syntax_only )
		exit(0);

	if ( !rfile ) {
		fprintf(stderr, "Input file (-r) required!\n");
		exit(255);
	}

	SetupInputFileSequence(Mdirs,rfile, NULL);

	if ( tstring ) {
		if ( !ScanTimeFrame(tstring, &t_start, &t_end) )
			exit(255);
	}

	process_data(GetProfiles(), num_profiles, t_start, t_end, zero_flows);

	CloseProfiles();

	return 0;
}
