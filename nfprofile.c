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
 *  $Author: haag $
 *
 *  $Id: nfprofile.c 9 2009-05-07 08:59:31Z haag $
 *
 *  $LastChangedRevision: 9 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "version.h"
#include "nf_common.h"
#include "rbtree.h"
#include "nftree.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfstat.h"
#include "nfstatfile.h"
#include "ipconv.h"
#include "flist.h"
#include "util.h"
#include "profile.h"

/* Local Variables */
static char const *rcsid 		  = "$Id: nfprofile.c 9 2009-05-07 08:59:31Z haag $";

/* exported fuctions */
void LogError(char *format, ...);

/* Function Prototypes */
static void usage(char *name);

static profile_param_info_t *ParseParams (char *profile_datadir);

static void process_data(profile_channel_info_t *channels, unsigned int num_channels, time_t tslot, int compress);


/* Functions */
static void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here\n"
					"-V\t\tPrint version and exit.\n"
					"-D <dns>\tUse nameserver <dns> for host lookup.\n"
					"-M <expr>\tRead input from multiple directories.\n"
					"-r\t\tread input from file\n"
					"-f\t\tfilename with filter syntaxfile\n"
					"-p\t\tprofile data dir.\n"
					"-P\t\tprofile stat dir.\n"
					"-s\t\tprofile subdir.\n"
					"-Z\t\tCheck filter syntax and exit.\n"
					"-S subdir\tSub directory format. see nfcapd(1) for format\n"
					"-z\t\tCompress flows in output file.\n"
					"-t <time>\ttime for RRD update\n", name);
} /* usage */

/* 
 * some modules are needed for daemon code as well as normal stdio code 
 * therefore a generic LogError is defined, which maps in this case
 * to stderr
 */
void LogError(char *format, ...) {
va_list var_args;

	va_start(var_args, format);
	vfprintf(stderr, format, var_args);
	va_end(var_args);

} // End of LogError


static void process_data(profile_channel_info_t *channels, unsigned int num_channels, time_t tslot, int compress) {
data_block_header_t in_block_header;					
common_record_t 	*flow_record, *in_buff;
master_record_t		master_record;
FilterEngine_data_t	*engine;
int 		i, j, rfd, done, ret ;
char		*string;

#ifdef COMPAT14
extern int	Format14;
#endif

	rfd = GetNextFile(0, 0, 0, NULL);
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
	in_buff = (common_record_t *) malloc(BUFFSIZE);
	if ( !in_buff ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		close(rfd);
		return;
	}

	for ( j=0; j < num_channels; j++ ) {
		channels[j].stat_record.first_seen 	= 0x7fffffff;
		channels[j].stat_record.last_seen  	= 0;
		if ( channels[j].wfd > 0 ) {
			channels[j].flow_header 			= (data_block_header_t *)malloc(BUFFSIZE);
			if ( !channels[j].flow_header ) {
				fprintf(stderr, "Buffer allocation error: %s", strerror(errno));
				return;
			}
			channels[j].writeto 				= (void *)((pointer_addr_t)channels[j].flow_header + sizeof(data_block_header_t));
			channels[j].flow_header->size 		= 0;
			channels[j].flow_header->NumBlocks 	= 0;
			channels[j].flow_header->pad 		= 0;
			channels[j].flow_header->id	  	 	= DATA_BLOCK_TYPE_1;
		}

		(channels[j].engine)->nfrecord 		= (uint64_t *)&master_record;
	}

	done = 0;
	while ( !done ) {

		// get next data block from file
		ret = ReadBlock(rfd, &in_block_header, (void *)in_buff, &string);

		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				if ( ret == NF_CORRUPT ) 
					fprintf(stderr, "Skip corrupt data file '%s': '%s'\n",GetCurrentFilename(), string);
				else 
					fprintf(stderr, "Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );
				// fall through - get next file in chain
			case NF_EOF:
				rfd = GetNextFile(rfd, 0, 0, NULL);
				if ( rfd < 0 ) {
					if ( rfd == NF_ERROR )
						fprintf(stderr, "Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );

					// rfd == EMPTY_LIST
					done = 1;
				} // else continue with next file
				continue;
	
				break; // not really needed
		}

		if ( in_block_header.id != DATA_BLOCK_TYPE_1 ) {
			fprintf(stderr, "Can't process block type %u. Skip block.\n", in_block_header.id);
			continue;
		}

		flow_record = in_buff;
		for ( i=0; i < in_block_header.NumBlocks; i++ ) {
			ExpandRecord( flow_record, &master_record);

			// Time filter
			// if no time filter is given, the result is always true
			flow_record->mark = 1;

			// if outside given time window 
			if ( !flow_record->mark ) {
				flow_record = (void *)((pointer_addr_t)flow_record + flow_record->size);
				continue;
			}

			for ( j=0; j < num_channels; j++ ) {

				// apply profile filter
				engine = channels[j].engine;
				flow_record->mark = (*engine->FilterEngine)(engine);

				// if profile filter failed -> next profile
				if ( !flow_record->mark )
					continue;

				// filter was successful -> continue record processing
				flow_record->mark = 0;

				if ( channels[j].wfd && ((channels[j].flow_header->size + flow_record->size) > BUFFSIZE) ) {
					// this should really never happen
					fprintf(stderr, "Record size overflow in %s line %d: skip record.\n", __FILE__, __LINE__);
					continue;
				}

				// update statistics
				switch (master_record.prot) {
					case 1:
						channels[j].stat_record.numflows_icmp++;
						channels[j].stat_record.numpackets_icmp += master_record.dPkts;
						channels[j].stat_record.numbytes_icmp   += master_record.dOctets;
						break;
					case 6:
						channels[j].stat_record.numflows_tcp++;
						channels[j].stat_record.numpackets_tcp += master_record.dPkts;
						channels[j].stat_record.numbytes_tcp   += master_record.dOctets;
						break;
					case 17:
						channels[j].stat_record.numflows_udp++;
						channels[j].stat_record.numpackets_udp += master_record.dPkts;
						channels[j].stat_record.numbytes_udp   += master_record.dOctets;
						break;
					default:
						channels[j].stat_record.numflows_other++;
						channels[j].stat_record.numpackets_other += master_record.dPkts;
						channels[j].stat_record.numbytes_other   += master_record.dOctets;
				}
				channels[j].stat_record.numflows++;
				channels[j].stat_record.numpackets 	+= master_record.dPkts;
				channels[j].stat_record.numbytes 	+= master_record.dOctets;

				if ( master_record.first < channels[j].stat_record.first_seen ) {
					channels[j].stat_record.first_seen = master_record.first;
					channels[j].stat_record.msec_first = master_record.msec_first;
				}
				if ( master_record.first == channels[j].stat_record.first_seen && 
				 	master_record.msec_first < channels[j].stat_record.msec_first ) 
						channels[j].stat_record.msec_first = master_record.msec_first;
	
				if ( master_record.last > channels[j].stat_record.last_seen ) {
					channels[j].stat_record.last_seen = master_record.last;
					channels[j].stat_record.msec_last = master_record.msec_last;
				}
				if ( master_record.last == channels[j].stat_record.last_seen && 
				 	master_record.msec_last > channels[j].stat_record.msec_last ) 
						channels[j].stat_record.msec_last = master_record.msec_last;

				// do we need to write data to new file - shadow profiles do not have files.
				// check if we need to flush the output buffer
				if ( channels[j].wfd > 0 ) {
					// write record to output buffer
					memcpy(channels[j].writeto, (void *)flow_record, flow_record->size);
					channels[j].flow_header->NumBlocks++;
					channels[j].flow_header->size += flow_record->size;
					channels[j].writeto = (void *)((pointer_addr_t)channels[j].writeto + flow_record->size);
	
					if ( (channels[j].flow_header->size + flow_record->size) > OUTPUT_FLUSH_LIMIT ) {
						if ( WriteBlock(channels[j].wfd, channels[j].flow_header, compress) <= 0 ) {
							fprintf(stderr, "Failed to write output buffer to disk: '%s'" , strerror(errno));
						} else {
							channels[j].flow_header->size 		= 0;
							channels[j].flow_header->NumBlocks 	= 0;
							channels[j].writeto = (void *)((pointer_addr_t)channels[j].flow_header + sizeof(data_block_header_t));
							channels[j].file_blocks++;
						}
					} 
				} 

			} // End of for all channels

			flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);

		} // End of for all NumRecords
	} // End of while !done

	// do we need to write data to new file - shadow profiles do not have files.
	for ( j=0; j < num_channels; j++ ) {
		if ( channels[j].wfd > 0 ) {
			// flush output buffer
			if ( channels[j].flow_header->NumBlocks ) {
				if ( WriteBlock(channels[j].wfd, channels[j].flow_header, compress) <= 0 ) {
					fprintf(stderr, "Failed to write output buffer to disk: '%s'" , strerror(errno));
				} else {
					free((void *)channels[j].flow_header);
					channels[j].writeto = NULL;
					channels[j].file_blocks++;
				}
			} 
		}
	}
	free((void *)in_buff);

} // End of process_data

static profile_param_info_t *ParseParams (char *profile_datadir) {
struct stat stat_buf;
char line[512], path[MAXPATHLEN], *p, *q, *s;
profile_param_info_t *profile_list;
profile_param_info_t **list = &profile_list;

	profile_list = NULL;
	while ( ( fgets(line, 512, stdin) != NULL )) {
printf("Process line '%s'\n", line);
		line[511] = '\0';

		if ( *list == NULL ) 
			*list = (profile_param_info_t *)malloc(sizeof(profile_param_info_t));
		// else we come from a continue statement with illegal data - overwrite

		if ( !*list) {
			fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			return NULL;
		}

		(*list)->next 		  = NULL;
		(*list)->profilegroup = NULL;
		(*list)->profilename  = NULL;
		(*list)->channelname  = NULL;
		(*list)->channel_sourcelist = NULL;
		(*list)->profiletype  = 0;

		// delete '\n' at the end of line
		// format of stdin config line:
		// <profilegroup>#<profilename>#<profiletype>#<channelname>#<channel_sourcelist>
		p = strchr(line, '\n');
		if ( p ) *p = '\0';

		q = line;
		p = strchr(q, '#');
		if ( p ) 
			*p = '\0';

		s = line;

		// savety check: if no separator found loop to next line
		if ( !p ) {
			fprintf(stderr, "Incomplete line - channel skipped.\n");
			continue;
		}

		q = p;
		q++;

		p = strchr(q, '#');
		if ( p ) 
			*p = '\0';

		snprintf(path, MAXPATHLEN-1, "%s/%s/%s", profile_datadir, s, q);
		path[MAXPATHLEN-1] = '\0';
		if ( stat(path, &stat_buf) || !S_ISDIR(stat_buf.st_mode) ) {
			fprintf(stderr, "profile '%s' not found in group %s. Skipped.\n", q, s);
			continue;
		}

		(*list)->profilegroup = strdup(s);
		(*list)->profilename  = strdup(q);

		// savety check: if no separator found loop to next line
		if ( !p ) {
			fprintf(stderr, "Incomplete line - channel skipped.\n");
			continue;
		}

		q = p;
		q++;

		p = strchr(q, '#');
		if ( p ) 
			*p = '\0';

		s = q;
		while ( *s ) {
			if ( *s < '0' || *s > '9' ) {
				fprintf(stderr, "Not a valid number: %s\n", q);
				s = NULL;
				break;
			}
			s++;
		}
		if ( s == NULL )
			continue;

		(*list)->profiletype = (int)strtol(q, (char **)NULL, 10);

		// savety check: if no separator found loop to next line
		if ( !p ) {
			fprintf(stderr, "Incomplete line - channel skipped.\n");
			continue;
		}

		q = p;
		q++;

		p = strchr(q, '#');
		if ( p ) 
			*p = '\0';

		snprintf(path, MAXPATHLEN-1, "%s/%s/%s/%s", profile_datadir, (*list)->profilegroup, (*list)->profilename, q);
		path[MAXPATHLEN-1] = '\0';
		if ( stat(path, &stat_buf) || !S_ISDIR(stat_buf.st_mode) ) {
			fprintf(stderr, "channel '%s' in profile '%s' not found. Skipped.\n", q, (*list)->profilename);
			continue;
		}

		(*list)->channelname = strdup(q);

		if ( !p ) {
			fprintf(stderr, "Incomplete line - Skipped.\n");
			continue;
		}

		q = p;
		q++;

		p = strchr(q, '#');
		if ( p ) 
			*p = '\0';

		// Skip leading '| chars
		while ( *q && *q == '|' ) {
			q++;
		}
		s = q;

		// if q is already empty ( '\0' ) loop is not processed
		while ( *s ) {
			// as s[0] is not '\0' s[1] may be '\0' but still valid and in range
			if ( s[0] == '|' && s[1] == '|' ) {
				char *t = s;
				t++;
				while ( *t ) {	// delete this empty channel name
					t[0] = t[1];
					t++;
				}
			} else
				s++;
		}
		// we have no doublicate '|' here any more
		// check if last char is an extra '|' 
		if ( *q && (q[strlen(q)-1] == '|') )
			q[strlen(q)-1] = '\0';

		if ( *q && (strcmp(q, "*") != 0) ) 
			(*list)->channel_sourcelist = strdup(q);

		list = &((*list)->next);
	}

	if ( *list != NULL ) {
		free(*list);
		*list = NULL;
	}

	if ( ferror(stdin) ) {
		fprintf(stderr, "fgets() error: %s", strerror(errno));
		return NULL;
	}

	return profile_list;

} // End of ParseParams

int main( int argc, char **argv ) {
unsigned int		num_channels, compress;
struct stat stat_buf;
profile_param_info_t *profile_list;
char *rfile, *ffile, *filename, *Mdirs, *tstring;
char	*profile_datadir, *profile_statdir, *nameserver;
int c, syntax_only, subdir_index, stdin_profile_params;;
time_t tslot;

	tstring 		= NULL;
	profile_datadir = NULL;
	profile_statdir = NULL;
	Mdirs 			= NULL;
	tslot 			= 0;
	syntax_only	    = 0;
	compress		= 0;
	subdir_index	= 0;
	profile_list	= NULL;
	nameserver		= NULL;
	stdin_profile_params = 0;

	// default file names
	ffile = "filter.txt";
	rfile = NULL;
	while ((c = getopt(argc, argv, "D:Ip:P:hf:r:n:M:S:t:VzZ")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'D':
				nameserver = optarg;
				if ( !set_nameserver(nameserver) ) {
					exit(255);
				}
				break;
			case 'I':
				stdin_profile_params = 1;
				break;
			case 'Z':
				syntax_only = 1;
				break;
			case 'p':
				profile_datadir = optarg;
				break;
			case 'P':
				profile_statdir = optarg;
				break;
			case 'S':
				subdir_index = atoi(optarg);
				break;
			case 'V':
				printf("%s: Version: %s %s\n%s\n",argv[0], nfdump_version, nfdump_date, rcsid);
				exit(0);
				break;
			case 'f':
				ffile = optarg;
				break;
			case 't':
				tslot = atoi(optarg);
				break;
			case 'M':
				Mdirs = optarg;
				break;
			case 'r':
				rfile = optarg;
				break;
			case 'z':
				compress = 1;
				break;
			default:
				usage(argv[0]);
				exit(0);
		}
	}

	if ( subdir_index && !InitHierPath(subdir_index) ) {
		exit(255);
	}

	if ( !profile_datadir ) {
		fprintf(stderr, "Profile data directory required!\n");
		exit(255);
	}

	if ( !profile_statdir ) {
		profile_statdir = profile_datadir;
	}

	if ( stat(profile_datadir, &stat_buf) || !S_ISDIR(stat_buf.st_mode) ) {
		fprintf(stderr, "'%s' not a directory\n", profile_datadir);
		exit(255);
	}

	if ( stdin_profile_params ) {
		profile_list = ParseParams(profile_datadir);
		if ( !profile_list ) {
			exit(254);
		}
	}

	if ( syntax_only ) {
		filename = NULL;
		rfile = NULL;
	} else {
		char *p;
		if ( rfile == NULL ) {
			fprintf(stderr, "-r filename required!\n");
			exit(255);
		}
		p = strrchr(rfile, '/');
		filename = p == NULL ? rfile : ++p;
		if ( strlen(filename) == 0 ) {
			fprintf(stderr, "Filename error: zero length filename\n");
			exit(254);
		}
	} 

	if ( chdir(profile_datadir)) {
		fprintf(stderr, "Error can't chdir to '%s': %s", profile_datadir, strerror(errno));
		exit(255);
	}

	num_channels = InitChannels(profile_datadir, profile_statdir, profile_list, ffile, filename, subdir_index, syntax_only, compress);

	// nothing to do
	if ( num_channels == 0 ) {
		printf("No channels to process.\n");
		return 0;
	}

	if ( syntax_only ) {
		printf("Syntax check done.\n");
		return 0;
	}

	if ( !rfile ) {
		fprintf(stderr, "Input file (-r) required!\n");
		exit(255);
	}

	SetupInputFileSequence(Mdirs,rfile, NULL);

	process_data(GetChannelInfoList(), num_channels, tslot, compress);

	CloseChannels(tslot, compress);

	return 0;
}
