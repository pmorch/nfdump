/*
 *  nfprofile : Reads netflow data from files, saved by nfcapd
 *                      Data can be view, filtered and saved to 
 *                      files.
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
 *  $Id: profile.c 70 2006-05-17 08:38:01Z peter $
 *
 *  $LastChangedRevision: 70 $
 *      
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nfdump.h"
#include "nffile.h"
#include "util.h"
#include "nftree.h"
#include "profile.h"

static profile_channel_info_t *profile_channel;
static unsigned int num_channels;

static void SetupProfile(char *profiledir, char *profilename, char *subdir, char *filterfile, char *filename, int veryfy_only, int quiet );

static void SetupProfileChannels(char *profiledir, char *profilename, char *filterfile, char *filename, int veryfy_only, int quiet );

profile_channel_info_t	*GetProfiles(void) {
	return profile_channel;
} // End of GetProfiles

int InitProfiles(char *profiledir, char *subdir, char *filterfile, char *filename, int veryfy_only, int quiet ) {
DIR *PDIR;
struct dirent *entry;
struct stat stat_buf;
char	stringbuf[1024];

	profile_channel 	 = NULL;
	num_channels = 0;
	PDIR = opendir(profiledir);
	if ( !PDIR ) {
		fprintf(stderr, "Can't read profiledir '%s': %s\n",profiledir, strerror(errno) );
		return 0;
	}

	while ( ( entry = readdir(PDIR)) != NULL ) {
		snprintf(stringbuf, 1023, "%s/%s", profiledir, entry->d_name);
		if ( stat(stringbuf, &stat_buf) ) {
			fprintf(stderr, "Can't stat '%s': %s\n",stringbuf, strerror(errno) );
			continue;
		}
		if ( !S_ISDIR(stat_buf.st_mode) ) 
			continue;

		// skip all '.' entries -> make .anything invisible to nfprofile
		if ( entry->d_name[0] == '.' )
			continue;

		if ( subdir ) 
			SetupProfile(profiledir, entry->d_name, subdir, filterfile, filename, veryfy_only, quiet);
		else
			SetupProfileChannels(profiledir, entry->d_name, filterfile, filename, veryfy_only, quiet);
	}
	closedir(PDIR);

	return num_channels;

} // End of InitProfiles

static void SetupProfile(char *profiledir, char *profilename, char *subdir, char *filterfile, char *filename, int veryfy_only, int quiet ) {
FilterEngine_data_t	*engine;
struct stat stat_buf;
char *filter;
char	stringbuf[1024], *string;
int	ffd, wfd, ret;

	// check if subdir exists if defined
	snprintf(stringbuf, 1023, "%s/%s/%s", profiledir, profilename, subdir);
	if ( stat(stringbuf, &stat_buf) ) {
		if ( !quiet ) 
			fprintf(stderr, "Skipping profile '%s'\n", profilename);
		return;
	}
	if ( !S_ISDIR(stat_buf.st_mode) )
		return;


	// Try to read filter
	snprintf(stringbuf, 1023, "%s/%s/%s", profiledir, profilename, filterfile);
	if ( stat(stringbuf, &stat_buf) || !S_ISREG(stat_buf.st_mode) ) {
		if ( !quiet ) 
			fprintf(stderr, "Skipping profile '%s'\n", profilename);
		return;
	}

	// stringbuf contains filter file
	filter = (char *)malloc(stat_buf.st_size+1);
	if ( !filter ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	ffd = open(stringbuf, O_RDONLY);
	if ( ffd < 0 ) {
		fprintf(stderr, "Can't open file '%s' for reading: %s\n",stringbuf, strerror(errno) );
		return;
	}

	ret = read(ffd, (void *)filter, stat_buf.st_size);
	if ( ret < 0   ) {
		fprintf(stderr, "Can't read from file '%s': %s\n",stringbuf, strerror(errno) );
		close(ffd);
		return;
	}
	close(ffd);
	filter[stat_buf.st_size] = 0;

	if ( !quiet ) 
		printf("Setup Profile %s static channel %s\n", profilename, subdir);
	// compile profile filter
	if ( veryfy_only && !quiet )
		printf("Check profile %s static channel %s: ", profilename, subdir);
			
	engine = CompileFilter(filter);
	free(filter);

	if ( !engine ) {
		printf("\n");
		exit(254);
	}

	if ( veryfy_only  && !quiet ) {
		printf("Done.\n");
		return;
	}

	// prepare output file
	snprintf(stringbuf, 1023, "%s/%s/%s/%s", profiledir, profilename, subdir, filename);

	wfd = OpenNewFile(stringbuf, &string);

	if ( wfd < 0 ) {
		if ( string != NULL )
			fprintf(stderr, "%s\n", string);
		return;
	}

	if ( wfd < 0 ) {
		fprintf(stderr, "Can't open file '%s' for writing: %s\n",stringbuf, strerror(errno) );
		return;
	}

	// collect all profile info
	num_channels++;
	profile_channel = realloc(profile_channel, num_channels * sizeof(profile_channel_info_t) );
	if ( !profile_channel ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}

	memset(&profile_channel[num_channels-1], 0, sizeof(profile_channel_info_t));

	profile_channel[num_channels-1].engine		= engine;
	profile_channel[num_channels-1].profile		= strdup(profilename);
	profile_channel[num_channels-1].channel 	= strdup(subdir);
	profile_channel[num_channels-1].wfile 		= strdup(stringbuf);
	profile_channel[num_channels-1].wfd			= wfd;
	memset((void *)&profile_channel[num_channels-1].stat_record, 0, sizeof(stat_record_t));
	profile_channel[num_channels-1].stat_record.first_seen	= 0xffffffff;
	profile_channel[num_channels-1].stat_record.last_seen	= 0;

	return;

} // End of SetupProfile


static void SetupProfileChannels(char *profiledir, char *profilename, char *filterfile, char *filename, int veryfy_only, int quiet ) {
DIR *PDIR;
struct dirent *entry;
FilterEngine_data_t	*engine;
struct stat stat_buf;
char *filter;
char	stringbuf[1024], *string;
int	ffd, wfd, ret;

	snprintf(stringbuf, 1023, "%s/%s", profiledir, profilename);

	PDIR = opendir(stringbuf);
	if ( !PDIR ) {
		fprintf(stderr, "Can't open directory '%s': %s\n",stringbuf, strerror(errno) );
		return;
	}

	while ( ( entry = readdir(PDIR)) != NULL ) {
		snprintf(stringbuf, 1023, "%s/%s/%s", profiledir, profilename, entry->d_name);

		if ( stat(stringbuf, &stat_buf) ) {
			fprintf(stderr, "Can't stat directory entry '%s': %s\n",stringbuf, strerror(errno) );
			continue;
		}
		if ( !S_ISDIR(stat_buf.st_mode) ) 
			continue;

		// skip all '.' entries -> make .anything invisible to nfprofile
		if ( entry->d_name[0] == '.' )
			continue;

		// Try to read filter
		snprintf(stringbuf, 1023, "%s/%s/%s/%s", profiledir, profilename, entry->d_name, filterfile);
		if ( stat(stringbuf, &stat_buf) || !S_ISREG(stat_buf.st_mode) ) {
			if ( !quiet ) 
				fprintf(stderr, "Skipping channel %s in profile '%s'\n", entry->d_name, profilename);
			continue;
		}

		// stringbuf contains filter filename
		filter = (char *)malloc(stat_buf.st_size+1);
		if ( !filter ) {
			fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(255);
		}
		ffd = open(stringbuf, O_RDONLY);
		if ( ffd < 0 ) {
			fprintf(stderr, "Can't open file '%s' for reading: %s\n",stringbuf, strerror(errno) );
			return;
		}

		ret = read(ffd, (void *)filter, stat_buf.st_size);
		if ( ret < 0   ) {
			fprintf(stderr, "Can't read from file '%s': %s\n",stringbuf, strerror(errno) );
			close(ffd);
			continue;
		}
		close(ffd);
		filter[stat_buf.st_size] = 0;

		if ( !quiet ) 
			printf("Setup profile %s channel %s \n", profilename, entry->d_name);

		// compile profile filter
		if ( veryfy_only && !quiet )
			printf("Check profile %s channel '%s': ", profilename, entry->d_name);
			
		engine = CompileFilter(filter);
		free(filter);

		if ( !engine ) {
			printf("\n");
			exit(254);
		}

		if ( veryfy_only  && !quiet ) {
			printf("Done.\n");
			continue;
		}

		// prepare output file
		snprintf(stringbuf, 1023, "%s/%s/%s/%s", profiledir, profilename, entry->d_name, filename);

		wfd = OpenNewFile(stringbuf, &string);

		if ( wfd < 0 ) {
			if ( string != NULL )
				fprintf(stderr, "%s\n", string);
			continue;
		}

		// collect all channel info
		num_channels++;
		profile_channel = realloc(profile_channel, num_channels * sizeof(profile_channel_info_t) );
		if ( !profile_channel ) {
			fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(255);
		}

		memset(&profile_channel[num_channels-1], 0, sizeof(profile_channel_info_t));

		profile_channel[num_channels-1].engine		= engine;
		profile_channel[num_channels-1].profile 	= strdup(profilename);
		profile_channel[num_channels-1].channel 	= strdup(entry->d_name);
		profile_channel[num_channels-1].wfile 		= strdup(stringbuf);
		profile_channel[num_channels-1].wfd			= wfd;
		memset((void *)&profile_channel[num_channels-1].stat_record, 0, sizeof(stat_record_t));
		profile_channel[num_channels-1].stat_record.first_seen	= 0xffffffff;
		profile_channel[num_channels-1].stat_record.last_seen	= 0;

	}

	return;

} // End of SetupProfileChannels

void CloseProfiles (void) {
unsigned int num;
char *s;

	for ( num = 0; num < num_channels; num++ ) {
		CloseUpdateFile(profile_channel[num].wfd, &(profile_channel[num].stat_record), profile_channel[num].file_blocks, GetIdent(), &s );
		if ( s != NULL )
			fprintf(stderr, "%s\n", s);
	}

} // End of CloseProfiles

