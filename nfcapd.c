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
 *  $Id: nfcapd.c 97 2008-02-21 09:50:02Z peter $
 *
 *  $LastChangedRevision: 97 $
 *	
 *
 */

/*
 * Because NetFlow export uses UDP to send export datagrams, it is possible 
 * for datagrams to be lost. To determine whether flow export information has 
 * been lost, Version 5, Version 7, and Version 8 headers contain a flow 
 * sequence number. The sequence number is equal to the sequence number of the 
 * previous datagram plus the number of flows in the previous datagram. After 
 * receiving a new datagram, the receiving application can subtract the expected 
 * sequence number from the sequence number in the header to derive the number 
 * of missed flows.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <sys/mman.h>
#include <string.h>
#include <dirent.h>

#if 0
#include "pcap_reader.h"
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "version.h"
#include "nffile.h"
#include "nf_common.h"
#include "nfnet.h"
#include "launch.h"
#include "netflow_v5_v7.h"
#include "netflow_v9.h"
#include "flist.h"
#include "nfstatfile.h"
#include "bookkeeper.h"

#ifdef HAVE_FTS_H
#   include <fts.h>
#else
#   include "fts_compat.h"
#define fts_children fts_children_compat
#define fts_close fts_close_compat
#define fts_open  fts_open_compat
#define fts_read  fts_read_compat
#define fts_set   fts_set_compat
#endif

#include "expire.h"

/* default path to store data - not really attractive, but anyway ... */
#define DEFAULT_DIR	  	"/var/tmp"

#define NF_DUMPFILE 	"nfcapd.current"

#define DEFAULTCISCOPORT "9995"
#define DEFAULTHOSTNAME "127.0.0.1"
#define SENDSOCK_BUFFSIZE 200000

/* Default time window in seconds to rotate files */
#define TIME_WINDOW	  	300

/* overdue time: 
 * if nfcapd does not get any data, wake up the receive system call
 * at least after OVERDUE_TIME seconds after the time window
 */
#define OVERDUE_TIME	10

// time nfcapd will wait for launcher to terminate
#define LAUNCHER_TIMEOUT 60

#define SYSLOG_FACILITY LOG_DAEMON

/* Global Variables */
caddr_t		shmem;

/* globals */
int verbose = 0;


/* module limited globals */
static bookkeeper_t *bookkeeper;

static int done, launcher_alive, rename_trigger, launcher_pid;

static char Ident[IdentLen];

static char const *rcsid 		  = "$Id: nfcapd.c 97 2008-02-21 09:50:02Z peter $";

/* exported fuctions */
void LogError(char *format, ...);

/* Local function Prototypes */
static void usage(char *name);

static void kill_launcher(int pid);

static void IntHandler(int signal);

static void daemonize(void);

static void SetPriv(char *userid, char *groupid );

static void run(int socket, send_peer_t peer, time_t twin, time_t t_begin, int report_seq, int use_subdirs, int sampling_rate, int compress);

/* Functions */
static void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here\n"
					"-u userid\tChange user to userid\n"
					"-g groupid\tChange group to groupid\n"
					"-w\t\tSync file rotation with next 5min (default) interval\n"
					"-t interval\tset the interval to rotate nfcapd files\n"
					"-b host\t\tbind socket to host/IP addr\n"
					"-j mcastgroup\tJoin multicast group <mcastgroup>\n"
					"-p portnum\tlisten on port portnum\n"
					"-l logdir \tset the output directory. (default /var/tmp) \n"
					"-S subdir\tSub directory format. see nfcapd(1) for format\n"
					"-I Ident\tset the ident string for stat file. (default 'none')\n"
					"-P pidfile\tset the PID file\n"
					"-R IP[/port]\tRepeat incoming packets to IP address/port\n"
					"-x process\tlauch process after a new file becomes available\n"
					"-z\t\tCompress flows in output file.\n"
					"-B bufflen\tSet socket buffer to bufflen bytes\n"
					"-e\t\tExpire data at each cycle.\n"
					"-D\t\tFork to background\n"
					"-E\t\tPrint extended format of netflow data. for debugging purpose only.\n"
					"-4\t\tListen on IPv4 (default).\n"
					"-6\t\tListen on IPv6.\n"
					"-V\t\tPrint version and exit.\n"
					, name);
} // End of usage

/* 
 * Some C code is needed for daemon code as well as normal stdio code 
 * therefore a generic LogError is defined, which maps in this case
 * to syslog
 */
void LogError(char *format, ...) {
va_list var_args;
char string[512];

	va_start(var_args, format);
	vsnprintf(string, 511, format, var_args);
	va_end(var_args);
	syslog(LOG_ERR, "%s", string);

} // End of LogError

void kill_launcher(int pid) {
int stat, i;
pid_t ret;

	if ( pid == 0 )
		return;

	if ( launcher_alive ) {
		syslog(LOG_INFO, "Signal laucher[%i] to terminate.", pid);
		kill(pid, SIGTERM);

		// wait for launcher to teminate
		for ( i=0; i<LAUNCHER_TIMEOUT; i++ ) {
			if ( !launcher_alive ) 
				break;
			sleep(1);
		}
		if ( i >= LAUNCHER_TIMEOUT ) {
			syslog(LOG_WARNING, "Laucher does not want to terminate - signal again");
			kill(pid, SIGTERM);
			sleep(1);
		}
	} else {
		syslog(LOG_ERR, "laucher[%i] already dead.", pid);
	}

	if ( (ret = waitpid (pid, &stat, 0)) == -1 ) {
		syslog(LOG_ERR, "wait for launcher failed: %s %i", strerror(errno), ret);
	} else {
		if ( WIFEXITED(stat) ) {
			syslog(LOG_INFO, "laucher exit status: %i", WEXITSTATUS(stat));
		}
		if (  WIFSIGNALED(stat) ) {
			syslog(LOG_WARNING, "laucher terminated due to signal %i", WTERMSIG(stat));
		}
	}

} // End of kill_launcher

static void IntHandler(int signal) {

	switch (signal) {
		case SIGALRM:
			rename_trigger = 1;
			break;
		case SIGHUP:
		case SIGINT:
		case SIGTERM:
			done = 1;
			break;
		case SIGCHLD:
			launcher_alive = 0;
			break;
		default:
			// ignore everything we don't know
			break;
	}

} /* End of IntHandler */

static void daemonize(void) {
int fd;
	switch (fork()) {
		case 0:
			// child
			break;
		case -1:
			// error
			fprintf(stderr, "fork() error: %s\n", strerror(errno));
			exit(0);
			break;
		default:
			// parent
			_exit(0);
	}

	if (setsid() < 0) {
		fprintf(stderr, "setsid() error: %s\n", strerror(errno));
		exit(0);
	}

	// Double fork
	switch (fork()) {
		case 0:
			// child
			break;
		case -1:
			// error
			fprintf(stderr, "fork() error: %s\n", strerror(errno));
			exit(0);
			break;
		default:
			// parent
			_exit(0);
	}

	fd = open("/dev/null", O_RDONLY);
	if (fd != 0) {
		dup2(fd, 0);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 1) {
		dup2(fd, 1);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 2) {
		dup2(fd, 2);
		close(fd);
	}

} // End of daemonize

static void SetPriv(char *userid, char *groupid ) {
struct 	passwd *pw_entry;
struct 	group *gr_entry;
uid_t	myuid, newuid, newgid;
int		err;

	if ( userid == 0 && groupid == 0 )
		return;

	newuid = newgid = 0;
	myuid = getuid();
	if ( myuid != 0 ) {
		syslog(LOG_ERR, "Only root wants to change uid/gid");
		fprintf(stderr, "ERROR: Only root wants to change uid/gid\n");
		exit(255);
	}

	if ( userid ) {
		pw_entry = getpwnam(userid);
		newuid = pw_entry ? pw_entry->pw_uid : atol(userid);

		if ( newuid == 0 ) {
			fprintf (stderr,"Invalid user '%s'\n", userid);
			exit(255);
		}
	}

	if ( groupid ) {
		gr_entry = getgrnam(groupid);
		newgid = gr_entry ? gr_entry->gr_gid : atol(groupid);

		if ( newgid == 0 ) {
			fprintf (stderr,"Invalid group '%s'\n", groupid);
			exit(255);
		}

		err = setgid(newgid);
		if ( err ) {
			syslog(LOG_ERR, "Can't set group id %ld for group '%s': %s",   (long)newgid, groupid, strerror(errno));
			fprintf (stderr,"Can't set group id %ld for group '%s': %s\n", (long)newgid, groupid, strerror(errno));
			exit(255);
		}

	}

	if ( newuid ) {
		err = setuid(newuid);
		if ( err ) {
			syslog(LOG_ERR, "Can't set user id %ld for user '%s': %s",   (long)newuid, userid, strerror(errno));
			fprintf (stderr,"Can't set user id %ld for user '%s': %s\n", (long)newuid, userid, strerror(errno));
			exit(255);
		}
	}

} // End of SetPriv

static void run(int socket, send_peer_t peer, time_t twin, time_t t_begin, int report_seq, int use_subdirs, int sampling_rate, int compress) {
common_flow_header_t	*nf_header;
data_block_header_t		*data_header;
stat_record_t 			stat_record;
struct 	stat 			fstat;
time_t 		t_start, t_now;
uint64_t	first_seen, last_seen, export_packets;
uint32_t	bad_packets, file_blocks, blast_cnt, blast_failures;
uint16_t	version;
struct  tm *now;
ssize_t		cnt;
void 		*in_buff, *out_buff, *writeto;
int 		err, nffd, first;
char 		*string, nfcapd_filename[64], dumpfile[64];
char 		*subdir;
srecord_t	*commbuff;
	
	Init_v5_v7_input();
	Init_v9();

	in_buff  = malloc(NETWORK_INPUT_BUFF_SIZE);
	out_buff = malloc(BUFFSIZE);
	if ( !in_buff || !out_buff ) {
		syslog(LOG_ERR, "Buffer allocation error: %s", strerror(errno));
		return;
	}

	// init vars
	commbuff = (srecord_t *)shmem;
	nf_header = (common_flow_header_t *)in_buff;

	// Init header
	data_header = (data_block_header_t *)out_buff;
	data_header->NumBlocks 	= 0;
	data_header->size 		= 0;
	data_header->id			= DATA_BLOCK_TYPE_1;
	data_header->pad		= 0;
	writeto = (void *)((pointer_addr_t)data_header + sizeof(data_block_header_t) );

	cnt  = 0;
	export_packets = blast_cnt = blast_failures = 0;

	snprintf(dumpfile, 63, "%s.%lu",NF_DUMPFILE, (unsigned long)getpid());
	dumpfile[63] = 0;
	nffd = OpenNewFile(dumpfile, &string, compress);
	if ( string != NULL ) {
		syslog(LOG_ERR, "%s", string);
		return;
	}

	bad_packets		 = 0;

	// init sequence check vars 
	first			 = 1;
	file_blocks		 = 0;

	first_seen = (uint64_t)0xffffffffffffLL;
	last_seen = 0;
	t_start = t_begin;
	memset((void *)&stat_record, 0, sizeof(stat_record_t));

	cnt = 0;
	rename_trigger = 0;
	alarm(t_start + twin + OVERDUE_TIME - time(NULL));
	/*
	 * Main processing loop:
	 * this loop, continues until done = 1, set by the signal handler
	 * The while loop will be breaked by the periodic file renaming code
	 * for proper cleanup 
	 */
	while ( 1 ) {

		/* read next bunch of data into beginn of input buffer */
		if ( !done) {
#if 0
			// Debug code to read from pcap file
			cnt = NextPacket(in_buff, NETWORK_INPUT_BUFF_SIZE);
			if ( cnt == 0 )
				done = 1;
#else

			cnt = recvfrom (socket, in_buff, NETWORK_INPUT_BUFF_SIZE , 0, NULL, 0);
			if ( cnt < 0 && errno != EINTR ) {
				syslog(LOG_ERR, "ERROR: recvfrom: %s", strerror(errno));
				continue;
			}
#endif

			if ( peer.hostname ) {
				size_t len;
				len = sendto(peer.sockfd, in_buff, cnt, 0, (struct sockaddr *)&(peer.addr), peer.addrlen);
				if ( len < 0 ) {
					syslog(LOG_ERR, "ERROR: sendto(): %s", strerror(errno));
				}
			}
		}

		/* Periodic file renaming, if time limit reached or if we are done.  */
		t_now = time(NULL);
		if ( ((t_now - t_start) >= twin) || done ) {

			alarm(0);
			now = localtime(&t_start);

			if ( verbose ) {
				// Dump to stdout
				format_file_block_header(out_buff, 0, &string, 0, 0);
			}

			if ( data_header->NumBlocks ) {
				// flush current buffer to disc
				if ( WriteBlock(nffd, data_header, compress) <= 0 )
					syslog(LOG_ERR, "Failed to write output buffer to disk: '%s'" , strerror(errno));
				else 
					// update successful written blocks
					file_blocks++;
			}

			// Initialize header and write pointer
			data_header->NumBlocks 	= 0;
			data_header->size 		= 0;
			writeto = (void *)((pointer_addr_t)data_header + sizeof(data_block_header_t) );

			if ( use_subdirs ) {
				char error[255];

				subdir = SetupSubDir(now, error, 255);
				if ( !subdir ) {
					syslog(LOG_ERR, "Failed to create subdir path: '%s'" , error);

					// in the event of a failure to create the sub dir path, use the base dir
					snprintf(nfcapd_filename, 64, "nfcapd.%i%02i%02i%02i%02i", 
						now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min);
				} else {
					snprintf(nfcapd_filename, 64, "%s/nfcapd.%i%02i%02i%02i%02i", subdir,
						now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min);
					subdir = "";
				}
			} else {
				snprintf(nfcapd_filename, 64, "nfcapd.%i%02i%02i%02i%02i", 
					now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min);
				subdir = "";
			}

			/* t_start = filename time stamp: begin of slot
			 * + twim = time now
			 * + twin = end of next time interval
			 * + OVERDUE_TIME = if no data is collected, this is at latest to act
			 * - t_now = difference value to now
			 */
			alarm(t_start + 2*twin + OVERDUE_TIME - t_now);

			stat_record.first_seen 	= first_seen/1000;
			stat_record.msec_first	= first_seen - stat_record.first_seen*1000;
			stat_record.last_seen 	= last_seen/1000;
			stat_record.msec_last	= last_seen - stat_record.last_seen*1000;

			/* Write Stat Info */
			CloseUpdateFile(nffd, &stat_record, file_blocks, Ident, compress, &string );
			if ( string != NULL ) {
				syslog(LOG_ERR, "%s", string);
			}

			err = rename(dumpfile, nfcapd_filename);
			if ( err ) {
				syslog(LOG_ERR, "Can't rename dump file: %s", strerror(errno));
				if (done) {
					break; 
				} else {
					t_start += twin;
					continue;
				}
			}

			// Update books
			stat(nfcapd_filename, &fstat);
			UpdateBooks(bookkeeper, t_start, 512*fstat.st_blocks);
		
			t_start += twin;

			if ( launcher_pid ) {
				// Signal launcher
				strncpy(commbuff->fname, nfcapd_filename, FNAME_SIZE);
				commbuff->fname[FNAME_SIZE-1] = 0;
				snprintf(commbuff->tstring, 16, "%i%02i%02i%02i%02i", 
					now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min);
				commbuff->tstring[15] = 0;
				commbuff->tstamp = t_start;
				strncpy(commbuff->subdir, subdir, FNAME_SIZE);

				if ( launcher_alive ) {
					syslog(LOG_DEBUG, "Signal launcher");
					kill(launcher_pid, SIGHUP);
				} else {
					syslog(LOG_ERR, "ERROR: Launcher did unexpectedly!");
				}
			}

			syslog(LOG_INFO,"Ident: '%s' Flows: %llu, Packets: %llu, Bytes: %llu, Sequence Errors: %u, Bad Packets: %u", 
				Ident, (unsigned long long)stat_record.numflows, (unsigned long long)stat_record.numpackets, 
				(unsigned long long)stat_record.numbytes, stat_record.sequence_failure, bad_packets);

			memset((void *)&stat_record, 0, sizeof(stat_record_t));
			bad_packets = 0;
			first_seen 	= 0xffffffffffffLL;
			last_seen 	= 0;
			file_blocks	= 0;

			if ( done ) 
				break;

			nffd = OpenNewFile(dumpfile, &string, compress);
			if ( string != NULL ) {
				syslog(LOG_ERR, "%s", string);
				return;
			}

		}

		/* check for error condition or done . errno may only be EINTR */
		if ( cnt < 0 ) {
			if ( rename_trigger ) {	
				rename_trigger = 0;
				continue;
			}
			if ( done ) 
				continue;
			else {
				/* this should never be executed as it should be caught in other places */
				syslog(LOG_ERR, "error condition in '%s', line '%d', cnt: %i", __FILE__, __LINE__ ,(int)cnt);
				continue;
			}
		}

		/* enough data? */
		if ( cnt == 0 )
			continue;

		/* check for too little data - cnt must be > 0 at this point */
		if ( cnt < sizeof(common_flow_header_t) ) {
			syslog(LOG_WARNING, "Data length error: too little data for common netflow header. cnt: %i",(int)cnt);
			bad_packets++;
			continue;
		}


		/* Process data - have a look at the common header */
		version = ntohs(nf_header->version);
		switch (version) {
			case 5: // fall through
			case 7: 
				writeto = Process_v5_v7(in_buff, cnt, data_header, writeto, &stat_record, &first_seen, &last_seen);
				break;
			case 9: 
				writeto = Process_v9(in_buff, cnt, data_header, writeto, &stat_record, &first_seen, &last_seen);
				break;
			case 255:
				// blast test header
				if ( verbose ) {
					uint16_t count = ntohs(nf_header->count);
					if ( blast_cnt != count ) {
							// fprintf(stderr, "Missmatch blast check: Expected %u got %u\n", blast_cnt, count);
						blast_cnt = count;
						blast_failures++;
					} else {
						blast_cnt++;
					}
					if ( blast_cnt == 65535 ) {
						fprintf(stderr, "Total missed packets: %u\n", blast_failures);
						done = 1;
					}
					break;
				}
			default:
				// data error, while reading data from socket
				syslog(LOG_ERR,"Error reading netflow header: Unexpected netflow version %i", nf_header->version);
				bad_packets++;
				continue;

				// not reached
				break;
		}
		// each Process_xx function has to process the entire input buffer, therefore it's empty now.
		export_packets++;

		// flush current buffer to disc
		if ( data_header->size > BUFFSIZE ) {
				syslog(LOG_ERR, "output buffer overflow: expect memory inconsitency");
		}
		if ( data_header->size > OUTPUT_FLUSH_LIMIT ) {
			if ( WriteBlock(nffd, data_header, compress) <= 0 ) {
				syslog(LOG_ERR, "Failed to write output buffer to disk: '%s'" , strerror(errno));
			} else {
				data_header->size 		= 0;
				data_header->NumBlocks 	= 0;
				writeto = (void *)((pointer_addr_t)data_header + sizeof(data_block_header_t) );
				file_blocks++;
			}
		}
	}

	if ( verbose && blast_failures ) {
		fprintf(stderr, "Total missed packets: %u\n", blast_failures);
	}
	free(in_buff);
	free(out_buff);
	close(nffd);
	unlink(dumpfile);

} /* End of run */

int main(int argc, char **argv) {
 
char	*bindhost, *filter, *datadir, pidstr[32], *lauch_process;
char	*userid, *groupid, *checkptr, *listenport, *mcastgroup;
char	pidfile[MAXPATHLEN];
struct stat fstat;
srecord_t	*commbuff;
dirstat_t 	*dirstat;
send_peer_t  peer;
struct sigaction act;
int		family, bufflen;
time_t 	twin, t_start, t_tmp;
int		sock, err, synctime, do_daemonize, expire, report_sequence;
int		subdir_index, sampling_rate, compress;
int	c;

	verbose = synctime = do_daemonize = 0;
	bufflen  		= 0;
	family			= AF_UNSPEC;
	launcher_pid	= 0;
	launcher_alive	= 0;
	report_sequence	= 0;
	listenport		= DEFAULTCISCOPORT;
	bindhost 		= NULL;
	mcastgroup		= NULL;
	pidfile[0]		= 0;
	filter   		= NULL;
	lauch_process	= NULL;
	userid 			= groupid = NULL;
	twin	 		= TIME_WINDOW;
	datadir	 		= DEFAULT_DIR;
	subdir_index	= 0;
	expire			= 0;
	sampling_rate	= 1;
	compress		= 0;
	strncpy(Ident, "none", IDENT_SIZE);
	memset((void *)&peer, 0, sizeof(send_peer_t));
	peer.family		= AF_UNSPEC;


	while ((c = getopt(argc, argv, "46ewhEVI:DB:b:j:l:p:P:R:S:s:t:x:ru:g:z")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'u':
				userid  = optarg;
				break;
			case 'g':
				groupid  = optarg;
				break;
			case 'e':
				expire = 1;
				break;
			case 'E':
				verbose = 1;
				break;
			case 'V':
				printf("%s: Version: %s %s\n%s\n",argv[0], nfdump_version, nfdump_date, rcsid);
				exit(0);
				break;
			case 'D':
				do_daemonize = 1;
				break;
			case 'I':
				strncpy(Ident, optarg, IDENT_SIZE);
				Ident[IDENT_SIZE - 1] = 0;
				if ( strchr(Ident, ' ') ) {
					fprintf(stderr,"Ident must not contain spaces\n");
					exit(255);
				}
				break;
			case 'w':
				synctime = 1;
				break;
			case 'B':
				bufflen = strtol(optarg, &checkptr, 10);
				if ( (checkptr != NULL && *checkptr == 0) && bufflen > 0 )
					break;
				fprintf(stderr,"Argument error for -B\n");
				exit(255);
			case 'b':
				bindhost = optarg;
				break;
			case 'j':
				mcastgroup = optarg;
				break;
			case 'p':
				listenport = optarg;
				break;
			case 'P':
				if ( optarg[0] == '/' ) { 	// absolute path given
					strncpy(pidfile, optarg, MAXPATHLEN-1);
				} else {					// path relative to current working directory
					char tmp[MAXPATHLEN];
					if ( !getcwd(tmp, MAXPATHLEN-1) ) {
						fprintf(stderr, "Failed to get current working directory: %s\n", strerror(errno));
						exit(255);
					}
					tmp[MAXPATHLEN-1] = 0;
					snprintf(pidfile, MAXPATHLEN - 1 - strlen(tmp), "%s/%s", tmp, optarg);
				}
				// pidfile now absolute path
				pidfile[MAXPATHLEN-1] = 0;
				break;
			case 'R': {
				char *p = strchr(optarg, '/');
				if ( p ) { 
					*p++ = '\0';
					peer.port = strdup(p);
				} else {
					peer.port = DEFAULTCISCOPORT;
				}
				peer.hostname = strdup(optarg);

				break; }
			case 'r':
				report_sequence = 1;
				break;
			case 's':
				sampling_rate = (int)strtol(optarg, (char **)NULL, 10);
				if ( sampling_rate <= 0 ) {
					fprintf(stderr, "Invalid sampling rate: %s\n", optarg);
				} else {
					sampling_rate = 1;
				}
				break;
			case 'l':
				datadir = optarg;
				err  = stat(datadir, &fstat);
				if ( !(fstat.st_mode & S_IFDIR) ) {
					fprintf(stderr, "No such directory: %s\n", datadir);
					break;
				}
				break;
			case 'S':
				subdir_index = atoi(optarg);
				break;
			case 't':
				twin = atoi(optarg);
				if ( twin <= 0 ) {
					fprintf(stderr, "ERROR: time frame <= 0\n");
					exit(255);
				}
				if (twin < 60) {
					fprintf(stderr, "WARNING, Very small time frame - < 60s!\n");
				}
				break;
			case 'x':
				lauch_process = optarg;
				break;
			case 'z':
				compress = 1;
				break;
			case '4':
				if ( family == AF_UNSPEC )
					family = AF_INET;
				else {
					fprintf(stderr, "ERROR, Accepts only one protocol IPv4 or IPv6!\n");
					exit(255);
				}
				break;
			case '6':
				if ( family == AF_UNSPEC )
					family = AF_INET6;
				else {
					fprintf(stderr, "ERROR, Accepts only one protocol IPv4 or IPv6!\n");
					exit(255);
				}
				break;
			default:
				usage(argv[0]);
				exit(255);
		}
	}
	
	if ( bindhost && mcastgroup ) {
		fprintf(stderr, "ERROR, -b and -j are mutually exclusive!!\n");
		exit(255);
	}

	openlog(argv[0] , LOG_CONS|LOG_PID, SYSLOG_FACILITY);

	if ( mcastgroup ) 
		sock = Multicast_receive_socket (mcastgroup, listenport, family, bufflen);
	else 
		sock = Unicast_receive_socket(bindhost, listenport, family, bufflen );

	if ( sock == -1 ) {
		fprintf(stderr,"Terminated due to errors.\n");
		exit(255);
	}

	if ( peer.hostname ) {
		peer.sockfd = Unicast_send_socket (peer.hostname, peer.port, peer.family, bufflen, 
											&peer.addr, &peer.addrlen );
		if ( peer.sockfd <= 0 )
			exit(255);
		syslog(LOG_DEBUG, "Replay flows to host: %s port: %s", peer.hostname, peer.port);
	}

#if 0 
// Debug code to read from pcap file
printf("Setup pcap reader\n");
setup_packethandler("flows.raw", NULL);
#endif

	SetPriv(userid, groupid);

	if ( subdir_index && !InitHierPath(subdir_index) ) {
		close(sock);
		exit(255);
	}

	// check if pid file exists and if so, if a process with registered pid is running
	if ( strlen(pidfile) ) {
		int pidf;
		pidf = open(pidfile, O_RDONLY, 0);
		if ( pidf > 0 ) {
			// pid file exists
			char s[32];
			ssize_t len;
			len = read(pidf, (void *)s, 31);
			close(pidf);
			s[31] = '\0';
			if ( len < 0 ) {
				fprintf(stderr, "read() error existing pid file: %s\n", strerror(errno));
				exit(255);
			} else {
				unsigned long pid = atol(s);
				if ( pid == 0 ) {
					// garbage - use this file
					unlink(pidfile);
				} else {
					if ( kill(pid, 0) == 0 ) {
						// process exists
						fprintf(stderr, "A process with pid %lu registered in pidfile %s is already running!\n", 
							pid, strerror(errno));
						exit(255);
					} else {
						// no such process - use this file
						unlink(pidfile);
					}
				}
			}
		} else {
			if ( errno != ENOENT ) {
				fprintf(stderr, "open() error existing pid file: %s\n", strerror(errno));
				exit(255);
			} // else errno == ENOENT - no file - this is fine
		}
	}

	if (argc - optind > 1) {
		usage(argv[0]);
		kill_launcher(launcher_pid);
		close(sock);
		exit(255);
	} else {
		/* user specified a pcap filter */
		filter = argv[optind];
	}

	if ( synctime ) {
		t_tmp = time(NULL);
		t_start = t_tmp - ( t_tmp % twin);
	} else
		t_start = time(NULL);

	if ( do_daemonize ) {
		verbose = 0;
		daemonize();
	}
	if (strlen(pidfile)) {
		pid_t pid = getpid();
		int pidf  = open(pidfile, O_RDWR|O_TRUNC|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if ( pidf == -1 ) {
			syslog(LOG_ERR, "Error opening pid file: '%s' %s", pidfile, strerror(errno));
			close(sock);
			exit(255);
		}
		snprintf(pidstr,31,"%lu\n", (unsigned long)pid);
		write(pidf, pidstr, strlen(pidstr));
		close(pidf);
	}

	done = 0;
	if ( lauch_process || expire ) {
		// for efficiency reason, the process collecting the data
		// and the process launching processes, when a new file becomes
		// available are separated. Communication is done using signals
		// as well as shared memory
		// prepare shared memory
		shmem = mmap(0, sizeof(srecord_t), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
		if ( shmem == (caddr_t)-1 ) {
			syslog(LOG_ERR, "mmap() error: %s", strerror(errno));
			close(sock);
			exit(255);
		}

		commbuff = (srecord_t *)shmem;
		strncpy(commbuff->ident, Ident, IDENT_SIZE );
		commbuff->ident[IDENT_SIZE - 1] = 0;

		launcher_pid = fork();
		switch (launcher_pid) {
			case 0:
				// child
				close(sock);
				launcher((char *)shmem, datadir, lauch_process, expire);
				_exit(0);
				break;
			case -1:
				syslog(LOG_ERR, "fork() error: %s", strerror(errno));
				if ( strlen(pidfile) )
					unlink(pidfile);
				exit(255);
				break;
			default:
				// parent
			launcher_alive = 1;
			syslog(LOG_DEBUG, "Launcher[%i] forked", launcher_pid);
		}
	}

	if ( InitBookkeeper(&bookkeeper, datadir, getpid(), launcher_pid) != BOOKKEEPER_OK ) {
		syslog(LOG_ERR, "initialize bookkeeper failed.");
		close(sock);
		if ( launcher_pid )
			kill_launcher(launcher_pid);
		if ( strlen(pidfile) )
			unlink(pidfile);
		exit(255);
	}

	if ( chdir(datadir)) {
		syslog(LOG_ERR, "Error can't chdir to '%s': %s", datadir, strerror(errno));
		close(sock);
		if ( strlen(pidfile) )
			unlink(pidfile);
		exit(255);
	}

	/* Signal handling */
	memset((void *)&act,0,sizeof(struct sigaction));
	act.sa_handler = IntHandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);

	syslog(LOG_INFO, "Startup.");
	run(sock, peer, twin, t_start, report_sequence, subdir_index, sampling_rate, compress);
	close(sock);
	kill_launcher(launcher_pid);

	// if we do not auto expire and there is a stat file, update the stats before we leave
	if ( expire == 0 && ReadStatInfo(datadir, &dirstat, LOCK_IF_EXISTS) == STATFILE_OK ) {
		UpdateStat(dirstat, bookkeeper);
		WriteStatInfo(dirstat);
		syslog(LOG_INFO, "Updating statinfo in directory '%s'", datadir);
	}
	ReleaseBookkeeper(bookkeeper, DESTROY_BOOKKEEPER);

	syslog(LOG_INFO, "Terminating nfcapd.");
	closelog();

	if ( strlen(pidfile) )
		unlink(pidfile);

	return 0;

} /* End of main */
