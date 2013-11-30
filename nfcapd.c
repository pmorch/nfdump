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
 *  $Id: nfcapd.c 62 2006-03-08 12:59:51Z peter $
 *
 *  $LastChangedRevision: 62 $
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

#include <stdio.h>
#include <stdlib.h>
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <sys/mman.h>
#include <string.h>
#include <dirent.h>

#include "config.h"

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

/* default path to store data - not really attractive, but anyway ... */
#define DEFAULT_DIR	  	"/var/tmp"

#define NF_DUMPFILE 	"nfcapd.current"

#define DEFAULTCISCOPORT "9995"

/* Default time window in seconds to rotate files */
#define TIME_WINDOW	  	300

/* overdue time: 
 * if nfcapd does not get any data, wake up the receive system call
 * at least after OVERDUE_TIME seconds after the time window
 */
#define OVERDUE_TIME	20

#define SYSLOG_FACILITY LOG_DAEMON

/* Global Variables */
uint32_t	byte_limit, packet_limit;	// needed for linking purpose only
int 		byte_mode, packet_mode;
caddr_t		shmem;

/* globals */
int verbose = 0;


/* module limited globals */
static int done, launcher_alive, rename_trigger, launcher_pid;

static char Ident[IdentLen];

static char const *rcsid 		  = "$Id: nfcapd.c 62 2006-03-08 12:59:51Z peter $";

/* Local function Prototypes */
static void IntHandler(int signal);

static void usage(char *name);

static void SetPriv(char *userid, char *groupid );

static void kill_launcher(int pid);

void kill_launcher(int pid) {
int stat;

	if ( pid == 0 )
		return;

	if ( launcher_alive ) {
		kill(pid, SIGTERM);
		waitpid (pid, &stat, 0);
		syslog(LOG_INFO, "laucher terminated: %i", stat);
	} else {
		waitpid (pid, &stat, 0);
		syslog(LOG_ERR, "Can't terminate laucher: process already did: %i", stat);
	}

} // End of kill_launcher


static void run(int socket, time_t twin, time_t t_begin, int report_seq);

/* Functions */
static void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here\n"
					"-u userid\tChange user to userid\n"
					"-g groupid\tChange group to groupid\n"
					"-w\t\tSync file rotation with next 5min (default) interval\n"
					"-t interval\tset the interval to rotate nfcapd files\n"
					"-b host\tbind socket to host/IP addr\n"
					"-j mcastgroup\tJoin multicast group <mcastgroup>\n"
					"-p portnum\tlisten on port portnum\n"
					"-l logdir \tset the output directory. (default /var/tmp) \n"
					"-I Ident\tset the ident string for stat file. (default 'none')\n"
					"-P pidfile\tset the PID file\n"
					"-x process\tlauch process after a new file becomes available\n"
					"-B bufflen\tSet socket buffer to bufflen bytes\n"
					"-D\t\tFork to background\n"
					"-E\t\tPrint extended format of netflow data. for debugging purpose only.\n"
					"-4\t\tListen on IPv4 (default).\n"
					"-6\t\tListen on IPv6.\n"
					"-V\t\tPrint version and exit.\n"
					, name);
} /* usage */

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
			syslog(LOG_ERR, "Can't set group id %u for group '%s': %s", newgid, groupid, strerror(errno));
			fprintf (stderr,"Can't set group id %u for group '%s': %s\n", newgid, groupid, strerror(errno));
			exit(255);
		}

	}

	if ( newuid ) {
		err = setuid(newuid);
		if ( err ) {
			syslog(LOG_ERR, "Can't set user id %u for user '%s': %s", newuid, userid, strerror(errno));
			fprintf (stderr,"Can't set user id %u for user '%s': %s\n", newuid, userid, strerror(errno));
			exit(255);
		}
	}

} // End of SetPriv

static void run(int socket, time_t twin, time_t t_begin, int report_seq) {
common_flow_header_t	*nf_header;
data_block_header_t		*data_header;
stat_record_t 			stat_record;
time_t 		t_start, t_now;
uint64_t	first_seen, last_seen, export_packets;
uint32_t	bad_packets, file_blocks, blast_cnt, blast_failures;
uint16_t	version;
struct  tm *now;
ssize_t		cnt, input_buffsize;
void 		*in_buff, *out_buff, *writeto;
int 		err, nffd, first;
char 		*string, nfcapd_filename[64], dumpfile[64];
srecord_t	*commbuff;
	
	Init_v5_v7_input();
	Init_v9();

	in_buff  = malloc(NETWORK_INPUT_BUFF_SIZE);
	out_buff = malloc(OUTPUT_BUFF_SIZE);
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

	snprintf(dumpfile, 63, "%s.%u",NF_DUMPFILE, getpid());
	dumpfile[63] = 0;
	nffd = OpenNewFile(dumpfile, &string);
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

	input_buffsize = 0;
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
		if ( input_buffsize == 0 && !done) {
			cnt = recvfrom (socket, in_buff, INPUT_BUFF_SIZE , 0, NULL, 0);
			if ( cnt < 0 && errno != EINTR ) {
				syslog(LOG_ERR, "ERROR: recvfrom: %s", strerror(errno));
				continue;
			}
			input_buffsize = cnt > 0 ? cnt : 0;
		}

		/* Periodic file renaming, if time limit reached or we are done.  */
		t_now = time(NULL);
		if ( ((t_now - t_start) >= twin) || done ) {
			alarm(0);
			now = localtime(&t_start);

			if ( verbose ) {
				// Dump to stdout
				format_file_block_header(out_buff, 0, &string, 0);
			}

			if ( data_header->NumBlocks ) {
				// flush current buffer to disc
				if ( write(nffd, out_buff, sizeof(data_block_header_t) + data_header->size) <= 0 )
					syslog(LOG_ERR, "Failed to write output buffer to disk: '%s'" , strerror(errno));
				else 
					// update successful written blocks
					file_blocks++;
			}

			// Initialize header and write pointer
			data_header->NumBlocks 	= 0;
			data_header->size 		= 0;
			writeto = (void *)((pointer_addr_t)data_header + sizeof(data_block_header_t) );

			snprintf(nfcapd_filename, 64, "nfcapd.%i%02i%02i%02i%02i", 
				now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min);

			t_start += twin;
			alarm(t_start + twin + OVERDUE_TIME - t_now);

			stat_record.first_seen 	= first_seen/1000;
			stat_record.msec_first	= first_seen - stat_record.first_seen*1000;
			stat_record.last_seen 	= last_seen/1000;
			stat_record.msec_last	= last_seen - stat_record.last_seen*1000;

			/* Write Stat Info */
			CloseUpdateFile(nffd, &stat_record, file_blocks, Ident, &string );
			if ( string != NULL ) {
				syslog(LOG_ERR, "%s", string);
			}

			err = rename(dumpfile, nfcapd_filename);
			if ( err ) {
				syslog(LOG_ERR, "Can't rename dump file: %s", strerror(errno));
				if (done) break; else continue;
			}

			if ( launcher_pid ) {
				// Signal launcher
				strncpy(commbuff->fname, nfcapd_filename, FNAME_SIZE);
				commbuff->fname[FNAME_SIZE-1] = 0;
				snprintf(commbuff->tstring, 16, "%i%02i%02i%02i%02i", 
					now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min);
				commbuff->tstring[15] = 0;
				commbuff->tstamp = t_start;

				if ( launcher_alive ) {
					syslog(LOG_DEBUG, "Signal launcher");
					kill(launcher_pid, SIGHUP);
				} else {
					syslog(LOG_ERR, "ERROR: Launcher did unexpectedly!");
				}
			}

			syslog(LOG_INFO,"Ident: '%s' Flows: %llu, Packets: %llu, Bytes: %llu, Sequence Errors: %u, Bad Packets: %u", 
				Ident, stat_record.numflows, stat_record.numpackets, stat_record.numbytes, stat_record.sequence_failure, bad_packets);

			memset((void *)&stat_record, 0, sizeof(stat_record_t));
			bad_packets = 0;
			first_seen 	= 0xffffffffffffLL;
			last_seen 	= 0;
			file_blocks	= 0;

			if ( done ) 
				break;

			nffd = OpenNewFile(dumpfile, &string);
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
				syslog(LOG_ERR, "error condition in '%s', line '%d', cnt: %i", __FILE__, __LINE__ ,cnt);
				if (done) break; else continue;
			}
		}

		/* check for too little data - input_buffsize must be > 0 at this point */
		if ( input_buffsize && input_buffsize < sizeof(common_flow_header_t) ) {
			syslog(LOG_WARNING, "Data length error: too little data for common netflow header. input_buffsize: %i", 
				input_buffsize);
			input_buffsize = 0;
			bad_packets++;
			continue;
		}

		/* enough data? */
		if ( input_buffsize == 0 )
			continue;


		/* Process data - have a look at the common header */
		version = ntohs(nf_header->version);
		switch (version) {
			case 5: // fall through
			case 7: 
				writeto = Process_v5_v7(in_buff, input_buffsize, data_header, writeto, &stat_record, &first_seen, &last_seen);
				break;
			case 9: 
				writeto = Process_v9(in_buff, input_buffsize, data_header, writeto, &stat_record, &first_seen, &last_seen);
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
		input_buffsize = 0;
		export_packets++;

		// flush current buffer to disc
		if ( data_header->size > BUFFSIZE ) {
				syslog(LOG_ERR, "output buffer overflow: expect memory inconsitency");
		}
		if ( data_header->size > OUTPUT_FLUSH_LIMIT ) {
			if ( write(nffd, out_buff, sizeof(data_block_header_t) + data_header->size) <= 0 ) {
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
char	pidfile[MAXNAMLEN];
struct stat fstat;
srecord_t	*commbuff;
struct sigaction act;
int		family, bufflen;
time_t 	twin, t_start, t_tmp;
int		sock, pidf, fd, err, synctime, daemonize, report_sequence;
char	c;
pid_t	pid;

	verbose = synctime = daemonize = 0;
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
	strncpy(Ident, "none", IDENT_SIZE);
	while ((c = getopt(argc, argv, "46whEVI:DB:b:j:l:p:P:t:x:ru:g:")) != EOF) {
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
			case 'E':
				verbose = 1;
				break;
			case 'V':
				printf("%s: Version: %s %s\n%s\n",argv[0], nfdump_version, nfdump_date, rcsid);
				exit(0);
				break;
			case 'D':
				daemonize = 1;
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
					strncpy(pidfile, optarg, MAXNAMLEN-1);
				} else {					// path relative to current working directory
					char tmp[MAXNAMLEN];
					if ( !getcwd(tmp, MAXNAMLEN-1) ) {
						fprintf(stderr, "Failed to get current working directory: %s\n", strerror(errno));
						exit(255);
					}
					tmp[MAXNAMLEN-1] = 0;
					snprintf(pidfile, MAXNAMLEN - 1 - strlen(tmp), "%s/%s", tmp, optarg);
				}
				// pidfile now absolute path
				pidfile[MAXNAMLEN-1] = 0;
				break;
			case 'r':
				report_sequence = 1;
				break;
			case 'l':
				datadir = optarg;
				err  = stat(datadir, &fstat);
				if ( !(fstat.st_mode & S_IFDIR) ) {
					fprintf(stderr, "No such directory: %s\n", datadir);
					break;
				}
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

	SetPriv(userid, groupid);

	if ( strlen(pidfile) ) {
		pidf = open(pidfile, O_CREAT|O_RDWR, 0644);
		if ( pidf == -1 ) {
			fprintf(stderr, "Error opening pid file '%s': %s\n", pidfile, strerror(errno));
			exit(255);
		}
		pid = getpid();
		snprintf(pidstr,31,"%i\n", pid);
		write(pidf, pidstr, strlen(pidstr));
		close(pidf);
	}

	if ( lauch_process ) {
		// for efficiency reason, the process collecting the data
		// and the process launching processes, when a new file becomes
		// available are separated. Communication is done using signals
		// as well as shared memory
		// prepare shared memory
		shmem = mmap(0, sizeof(srecord_t), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
		if ( shmem == (caddr_t)-1 ) {
	  		perror("mmap error");
			exit(255);
		}

		commbuff = (srecord_t *)shmem;
		strncpy(commbuff->ident, Ident, IDENT_SIZE );
		commbuff->ident[IDENT_SIZE - 1] = 0;

		if ((launcher_pid = fork()) == -1) {
			syslog(LOG_ERR, "Can't fork: %s", strerror(errno));
	  		perror("Can't fork()");
		} else if ( launcher_pid == 0 ) { // child

			// close stdin, stdout and stderr
			close(0);
			close(1);
			close(2);
			fd = open("/dev/null",O_RDWR); /* open stdin */
			dup(fd); /* stdout */
			dup(fd); /* stdout */

			launcher((char *)shmem, datadir, lauch_process);
			exit(0);
		} else {
			launcher_alive = 1;
			syslog(LOG_DEBUG, "Launcher forked");
		}
		// parent continues 
	}

	if (argc - optind > 1) {
		usage(argv[0]);
		kill_launcher(launcher_pid);
		exit(255);
	} else {
		/* user specified a pcap filter */
		filter = argv[optind];
	}

	if ( mcastgroup ) 
		sock = Multicast_receive_socket (mcastgroup, listenport, family, bufflen);
	else 
		sock = Unicast_receive_socket(bindhost, listenport, family, bufflen );

	if ( sock == -1 ) {
		kill_launcher(launcher_pid);
		fprintf(stderr,"Terminated due to errors.\n");
		exit(255);
	}

	if ( synctime ) {
		t_tmp = time(NULL);
		t_start = t_tmp - ( t_tmp % twin);
	} else
		t_start = time(NULL);

	if ( daemonize ) {
		verbose = 0;
		if ((pid = fork()) < 0 ) {
	  		perror("Can't fork()");
		} else if (pid) {
	  		if (strlen(pidfile)) {
				pidf = open(pidfile, O_CREAT|O_RDWR, 0644);
				if ( pidf == -1 ) {
					syslog(LOG_ERR, "Error opening pid file: '%s' %s", pidfile, strerror(errno));
					perror("Error opening pid file:");
					kill_launcher(launcher_pid);
					exit(255);
				}
				snprintf(pidstr,31,"%i\n", pid);
				write(pidf, pidstr, strlen(pidstr));
				close(pidf);
			}
	  		exit (0); /* parent */
		} // else -> child continues

		if (setsid() < 0) {
			syslog(LOG_ERR, "Can't create new session: '%s'", strerror(errno));
			exit(255);
		}
		// close stdin, stdout and stderr
		close(0);
		close(1);
		close(2);
		fd = open("/dev/null",O_RDWR); /* open stdin */
		dup(fd); /* stdout */
		dup(fd); /* stderr */
	}

	if ( chdir(datadir)) {
		syslog(LOG_ERR, "Error can't chdir to '%s': %s", datadir, strerror(errno));
		kill_launcher(launcher_pid);
		exit(255);
	}
	done = 0;

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
	run(sock, twin, t_start, report_sequence);
	close(sock);
	syslog(LOG_INFO, "Terminating nfcapd.");

	if ( strlen(pidfile) )
		unlink(pidfile);

	closelog();
	kill_launcher(launcher_pid);
	exit(0);

} /* End of main */
