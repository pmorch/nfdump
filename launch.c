/*
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
 *  $Id: launch.c 70 2006-05-17 08:38:01Z peter $
 *
 *  $LastChangedRevision: 70 $
 *	
 *
 */

#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "launch.h"

static int done, launch, child_exit;

static void SignalHandler(int signal);

static char *cmd_expand(srecord_t *InfoRecord, char *datadir, char *process);

static void cmd_parse(char *buf, char **args);

static void cmd_execute(char **args);

#define MAXARGS 256
#define MAXCMDLEN 4096

static void SignalHandler(int signal) {

	switch (signal) {
		case SIGTERM:
			// in case the process will not terminate, we
			// kill the process directly after the 2nd TERM signal
			if ( done > 1 )
				exit(234);
			done++;
			break;
		case SIGHUP:
			launch = 1;
			break;
		case SIGCHLD:
			child_exit = 1;
			break;
	}
	
} /* End of IntHandler */

/*
 * Expand % placeholders in command string
 * expand the memory needed in the command string and replace placeholders
 * prevent endless expansion
 */
static char *cmd_expand(srecord_t *InfoRecord, char *datadir, char *process) {
char *q, *s, tmp[16];
int  i;

	q = strdup(process);
	if ( !q ) {
		perror("Process cmdline");
		return NULL;
	}
	i = 0;

	while ( q[i] ) {
		if ( (q[i] == '%') && q[i+1] ) {
			// replace the %x var
			switch ( q[i+1] ) {
				case 'd' : 
					s = datadir;
					break;
				case 'f' :
					s = InfoRecord->fname;
					break;
				case 't' :
					s = InfoRecord->tstring;
					break;
				case 'u' :
#if defined __OpenBSD__ || defined __FreeBSD__
					snprintf(tmp, 16, "%i", InfoRecord->tstamp);
#else
					snprintf(tmp, 16, "%li", InfoRecord->tstamp);
#endif
					tmp[15] = 0;
					s = tmp;
					break;
				case 'i' : 
					s = InfoRecord->ident;
					break;
				default:
					syslog(LOG_ERR, "Unknown format token '%%%c'\n", q[i+1]);
					s = NULL;
			}
			if ( s ) {
				q = realloc(q, strlen(q) + strlen(s));
				if ( !q ) {
					perror("Process cmdline");
					return NULL;
				}
				// be a bit paranoid and prevent endless expansion
				if ( strlen(q) > MAXCMDLEN ) {
					// this is fishy
					syslog(LOG_ERR, "Error: cmdline too long!\n");
					return NULL;
				}
				memmove(&q[i] + strlen(s), &q[i+2], strlen(&q[i+2]) + 1);   // include trailing '0' in memmove
				memcpy(&q[i], s, strlen(s));
			}
		}
		i++;
	}

	return q;

} // End of cmd_expand

/*
 * split the command in buf into individual arguments.
 */
static void cmd_parse(char *buf, char **args) {
int i, argnum;

	i = argnum = 0;
    while ( (i < MAXCMDLEN) && (buf[i] != 0) ) {

        /*
         * Strip whitespace.  Use nulls, so
         * that the previous argument is terminated
         * automatically.
         */
        while ( (i < MAXCMDLEN) && ((buf[i] == ' ') || (buf[i] == '\t')))
            buf[i++] = 0;

        /*
         * Save the argument.
         */
		if ( argnum < MAXARGS ) 
        	args[argnum++] = &(buf[i]);

        /*
         * Skip over the argument.
         */
        while ( (i < MAXCMDLEN) && ((buf[i] != 0) && (buf[i] != ' ') && (buf[i] != '\t')))
            i++;
    }

	if ( argnum < MAXARGS ) 
    	args[argnum] = NULL;

	if ( (i >= MAXCMDLEN) || (argnum >= MAXARGS) ) {
		// for safety reason, disable the command
    	args[0] = NULL;	
		syslog(LOG_ERR, "Launcher: Unable to parse command: '%s'", buf);
	}

} // End of cmd_parse

/*
 * cmd_execute
 * spawn a child process and execute the program.
 */
static void cmd_execute(char **args) {
int pid;

    // Get a child process.
	if ((pid = fork()) < 0) {
		syslog(LOG_ERR, "Can't fork: %s", strerror(errno));
        return;
	}

    if (pid == 0) {	// we are the child
        execvp(*args, args);
		syslog(LOG_ERR, "Can't execvp: %s: %s", args[0], strerror(errno));
        exit(1);
    }

	// we are the parent
	/* empty */

} // End of cmd_execute

void launcher (char *commbuff, char *datadir, char *process) {
struct sigaction act;
char 		*cmd, *s;
char 		*args[MAXARGS];
int 		i, pid, stat;
srecord_t	*InfoRecord, TestRecord;

	InfoRecord = (srecord_t *)commbuff;

	syslog(LOG_INFO, "Launcher: Startup.");
	done = launch = child_exit = 0;

	// check for valid command expansion
	strncpy(TestRecord.fname, "test", FNAME_SIZE-1);
	TestRecord.fname[FNAME_SIZE-1] = 0;
	strncpy(TestRecord.tstring, "200407110845", 15);	
	TestRecord.tstring[15] = 0;
	TestRecord.tstamp = 1;
	cmd = cmd_expand(&TestRecord, datadir, process);
	if ( cmd == NULL ) {
		syslog(LOG_ERR, "Launcher: Unable to expand command: '%s'", process);
		exit(255);
	}

	cmd_parse(cmd, args);
	i = 0;
	s = args[i];

	/* Signal handling */
	memset((void *)&act,0,sizeof(struct sigaction));
	act.sa_handler = SignalHandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGCHLD, &act, NULL);	// child process terminated
	sigaction(SIGTERM, &act, NULL);	// we are done
	sigaction(SIGINT, &act, NULL);	// we are done
	sigaction(SIGHUP, &act, NULL);	// run command

	while ( !done ) {
		// sleep until we get signaled
		select(0, NULL, NULL, NULL, NULL);
		syslog(LOG_DEBUG, "Launcher: Wakeup");
		if ( launch ) {	// SIGHUP
			launch = 0;

			// Expand % placeholders
			cmd = cmd_expand(InfoRecord, datadir, process);
			if ( cmd == NULL ) {
				syslog(LOG_ERR, "Launcher: Unable to expand command: '%s'", process);
				continue;
			}
			// printf("Launcher: run command: '%s'\n", cmd);
			syslog(LOG_DEBUG, "Launcher: run command: '%s'", cmd);

			// prepare args array
			cmd_parse(cmd, args);
			if ( args[0] )
				cmd_execute(args);
			// else cmd_parse already reported the error
		}
		if ( child_exit ) {
			while ( (pid = waitpid (-1, &stat, 0)) > 0  ) {
				syslog(LOG_DEBUG, "Launcher: child %i terminated: %i", pid, stat);
			}
			child_exit = 0;
		}
	}

	waitpid (-1, &stat, 0);

	// we are done
	syslog(LOG_INFO, "Launcher: Terminating.");

} // End of launcher
