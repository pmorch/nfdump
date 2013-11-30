#!/usr/bin/perl
#
#   Sample script to clean old data.
#   Run this script each hour to cleanup old files to make room for
#   new data. When max_size_spool is reached the oldest files are
#   deleted down to high_water.
#
#   Copyright (c) 2004, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
#   All rights reserved.
#   
#   Redistribution and use in source and binary forms, with or without 
#   modification, are permitted provided that the following conditions are met:
#   
#    * Redistributions of source code must retain the above copyright notice, 
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice, 
#      this list of conditions and the following disclaimer in the documentation 
#      and/or other materials provided with the distribution.
#    * Neither the name of SWITCH nor the names of its contributors may be 
#      used to endorse or promote products derived from this software without 
#      specific prior written permission.
#   
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
#   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
#   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
#   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
#   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
#   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
#   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
#   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
#   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
#   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
#   POSSIBILITY OF SUCH DAMAGE.
#   
#   $Author$
#
#   $Id$
#
#   $LastChangedRevision$

use strict;

# Configuration
# Define all the netflow sources you have
my @flow_sources = ( 'router1',  'router2',  'router3',  'router4' );

# 
# Linux does not support spool devices larger than 1TB. If you still want
# your spool device larger than 1TB you need to split it into two different
# drives of equally size. New data is stored in flow_base_dir, and shifted 
# into carry_base_dir when max_size_spool is reached. 
# If you do not have two spool devices set carry_base_dir to 'undef'
# At least set flow_base_dir to your spool directory
my $flow_base_dir        = '/netflow0/nfsen/spool';
my $carry_base_dir		 = undef;

# To which size may flow_base_dir and carry_base_dir grow
my $max_size_spool       = 0.95 * 1024 * 1024 * 1024 * 1024;	# 0.95TB

my $high_water			 = 0.9;	# when we delete files, we delete down to max_size * high_water

# End of configuration

my ($date_extension);
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
$mon++;
$date_extension  = $year += 1900;
$date_extension .= $mon  < 10 ? "0$mon"  : "$mon";
$date_extension .= $mday < 10 ? "0$mday" : "$mday";
$date_extension .= $hour < 10 ? "0$hour" : "$hour";
$date_extension .= $min  < 10 ? "0$min"  : "$min";

sub CleanDir {
	my $flow_base_dir  = shift;
	my $carry_base_dir = shift;
	my $max_size	   = shift;

	if ( defined $carry_base_dir ) {
		CleanDir($carry_base_dir, undef, $max_size);
	}

    my $ksize = $max_size / 1024;
    print "Clean Dir $flow_base_dir up to $ksize k\n";
	#
	# Get a list of all argus files in all directories
	my @AllFiles;
	foreach my $flow ( @flow_sources ) {
		opendir(DIR, "$flow_base_dir/$flow" ) || die "can't opendir '$flow_base_dir/$flow' : $!";
		push @AllFiles, map{ "$flow_base_dir/$flow/" . $_} grep { /^nf[\w]*\.\d+$/ && -f "$flow_base_dir/$flow/$_" } readdir(DIR);
		closedir DIR;
	}
	
	if ( scalar(@AllFiles) == 0 ) {
		warn "No files to process\n";
		return;
	}
	
	#
	# Create a hash with key = filename and value = filesize
	my %File_Sizes = map { $_ => (stat($_))[7] } @AllFiles;
	
	#
	# calculate total size of all files
	my $total_size = 0;
	foreach my $file ( keys %File_Sizes ) {
		# print "$file: $File_Sizes{$file}\n";
		$total_size += $File_Sizes{$file};
	}
	$ksize = $total_size / 1024;
	print "Total Size: $ksize k\n";
	
	#
	# check if we are within max_size
	if ( $total_size > $max_size ) {
		print "Total size $total_size > $max_size. Cleaning up ...\n";
		# hmm .. we need to delete some files
		# we do this by sorting all files accoring their mtime
		# and delete until we have max_size * high_water
		my %mtime_stamp = map { $_ => (stat($_))[9] } @AllFiles;
		my @sorted_mtime = sort { $mtime_stamp{$a} <=> $mtime_stamp{$b} } keys %mtime_stamp;
		my $max_allowed = $max_size * $high_water;
		my $file;
		do {
			my $what;
			my ( $base, $source, $filename, $command );
			$file = shift @sorted_mtime;
			if ( defined $carry_base_dir ) {
				$what = 'Moving';
				( $source, $filename ) = $file =~ m#.+/(\w+)/([^/]+)$#;
				$command = "/bin/mv $file $carry_base_dir/$source/$filename";
				system("$command");
				$command = "/bin/mv ${file}.stat $carry_base_dir/$source/${filename}.stat";
				system("$command");
			} else {
				$what = 'Unlinking';
				unlink $file;
				unlink "$file.stat" if -f "$file.stat";
			}
			if ( -f "$file.stat" ) {
				print "$what $file and stat file. size: $File_Sizes{$file}  New total: $total_size\n";
			} else {
				print "$what $file size: $File_Sizes{$file}  New total: $total_size\n";
			}
			$total_size -= $File_Sizes{$file};
		} while $total_size > $max_allowed;
	}
	
} # End of CleanDir

#
# Main starts here
#

# Expire old data
&CleanDir($flow_base_dir, $carry_base_dir, $max_size_spool);

