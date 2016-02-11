#!/usr/bin/perl

use strict;
use POSIX qw(strftime);
use RRDs;

use CGI;
my $q = new CGI;

defined $q->param('tilera') or die "Param 'tilera' is required !";

$0=~/^(.+[\\\/])[^\\\/]+[\\\/]*$/;
my $cgidir= $1 || "./";

my $data_dir = $cgidir."/".$q->param('tilera')."/";
my $rrd_file = $q->param('tilera').".rrd";
my $step = 1;
if (defined $q->param('step'))
{
  $step = $q->param('step');
}
my $timestamp;
my $start;
my $end;
if (defined $q->param('start'))
{
  $start = $q->param('start');
}
else
{
  $timestamp = time;
  $start = $timestamp - 3600;
}
if (defined $q->param('end'))
{
  $end = $q->param('end');
}
else
{
  $end = $start + 3600;
}

print <<"EOF";
Content-Type: text/html 
Refresh: 500
Pragma: no-cache
EOF
# Expires header calculation stolen from CGI.pm
print strftime("Expires: %a, %d %b %Y %H:%M:%S GMT\n",
        gmtime(time+$step));

print "\n";


my ($start,$step,$names,$data) = RRDs::fetch($data_dir.$rrd_file, "AVERAGE", "-s $start", "-e $end", "-r $step");
my $ERR=RRDs::error;
die "Error fetching data from rrd : $ERR\n" if $ERR;

for my $line (@$data) {
  print "${start};";
  $start += $step;
  for my $val (@$line) {
    printf "%u;", $val;
  }
  print "\n";
}

