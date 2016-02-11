#!/usr/bin/perl

use strict;
use POSIX qw(strftime);
use RRDs; #apt-get install librrds-perl

use CGI;
my $q = new CGI;

print <<"EOF";
Content-Type: text/html 
Refresh: 500
Pragma: no-cache

EOF

if (defined $q->param('tilera'))
{
    my $tilera = $q->param('tilera');
    my $now = time;
    my $step = defined $q->param('step') ? $q->param('step') : 1; # In seconds

    print <<"EOF";
    <html>
    <head>
      <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
      <script src="js/jquery.min.js" type="text/javascript"></script>
      <script src="js/highcharts.js" type="text/javascript"></script>
      <script src="js/biginteger.js" type="text/javascript"></script>
      <script src="js/tilera.js" type="text/javascript"></script>
      <link rel="stylesheet" type="text/css" media="screen" href="css/jquery.datetimepicker.css">
      <script src="js/jquery.datetimepicker.js" type="text/javascript"></script>
      <script type="text/javascript">

          \$(document).ready(function() {
EOF
            print "build_graphs(\"$tilera\", ". $step * 1000 .");";
    print <<"EOF";
          });

          \$(function() {
            \$( "#fromPicker" ).datetimepicker();
          });
          \$(function() {
            \$( "#toPicker" ).datetimepicker();
          });
          function fromToSubmit()
          {
            var start = \$( "#fromPicker" ).val();
            var end = \$( "#toPicker" ).val();
            var date = new Date(start);
            start = date.getTime()/1000;
            date = new Date(end);
            end = date.getTime()/1000;
            window.location = "tilera.cgi?tilera=$tilera&start="+start+"&end="+end+"&step="+\$("#stepPicker").val()
          }
      </script>
    </head>
    <body>
      <div>
        [<a href='?tilera=$tilera'>Last 2 hours</a>]
EOF
        print "[<a href='?tilera=$tilera&start=" . ($now - (3600 * 6)) . "&end=$now'>Last 6 hours</a>]";
        print "[<a href='?tilera=$tilera&start=" . ($now - (3600 * 12)) . "&end=$now'>Last 12 hours</a>]";
        print "[<a href='?tilera=$tilera&start=" . ($now - (3600 * 24)) . "&end=$now&step=300'>Last 24 hours</a>]";
        print "[<a href='?tilera=$tilera&start=" . ($now - (3600 * 24 * 7)) . "&end=$now&step=300'>Last 7 days</a>]";
      print <<"EOF";
      </div>
      <form method='GET'>
        From : <input type='text' name='start' id='fromPicker'/>
        To : <input type='text' name='end' id='toPicker'/>
        Step : <select id='stepPicker'>
                <option>1</option>
                <option>10</option>
                <option>60</option>
                <option>300</option>
               </select>
        <input type='button' value='submit' onClick='fromToSubmit()'/>
      </form>
      <div id="chartTrafficIn" style="width: 800px; height: 400px; margin: 0 auto"></div>
      <div id="tileraHealth" style="width: 800px; height: 400px; margin: 0 auto"></div>
      <div id="chartPhishPackets" style="width: 800px; height: 400px; margin: 0 auto"></div>
      <div id="chartPhishAPI" style="width: 800px; height: 400px; margin: 0 auto"></div>
      <div id="chartIpp" style="width: 800px; height: 400px; margin: 0 auto"></div>
      <div id="chartPackets" style="width: 800px; height: 400px; margin: 0 auto"></div>
      <div id="chartPerf" style="width: 800px; height: 400px; margin: 0 auto"></div>
    </body>
    </html>
EOF
}
else
{
    print "Parameter 'tilera' is required";
}
