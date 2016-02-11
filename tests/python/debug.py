#!/usr/bin/env python
# coding=utf-8

#Test code, to debug only

from ofp_api_server_script.IpConfigFile import IpConfigFile
from ofp_api_server_script.Printing import print_out, print_verbose, is_verbose, print_error
from ofp_api_server_script.SocketMessage import send_lines, list_rules

from subprocess import call

import json
import os
#import requests
import urllib2
import getopt
import sys
import socket

tilegx = os.uname()[4] == "tilegx"

ip_config_file = "/etc/tilera-phishing/ip.conf"
if not tilegx:
  ip_config_file = "../conf/ip.conf"
reload_cmd = "/etc/init.d/tilera-phishing reload"

def api_add_test():
  print_out("api_add_test...");

  app_target_host = "localhost";
  app_port = 443;
  if not tilegx:
    app_target_host = "localhost";
    app_port = 4443;

  try:
    opts, args = getopt.getopt(sys.argv[1:],"hp:t:",["port=", "target="])
  except getopt.GetoptError:
    print '{0} -t <target host> -p <port>'.format(sys.argv[0])
    sys.exit(2)
  for opt, arg in opts:
    if opt == '-h':
      print '{0} -t <target host> -p <port>'.format(sys.argv[0])
      sys.exit()
    elif opt in ("-p", "--port"):
      app_port = int(arg)
    elif opt in ("-t", "--target"):
      app_target_host = arg
  print 'app_port %d' % app_port
  print 'app_target_host %s' % app_target_host


  data = {
   'targets': [
      {
        "ip" : "192.168.0.123",
        #"url" : "http://www.example2.com",
        #"url" : "http://vps117860.ovh.net/test/ÃÂ/phishing2",
        "url" : "http://vps117860.ovh.net/test/ß/phishing2",
      }
    ]
  }
  url = 'https://{0}:{1}/v1/targets/add'.format(app_target_host, app_port);

  #requests.post(url, json=data)

  req = urllib2.Request(url, json.dumps(data), {'Content-Type': 'application/json'} )
  response = urllib2.urlopen(req)
  print_out("urlopen() done")
  print_out(response)

def socket_send_test_lines(lines):
  if not len(lines):
    lines = [
      '+x 10.254.1.1 http://www.example_1.com/newone.html',
      '+x 10.254.1.2 http://www.example_2.com/newone.html',
      '+x 10.254.1.3 http://www.example_3.com/newone.html',
      '+x 10.254.1.4 http://www.example_4.com/newone.html',
      '+x 10.254.1.5 http://www.example_5.com/newone.html',
      '+x 10.254.1.6 http://www.example_6.com/newone.html',
      '+x 10.254.1.7 http://www.example_7.com/newone.html',
      '+x 10.254.1.8 http://www.example_8.com/newone.html',
      '+x 10.254.1.9 http://www.example_9.com/newone.html',

      '-x 10.254.1.1 http://www.example_1.com/newone.html',
      '-x 10.254.1.2 http://www.example_2.com/newone.html',
      '-x 10.254.1.3 http://www.example_3.com/newone.html',
      '-x 10.254.1.4 http://www.example_4.com/newone.html',
      '-x 10.254.1.5 http://www.example_5.com/newone.html',
      '-x 10.254.1.6 http://www.example_6.com/newone.html',
      '-x 10.254.1.7 http://www.example_7.com/newone.html',
      '-x 10.254.1.8 http://www.example_8.com/newone.html',
      '-x 10.254.1.9 http://www.example_9.com/newone.html',
    ]
  send_lines(lines)
  print_out("socket_test...")

def socket_send_test_from_file(file_name):
  print_out("socket_send_test_from_file...")
  with open(file_name) as f:
    lines = [ '+{0}'.format(line.rstrip('\n')) for line in f]
#    lines = f.read().splitlines()
    socket_send_test_lines(lines)

def socket_send_test():
  socket_send_test_lines([])


def socket_list_test():
  lines = list_rules()
  print_out("result : ")
  for line in lines:
    print_out(line)
  print_out("socket_list_test...")



api_add_test()
#socket_send_test()
#socket_send_test_from_file("../socket_server/ip.conf")
#socket_list_test()

