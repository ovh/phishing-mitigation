#!/usr/bin/python -u

import json, getopt
import sys, os
from subprocess import call

from ofp_api_server_script.IpConfigFile import IpConfigFile
from ofp_api_server_script.Printing import print_out, print_verbose, is_verbose, print_error
from ofp_api_server_script.SocketMessage import send_lines, list_rules

from tornado.ioloop import IOLoop
from tornado.httpserver import HTTPServer
from tornado.web import RequestHandler, Application, url




tilegx = os.uname()[4] == "tilegx"

use_ssl = True
app_port = 443
crt_cert_file = "/etc/tilera-phishing/cert/ca.crt"
key_cert_file = "/etc/tilera-phishing/cert/ca.key"


if not tilegx:
  app_port = 4443
  crt_cert_file = "../conf/ca.crt"
  key_cert_file = "../conf/ca.key"

reload_cmd = "/etc/init.d/tilera-phishing reload"

jsonSample = """{
  "targets":[
    {
      "ip" : "192.168.0.2",
      "url" : "http://www.example.com/index.html"
    },
    {
      "ip" : "192.168.0.1",
      "url" : "http://www.example.com/phish.html"
    }
  ]
}"""

class HomeHandler(RequestHandler):
  def get(self):
    self.write("""
        <a href="/v1/targets"> /v1/targets</a> : list all targets<br/>
        <a href="/v1/targets/add"> /v1/targets/add</a> : add a set of targets<br/>
        <a href="/v1/targets/remove"> /v1/targets/remove</a> : remove a set of targets<br/>
      """)

class ListHandler(RequestHandler):
  def get(self):
    targets = list_rules()
    rules = []

    for target in targets:
      elems = target.split(" ", 2)
      if len(elems) >= 3:
        rules.append({'ip' : elems[1], 'url' : elems[2]})

    res = json.dumps({ 'targets' : rules });
    self.set_header("Content-Type", "application/json")
    self.write(res);


class AddHandler(RequestHandler):
  def get(self):
    self.write('<html><body><form action="/v1/targets/add" method="POST">'
               '<TEXTAREA name="message" rows=40 cols=80>'
               + jsonSample +
               '</TEXTAREA>'
               '<input type="submit" value="Submit">'
               '</form></body></html>')

  def post(self):
    message = self.request.body
    print(message)
    jsonObject = json.loads(message)
    rules = []
    for target in jsonObject["targets"]:
      cmd = "+x " + target["ip"] + " " + target["url"]
      rules.append(cmd.strip().encode('utf-8'))
    send_lines(rules)


    self.set_header("Content-Type", "application/json")
    self.write('{"done":true}')

class RemoveHandler(RequestHandler):
  def get(self):
    self.write('<html><body><form action="/v1/targets/remove" method="POST">'
               '<TEXTAREA name="message" rows=40 cols=80>'
               + jsonSample +
               '</TEXTAREA>'
               '<input type="submit" value="Submit">'
               '</form></body></html>')

  def post(self):
    message = self.request.body
    print(message)
    jsonObject = json.loads(message)
    rules = []
    for target in jsonObject["targets"]:
      cmd = "-x " + target["ip"] + " " + target["url"]
      rules.append(cmd.strip().encode('utf-8'))
    send_lines(rules)

    self.set_header("Content-Type", "application/json")
    self.write('{"done":true}')

def make_app():
  return Application([
    url(r"/", HomeHandler),
    url(r"/v1/targets/add", AddHandler),
    url(r"/v1/targets/remove", RemoveHandler),
    url(r"/v1/targets", ListHandler),
    ])

def parse_options():
  try:
    opts, args = getopt.getopt(sys.argv[1:],"hup:",["port=","unsecure"])
  except getopt.GetoptError:
    print_out("-p <port>")
    sys.exit(2)
  for opt, arg in opts:
    if opt == '-h':
      print_out("-p <port> : (--port) specify http server port : default : 443")
      print_out("-u : (--unsecure) use http instead of https : default : disabled")
      sys.exit()
    elif opt in ("-p", "--port"):
      global app_port
      app_port = int(arg)
    elif opt in ("-u", "--unsecure"):
      global use_ssl
      use_ssl = False

def main():
  parse_options()
  print_out("Starting server on port " + str(app_port));
  print_out("Ssl : {0}".format("Enabled" if use_ssl else "Disabled"));
  app = make_app()
  ssl_ctx = {
    "certfile": crt_cert_file,
    "keyfile": key_cert_file,
  }
  if use_ssl:
    http_server = HTTPServer(app, ssl_options=ssl_ctx)
  else:
    http_server = HTTPServer(app)
  http_server.listen(app_port)
  IOLoop.instance().start()

main()
