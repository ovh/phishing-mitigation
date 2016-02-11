import sys
import socket
import struct

from ofp_api_server_script.Printing import print_out, print_verbose, is_verbose, print_error

#send a command, with explicit format : { uint32 size, buffer[size] }
#with buffer size given at begining, client can easily decode data, and know when data are still pending, or when buffer have been split over multiple packet
def send_command(s, command):
  s.sendall(struct.pack(">I", len(command)))
  s.sendall(command)

def send_lines_from(s, lines):
  data = s.recv(1024)
  print 'Received', repr(data)
  #print 'Sending lines count = ', len(lines)
  if not data.startswith('ofp_socket v1'):
    return
  for line in lines:
    #print 'Sending : ', line
    send_command(s, line + '\n')

def send_lines(lines):
  HOST = '127.0.0.1'    # The remote host
  PORT = 9996              # The same port as used by the server
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((HOST, PORT))
  send_lines_from(s, lines)
  s.close()
  print_out("send_lines() done")


def list_rules_from(s):
  data = s.recv(1024)
  print 'step 0 Received', repr(data)
  rules = []
  if not data.startswith('ofp_socket v1'):
    return rules
  send_command(s, "list")
  data = s.recv(1024)
  current_remaining = "" #var to store what data is currently remaining, thoses data will need to be prepend to next incoming data
  print 'step 1 Received', repr(data)
  while True:
    elements = data.split('\n')
    previous_remaining = current_remaining; #store remaining data so we can clear safely current_remaining
    current_remaining = ""
    if len(elements):
      if previous_remaining:
        elements[0] = previous_remaining + elements[0]; #if there was data remaining from a previous recv(), then prepend it to first item
      #if last element (index -1) does not finish by \n, it's an incomplete data, so we store its content, and it will be prepend to next received data
      if not data.endswith("\n"):
        current_remaining = elements[-1]
        del elements[-1] #remove this incomplete data
    for element in elements:
      element = element.strip(' ')
      if not element:
        continue
      print 'parsed', repr(element)
      if element.startswith('list start'):
        pass
      elif element.startswith('list end'):
        print_out("read_lines() done")
        return rules
      else:
        rules.append(element)
    data = s.recv(1024)
    print 'step 2 Received', repr(data)

def list_rules():
  HOST = '127.0.0.1'    # The remote host
  PORT = 9996              # The same port as used by the server
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((HOST, PORT))
  rules = list_rules_from(s)
  s.close()
  return rules

