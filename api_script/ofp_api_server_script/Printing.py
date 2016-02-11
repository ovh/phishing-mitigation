import sys

#
# is_verbose
#
# Return True is the program was started with option:
# -V, --verbose, -d or --diff
def is_verbose():
  if "-V" in sys.argv or "--verbose" in sys.argv:
    return True
  # diff mode is always verbose
  if "--diff" in sys.argv or "-d" in sys.argv:
    return True
  return False
#
# print_error
#
# Used to return an error
def print_error(msg=""):
    sys.stderr.write("ERROR %s\n" % msg)

#
# fatal_error
#
# print a fatal error , and exit with -1
def fatal_error(msg=""):
  sys.stderr.write("FATALERROR %s\n" % msg)
  sys.exit(-1)

#
# print_out
#
# Used to print output info without exiting program
def print_out(msg):
  print(msg)

#
# print_verbose
#
# Used to print output info in verbose mode
def print_verbose(msg):
  if is_verbose():
    print(msg)

#
# print_done
#
# Used to tell an action is done
def print_done(retcode=0):
  if is_verbose() is True:
    print("DONE")
  sys.exit(retcode)
