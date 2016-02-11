from multiprocessing import Process, Queue
from . Printing import print_verbose
import json

#
# IpConfigFile
#
# This class manage the vac-game ip configs files
# We don't keep opened file descriptor on file,
# any file operation open an close the target file
# You have to handle the exceptions
class IpConfigFile:

  #
  # __init__
  #
  # Initialize the object with the name of the target file
  def __init__(self, filename):
    self.filename = filename
    self.rules = []

  #
  # load
  #
  # Load the target file configuration
  # also load comment and empty line
  # You have to handle the exceptions
  def load(self):

    # Clear the rules array
    self.rules[:] = []

    f = open(self.filename, 'r')
    for line in f:
      entry = line.strip() # Remove \n
      #if entry and entry[0] != '#': #remove empty line and comment line
      self.rules.append(entry)
    f.close()

  #
  # get_not_empty_rules
  #
  def get_not_empty_rules(self):

    rules = []

    for line in self.rules:
      entry = line.strip() # Remove \n
      if entry and entry[0] != '#': #remove empty line and comment line
        rules.append(entry)
    return rules

  #
  # save
  #
  # Save the current configuration into the target file
  def save(self):
    f = open(self.filename, 'w')
    for cmd in self.rules:
      f.write("%s\n" % cmd)
    f.close()

  #
  # has_rule
  #
  # Check if a rule is into the object rules
  # The file should be loaded
  def has_rule(self, rule):
    if rule in self.rules:
      return True
    return False

  #
  # add_rule
  #
  # Add a new entry into the object rules
  # You have to call save() to write the change on the target file
  def add_rule(self, rule):

    # Don't write an entry twice
    if self.has_rule(rule):
      return
    self.rules.append(rule)

  #
  # remove_rule
  #
  # Remove an entry from the object rules
  # You have to call save() to write the change on the target file
  def remove_rule(self, rule):
    if self.has_rule(rule):
      self.rules.remove(rule)

  #
  # add_rules
  #
  # Add new entries into the object rules
  # You have to call save() to write the change on the target file
  def add_rules(self, targets):
    for target in targets:
      value = target.strip()
      self.add_rule(value)

  #
  # remove_rules
  #
  # Remove entries from the object rules
  # You have to call save() to write the change on the target file
  def remove_rules(self, targets):
    for target in targets:
      value = target.strip()
      self.remove_rule(value)

  #
  # add_rules_from_json
  #
  # Add new entries into the object rules
  # You have to call save() to write the change on the target file
  def add_rules_from_json(self, jsonString):
    jsonObject = json.loads(jsonString)
    rules = []
    for target in jsonObject["targets"]:
      cmd = "x " + target["ip"] + " " + target["url"]
      rules.append(cmd.strip())
    self.add_rules(rules)

  #
  # remove_rules_from_json
  #
  # Remove entries from the object rules
  # You have to call save() to write the change on the target file
  def remove_rules_from_json(self, jsonString):
    jsonObject = json.loads(jsonString)
    rules = []
    for target in jsonObject["targets"]:
      cmd = "x " + target["ip"] + " " + target["url"]
      rules.append(cmd.strip())
    self.remove_rules(rules)

  #
  # diff
  #
  # Make a diff an other file
  # The output format is formated to be applied to the other file
  def diff(self, other):
    diff = []
    print_verbose("Checking from %s to %s" % (self.filename, other.filename))
    for rule in self.rules:
      if len(rule) != 0 and rule[0] != '#':
        if other.has_rule(rule) is False:
          diff.append("+%s" % rule)

    print_verbose("Checking from %s to %s" % (other.filename, self.filename))
    for rule in other.rules:
      if len(rule) != 0 and rule[0] != '#':
        if self.has_rule(rule) is False:
          diff.append("-%s" % rule)

    return diff

