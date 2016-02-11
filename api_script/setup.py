#!/usr/bin/env python

#build : python setup.py sdist
#install from dist dir : python setup.py install

from setuptools import setup
from setuptools.command.install import install
from distutils.core import setup

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class CustomInstallCommand(install):
    def run(self):
        install.run(self)
        #cert_path = self.install_data + "cert/"
        cert_path = "/etc/tilera-phishing/cert/"
        print bcolors.WARNING + "Be sure to copy your certificate files here :" + bcolors.ENDC
        print bcolors.WARNING + cert_path + "ca.crt" + bcolors.ENDC
        print bcolors.WARNING + cert_path + "ca.key" + bcolors.ENDC


setup(name='api_server',
    version='1.0',
    description='tilera-phishing api server',
    scripts = [
      'api_server.py',
      'api_server_loop'
    ],
    packages = ['ofp_api_server_script'],
    cmdclass={
        'install': CustomInstallCommand,
    },
)

