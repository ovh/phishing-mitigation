# Phishing Mitigation on Tilera

## Summary ##

This is the [Tilera](http://www.tilera.com) part of the OVH abuse tool suite.
This tool aims to prevent known phishing URLs hosted by OVH from being reachable by spammer target.
Each received packet matching : Ip, host and http request-URI will trigger the anti-phishing.
In response, anti-phising will send RST packet to source and destination


## Project structure ##
- /api_script : minimal API to add/remove/list URLs managed by Tilera
- /base : contains not Tilera specific code, but project specific (config, url matching...)
- /common : contains not Tilera specific code, and not project specific (allocator, log, ...)
- /conf : sample configuration files
    - ip.conf : list of target server IPs
    - main.conf : Tilera settings
- /dependencies : external libraries
- /stats-collector : tool running on Tilera and collecting stats to send to [RRDTool](http://oss.oetiker.ch/rrdtool/)
- /tests : unit test on not Tilera specific code + some functional test script

## Build ##
- make clean install
- /etc/init.d/tilera-phishing start

Tested on a TILE-Gx36 with gcc 4.7.2

## Tests ##
[Valgrind](http://valgrind.org/) need to be installed to run test

Under /tests directory run ```make clean all``` to run all unit tests under valgrind checking

```make clean run``` to run tests without valgrind


## Config ##

### main.conf

- edit /etc/tilera-phishing/main.conf
- some settings can be dynamicaly reloaded :
    - in this case a reload is enough to update config :
        - /etc/init.d/tilera-phishing reload
        - or send a SIGUSR1 to process : pkill -SIGUSR1 tilera-phishing -n
- else call
    - /etc/init.d/tilera-phishing restart
- workers : Nb workers to use
- links : comma separated list of network interface to link
    - max 4 interfaces
- bridge_mode
    - 0 : packets received on one network interface are sent using this same network interface
    - 1 : network interfaces are bridged like this :
        - 0 <-> 1
        - 2 <-> 3
        - ie
            - packets received on interface #0 are sent through interface #1 and vice versa
            - same goes for interfaces #2 & #3


### ip.conf
- this file describe a list of target url to RST
- syntax :
- x 10.254.0.8 http://www.example.com/index.html
    - RST http reequest to machine 10.254.0.8 with hostname example.com using GET command to uri /index.html
- after saving ip.conf you should call /etc/init.d/tilera-phishing reload


