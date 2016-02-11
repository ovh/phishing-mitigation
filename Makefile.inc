TILERA_VERSION ?= 4.3.3.184581

ifneq ($(filter tilegx,$(shell uname -m)),)
  TILERA_ROOT ?= /usr
else
  TILERA_ROOT ?= /opt/tilera/TileraMDE-$(TILERA_VERSION)/tilegx
endif

#Compilation options
GCC_SANITIZE ?= 0
TMC ?= 1
TILEGX=1
TWOINTERFACE = 0
DEBUG ?= 0
HASH_DEBUG ?= 0
REGEX ?= 1
SOCKET ?= 1
NO_FLOW_HASHING = 1
MODE_VLAN ?= 0
OFP_PROFILING ?= 1
OFP_LOOP_STATISTICS ?= 0
OFP_SYSLOG ?= 1
OVH_HASH_STATS ?= 0
PCAP_DUMP_DIR = /home/ofp_pcap
NO_LTO ?= 0
OVH_LOG_ALLOC ?= 0
OVH_MEMPOOL_HUGEPAGES ?= 1
OVH_MEMPOOL_DEBUG ?= 0

OPT =
#see https://gcc.gnu.org/onlinedocs/gcc/Debugging-Options.html#index-fsanitize_003daddress-666
ifneq ($(GCC_SANITIZE),0)
OPT += -fsanitize=address
#OPT += -fsanitize=thread
OPT += -fsanitize=undefined
endif

COMMON_CPPFLAGS = \
	   -DNO_FLOW_HASHING=${NO_FLOW_HASHING} \
	   -DMODE_VLAN=$(MODE_VLAN) \
	   -DTWOINTERFACE=$(TWOINTERFACE) \
	   -DOFP_PROFILING=${OFP_PROFILING} \
	   -DOVH_HASH_STATS=${OVH_HASH_STATS} \
	   -DOFP_LOOP_STATISTICS=${OFP_LOOP_STATISTICS} \
	   -DREGEX=${REGEX} \
	   -DSOCKET=${SOCKET} \
	   -DOFP_SYSLOG=${OFP_SYSLOG} \
	   -DCOMMIT_ID=$(COMMIT_ID) \
	   -DTILEGX=$(TILEGX) \
	   -DTMC=$(TMC) \
	   -DDEBUG=$(DEBUG) \
	   -DGCC_SANITIZE=$(GCC_SANITIZE) \
	   -DHASH_DEBUG=$(HASH_DEBUG) \
	   -DOVH_LOG_ALLOC=$(OVH_LOG_ALLOC) \
	   -DOVH_MEMPOOL_HUGEPAGES=$(OVH_MEMPOOL_HUGEPAGES) \
	   -DOVH_MEMPOOL_DEBUG=$(OVH_MEMPOOL_DEBUG) \
	   $(OPT)

#	   -Wno-error=unused-variable -Wno-error=unused-but-set-variable

