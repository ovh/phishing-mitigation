#ifndef __OFP_MAIN_H__
#define __OFP_MAIN_H__


// Packet disposition is either forwarding or discarding.
// Default is to discard.
extern int packet_drop;


#if TMC
#if MODE_VLAN
// For fowarding, default ys to swap vlan
extern int packet_vlan_swap;
// For fowarding, only forward from that vlan
// For fowarding, only forward to that vlan
extern uint16_t packet_vlan_swap1;
extern uint16_t packet_vlan_swap2;
#endif //MODE_VLAN
extern cpu_set_t normal_cpus;
extern cpu_set_t dataplane_cpus;
#endif //TMC


#if OFP_PROFILING
extern uint64_t *cycles_in_packet_work;
extern uint64_t *calls_to_packet_work;
#endif

#if OFP_LOOP_STATISTICS
extern unsigned limit_packets;
extern uint32_t *loop_counts_busy;
extern uint32_t *loop_counts_idle;
#endif


#endif //__OFP_MAIN_H__
