#ifndef __OFP_CHANNELS_H__
#define __OFP_CHANNELS_H__

#include "ovh_common.h"
#include "ofp_defines.h"
#include "ofp_config.h"

#if TMC

#if TILEGX
#include <gxio/mpipe.h>
#else
#include <netio/netio.h>
#endif

extern int *channels;
extern int nb_interfaces;

static INLINE int ofp_netio_get_output_channel(int inputChannel)
{

  if(config_bridge_mode)
  {
    //swap channel 0<->1
    if (inputChannel == channels[0])
        return channels[1];
    else if (inputChannel == channels[1])
      return channels[0];
    //swap channel 2<->3
    else if (inputChannel == channels[2])
      return channels[3];
    else if (inputChannel == channels[3])
      return channels[2];
    else
    {
      OVH_ASSERT(false); //unknown channel
    }
  }

  int channel = inputChannel;
  return channel;
}

static INLINE gxio_mpipe_equeue_t* ofp_netio_get_equeue_from_channel(gxio_mpipe_equeue_t **equeues, int channel)
{
  int outputChannel = ofp_netio_get_output_channel(channel);

  gxio_mpipe_equeue_t* equeue = equeues[outputChannel];

  return equeue;
}

static INLINE int ofp_netio_channel_to_index(int channel)
{
  for (int i = 0; i < nb_interfaces; ++i)
  {
    if(channels[i] == channel) return i;
  }

  OVH_ASSERT(false); //unknown channel
  return -1;
}

#endif //TMC

#endif //__OFP_CHANNELS_H__
