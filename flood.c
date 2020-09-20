#include "flood.h"
#include <stdio.h>
#include <stdlib.h>
#include "sender.h"
void disableServer(libnet_t *l,u_long sniffIp, u_long serverIp)
{
    //Sends 10 packet to the server with payload disable
    for(int i=0; i<11; i++)
    {   
        tcpTagCreate(l,libnet_get_prand(LIBNET_PRu16),(u_int16_t)513,
                                    1+i,0,
                                    "disable", 7,
                                    TH_SYN);

        ipTagCreate(l,(u_int32_t)sniffIp,(u_int32_t)serverIp,
                                   NULL, (u_int32_t)7 );
        sendPacket(l);
        usleep(200); 
    }
    usleep(2000); 
                    
}

void enableServer(libnet_t *l,u_long kevinIp,u_long serverIp)
{
    //Sends 1 packet to the server with payload enable
    tcpTagCreate(l,libnet_get_prand(LIBNET_PRu16),(u_int16_t)513,
                                    libnet_get_prand(LIBNET_PRu32),libnet_get_prand(LIBNET_PRu32),
                                    "enable", 6,
                                    TH_SYN);

    ipTagCreate(l,(u_int32_t)kevinIp,(u_int32_t)serverIp,
                                   NULL, (u_int32_t)6 );

    sendPacket(l);
    usleep(200);                   
}