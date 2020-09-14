#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>

int main() {

  libnet_t *l;  //Libnet Context

  char errbuf[LIBNET_ERRBUF_SIZE];

  l = libnet_init(LIBNET_RAW4, NULL, errbuf);
  if ( l == NULL ) {
    fprintf(stderr, "libnet initialization failed: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  libnet_destroy(l);
  return 0;
}