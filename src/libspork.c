#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>

#include "libspork.h"

int spork(int nprocs, int kthreads, void *(*func)(void *), void * param) {
  //Used variables.
  int i,c;
  pthread_t *thread_id;
  pid_t pID;

  if(nprocs<1)
    nprocs = 1;
  if(kthreads<1)
    kthreads = 1;
  // If more then one process shall work
  if(nprocs > 1) {
    //Create so many processes
    for(i = 0; i< nprocs; ++i) {
      // Fork Process
      pID = fork();
      if(pID == 0) {
        // stop spawning new process
        i = nprocs;
        // Spawn more thread if necessary
        thread_id = (pthread_t *)malloc(sizeof(pthread_t)*kthreads);
        for(c = 0; c < kthreads; ++c)
          pthread_create(&thread_id[c], NULL, func, param);
        for(c = 0; c < kthreads; ++c) {
          pthread_join(thread_id[c], NULL);
          fprintf(stderr, "Thread spawned!\n");
        }
      } else if(pID < 0) {
        fprintf(stderr, "Fork failed!\n");
      } else {
        fprintf(stderr, "Processs spawned!\n");
      }
    }
  } else {
    thread_id = (pthread_t *)malloc(sizeof(pthread_t)*kthreads);
    for(c = 0; c<kthreads; ++c)
      pthread_create(&thread_id[c], NULL, func, param);
    for(c = 0; c < kthreads; ++c) {
      pthread_join(thread_id[c], NULL);
    }
  }
  return 0;
}

