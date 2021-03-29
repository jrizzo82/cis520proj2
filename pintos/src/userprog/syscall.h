#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdio.h>
#include "lib/kernel/list.h"
void syscall_init (void);

typedef int pid_t;
#define PID_ERROR ((pid_t) -1)


/* A lock for access to filesys
   Since filesys is not yet concurrent */
struct lock lock_filesys;

/* A struct to keep file descriptor -> file pointer mapping*/
struct thread_file
{
  struct file * file_addr;
  int fd;
  struct list_elem elem;
};




#endif /* userprog/syscall.h */
