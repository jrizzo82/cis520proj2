#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct child * get_child(tid_t,struct thread *);
/*
Defines a child process for use within process.c
These hold return value to be sent to parent
*/
struct child 
{
  tid_t id;
  int ret_val;
  int used;
  struct list_elem elem;
};


#endif /* userprog/process.h */