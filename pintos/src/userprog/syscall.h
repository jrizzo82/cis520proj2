#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include "threads/synch.h"
#include "threads/thread.h"

typedef int pid_t;

void syscall_init (void);

//arguably this should be in thread.h but I got tired of going back and forth between files
struct child_process {
  int pid;
  int load_status;
  int wait;
  int exit;
  int status;
  struct semaphore load_sema;
  struct semaphore exit_sema;
  struct list_elem elem;
};

void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

/* Checks the passed-in pointer to ensure that it is in valid user memory. */
void check_valid_addr (const void *ptr);

/* Checks the passed-in buffer to ensure that each memory address is in valid user space. */
void check_buffer (void *buff, unsigned size);
struct child_process* find_child_process (int pid);
void remove_child_process (struct child_process *child);
void remove_all_child_processes (void);

/*Different ways to handle files*/
int add_file (struct file *file_name);
int syscall_filesize(int filedes);
struct file* get_file(int filedes);

#endif /* userprog/syscall.h */
