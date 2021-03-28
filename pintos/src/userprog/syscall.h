#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include <list.h>

typedef int pid_t;

void syscall_init (void);

struct lock lock_filesys; //lock to prevent concurrent access of filesystem

struct thread_file
{
  struct list_elem elem;
  struct file * file_addr;
  int fd;
};

void halt(void) NO_RETURN;
void exit(int status) NO_RETURN;
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned length);
int write(int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

/* Ensures that a given pointer is in valid user memory. */
bool validate(void *ptr);

/* Ensures that each memory address in a given buffer is in valid user space. */
void check_buffer(const void *buff, unsigned size);

#endif /* userprog/syscall.h */