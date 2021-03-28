#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/init.h"
#include "devices/shutdown.h" /* Imports shutdown_power_off() for use in halt(). */
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/malloc.h"

#define MAX_ARGS 3 //allows for easy modification of max arguments


static void syscall_handler (struct intr_frame *);

void get_stack_args (struct intr_frame *f, int * args, int num_of_args);

struct lock lock_filesys; //lock to prevent concurrent access of filesystem

struct thread_file
{
  struct list_elem file_elem;
  struct file *file_addr;
  int file_descriptor;
};

struct lock lock_filesys;

void syscall_init (void) 
{
  lock_init(&lock_filesys);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) //its a handler. It handles syscalls as per the name
{
  //confirms that address is within the virtual memory space 
  //if not exits with status -1
  check_valid_addr((const void *) f->esp); 

  int args[MAX_ARGS];

  void * phys_page_ptr; //points to location of physical page

  switch(*(int *) f->esp)
  {
    case SYS_HALT:
      halt(); //calls provided shutdown_power_off() declared in threads/init.h
      break;

    case SYS_EXIT:
      get_stack_args(f, &args[0], 1); //gets top arg off stack representing exit status
      exit(args[0]); //exits with that arg (status)
      break;

    case SYS_EXEC:
      
      get_stack_args(f, &args[0], 1); //gets the command line argument from stack

      //get page address and confirm that it is a valid address
      phys_page_ptr = (void *) pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
      if (phys_page_ptr == NULL)
      {
        exit(-1);
      }
      args[0] = (int) phys_page_ptr;
      
      //puts return value in eax register
      f->eax = exec((const char *) args[0]);
      break;

    case SYS_WAIT:
      //gets pid of the child process to wait on off the stack
      get_stack_args(f, &args[0], 1);
      //puts return value in eax
      f->eax = wait(args[0]);
      break;

    case SYS_CREATE:
      //gets args for file name and initial file size
      get_stack_args(f, &args[0], 2);
      //confirms validity of file name and file size being within user space
      check_buffer((const void *)args[0], args[1]);
      //yeah not commenting this bit repeatedly
      phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
        if (phys_page_ptr == NULL)
        {
          exit(-1);
        }
      //returns whether file was created to eax
      f->eax = create((const char *) args[0], (unsigned) args[1]);
      break;

    case SYS_REMOVE:
      //gets name of file to be removed
      get_stack_args(f, &args[0], 1);

      phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
        if (phys_page_ptr == NULL)
        {
          exit(-1);
        }
        args[0] = (int) phys_page_ptr;
      //returns to eax whether file was removed
      f->eax = remove((const char *) args[0]);
      break;

    case SYS_FILESIZE:
      //gets file descriptor to use
      get_stack_args(f, &args[0], 1);

      //returns size of file with given fd
      f->eax = filesize(args[0]);
      break;

    case SYS_READ:
      //gets arguments for file descriptor, buffer pointer, and size
      get_stack_args(f, &args[0], 3);

      //confirms that buffer values are valid within user space
      check_buffer((const void *)args[1], args[2]);

      //oh look this again
      phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[1]);
        if (phys_page_ptr == NULL)
        {
          exit(-1);
        }
        args[1] = (int) phys_page_ptr;

      //returns to eax either bytes read or -1 if file was unable to be read
      f->eax = read(args[0], (void *) args[1], (unsigned) args[2]);
      break;

    case SYS_WRITE:
      //same arguments as read except buff will be a const
      get_stack_args(f, &args[0], 3);
      //confirms valid buffer in reserved memory
      check_buffer((const void *)args[1], args[2]);

      phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[1]);
        if (phys_page_ptr == NULL)
        {
          exit(-1);
        }
        args[1] = (int) phys_page_ptr;

      //returns to eax the number of bytes written or 0 if none could be
      f->eax = write(args[0], (const void *)args[1], (unsigned)args[2]);
      break;
    
    case SYS_SEEK:
      //gets args for file descriptor of file and position to seek
      get_stack_args(f, &args[0], 2);
      //returns nothing. Simply changes position to be read/written next for the given fd
      seek(args[0], (unsigned)args[1]);
      break;
      
    case SYS_TELL:
      //gets file descriptor from stack
      get_stack_args(f, &args[0], 1);
      //returns position for next byte to be read/written from the file with given fd
      f->eax = tell(args[0]);
      break;

    case SYS_OPEN:
      //gets name of file to open from stack
      get_stack_args(f, &args[0], 1);
      //yay last time seeing this
      phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[1]);
        if (phys_page_ptr == NULL)
        {
          exit(-1);
        }
        args[1] = (int) phys_page_ptr;
      
      //returns to eax the file descriptor of the file opened or -1 if not
      f->eax = open((const char *)args[0]);  // open this file
      break;
    
    case SYS_CLOSE:
      //gets the file descriptor for the file to be closed from stack
      get_stack_args(f, &args[0], 1);
      //closes file descriptor fd
      close(args[0]);
      break;
      
    default:
      exit(-1);
      break;
  }
}

void halt(void)
{
  shutdown_power_off();
}

void exit(int status)
{
	thread_current()->exit_status = status;
	printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit ();
}

/* Executes the program with the given file name. */
pid_t exec(const char * file)
{
  /* If a null file is passed in, return a -1. */
	if(!file)
	{
		return -1;
	}
  lock_acquire(&lock_filesys);
  /* Get and return the PID of the process that is created. */
	pid_t child_tid = process_execute(file);
  lock_release(&lock_filesys);
	return child_tid;
}
//waits for a given pid
int wait(pid_t pid)
{
  return process_wait(pid); //calls process.c's process_wait which handles logic
}

//creates a file with provided name and size and returns file status
bool create(const char *file, unsigned initial_size)
{
  lock_acquire(&lock_filesys);
  bool file_status = filesys_create(file, initial_size);
  lock_release(&lock_filesys);
  return file_status;
}

//removes file with given name and returns whether successful
bool remove(const char *file)
{
  lock_acquire(&lock_filesys);
  bool file_status = filesys_remove(file);
  lock_release(&lock_filesys);
  return file_status;
}

//returns the size of the file open with the given file descriptor
int filesize(int fd)
{
  //same use as in previous stuff
  struct list_elem *temp;

  lock_acquire(&lock_filesys);

  //is the thread has no descriptors, then it can't have a file
  if (list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&lock_filesys);
    return -1;
  }

  //checks for a matching file to the file descriptor for this current thread
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      if (t->file_descriptor == fd)
      {
        lock_release(&lock_filesys);
        return (int) file_length(t->file_addr);
      }
  }

  lock_release(&lock_filesys);

  /* Return -1 if we can't find the file. */
  return -1;
}

/*
Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), 
or -1 if the file could not be read (due to a condition other than end of file). Oh look its what the assignment said
*/
int read(int fd, void *buffer, unsigned length)
{
  struct list_elem *temp;

  lock_acquire(&lock_filesys);

  //gets keyboard input for a descriptor of 0 which is user input
  if (fd == 0)
  {
    lock_release(&lock_filesys);
    return (int) input_getc();
  }

  //no files, no fun
  if (fd == 1 || list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&lock_filesys);
    return 0;
  }

  //checks for the file descriptor in those known to the current thread and reads in the 
  //bytes of data stored if any and returns amount read
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      if (t->file_descriptor == fd)
      {
        lock_release(&lock_filesys);
        int bytes = (int) file_read(t->file_addr, buffer, length);
        return bytes;
      }
  }

  lock_release(&lock_filesys);

  //default 
  return -1;
}

/*
Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
The return will be the bytes written or 0 if none. 
*/
int write(int fd, const void *buffer, unsigned length)
{
  //used for iterating through file descriptors later
  struct list_elem *temp;
  //lock to prevent concurrent writes
  lock_acquire(&lock_filesys);

  //these are behaviors for STDIN and STDOUT/no files
	if(fd == 1)
	{
    putbuf(buffer, length);
    lock_release(&lock_filesys);
    return length;
	}
  if (fd == 0 || list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&lock_filesys);
    return 0;
  }

  //iterates through the list of file descriptors for the current thread until file descriptor is found
  //and writes to it if so before releasing lock on file system
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      if (t->file_descriptor == fd)
      {
        int bytes_written = (int) file_write(t->file_addr, buffer, length);
        lock_release(&lock_filesys);
        return bytes_written;
      }
  }

  lock_release(&lock_filesys);
  //default behavior stating nothing was written
  return 0;
}

/*
 Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file.
 If position is placed past end of file, it will either fill the gap with zeros if written, or read nothing
*/
void seek(int fd, unsigned position)
{
  /* list element to iterate the list of file descriptors. */
  struct list_elem *temp;

  lock_acquire(&lock_filesys);

  /* If there are no files to seek through, then we immediately return. */
  if (list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&lock_filesys);
    return;
  }

  //checks for a file descriptor matching that of fd and sets the position to that specified if file found
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      if (t->file_descriptor == fd)
      {
        file_seek(t->file_addr, position);
        lock_release(&lock_filesys);
        return;
      }
  }

  lock_release(&lock_filesys);

  //default if file not found
  return;
}

/*
Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.
*/
unsigned tell(int fd)
{
  struct list_elem *temp;

  lock_acquire(&lock_filesys);

  //default behavior to release lock and return if nothing is found
  if (list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&lock_filesys);
    return -1;
  }
  
  //checks for the given file descriptor like others and then finds next byte to be read/written to and returns
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      if (t->file_descriptor == fd)
      {
        unsigned position = (unsigned) file_tell(t->file_addr);
        lock_release(&lock_filesys);
        return position;
      }
  }

  lock_release(&lock_filesys);

  return -1;
}

/* 
Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one.
*/
void close(int fd)
{
  struct list_elem *temp;

  lock_acquire(&lock_filesys);

  //no descriptors, no closing
  if (list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&lock_filesys);
    return;
  }

  //checks all file descriptors for the current thread and closes the one that matches if any
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      if (t->file_descriptor == fd)
      {
        file_close(t->file_addr);
        list_remove(&t->file_elem);
        lock_release(&lock_filesys);
        return;
      }
  }

  lock_release(&lock_filesys);

  return;
}

/*
Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened.
File descriptors 0 and 1 will not be used as they are reserved for STDIN and STDOUT
*/
int open(const char *file)
{
  lock_acquire(&lock_filesys);

  struct file* f = filesys_open(file);

  //if file creation failed for any reason, return and release lock
  if(f == NULL)
  {
    lock_release(&lock_filesys);
    return -1;
  }

  //creates a new thread file to hold file information for the current thread and adds the descriptor
  //to list of those known to current thread
  struct thread_file *new_file = malloc(sizeof(struct thread_file));
  new_file->file_addr = f;
  int fd = thread_current ()->cur_fd;
  thread_current ()->cur_fd++;
  new_file->file_descriptor = fd;
  list_push_front(&thread_current ()->file_descriptors, &new_file->file_elem);
  lock_release(&lock_filesys);
  return fd;
}

/* confirms that the addr is valid and in user space and exits otherwise*/
void check_valid_addr(const void *ptr_to_check)
{
  //does what main description says
  if(!is_user_vaddr(ptr_to_check) || ptr_to_check == NULL || ptr_to_check < (void *) 0x08048000)
	{
    //exits the thing and releases resources
    exit(-1);
	}
}

//confirms that all buffer values also remain in user space such that no argument overflows
void check_buffer(const void *buff, unsigned size)
{
  unsigned i;
  char *ptr  = (char * )buff;
  for (i = 0; i < size; i++)
    {
      check_valid_addr((const void *) ptr);
      ptr++;
    }
}

/* Get up to three arguments from a programs stack (they directly follow the system
   call argument). */
void get_stack_args(struct intr_frame *f, int *args, int num_of_args)
{
  int i;
  int *ptr;
  for (i = 0; i < num_of_args; i++)
    {
      ptr = (int *) f->esp + i + 1;
      check_valid_addr((const void *) ptr);
      args[i] = *ptr;
    }
}