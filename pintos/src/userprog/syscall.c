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


static void syscall_handler (struct intr_frame *); //handler for all sys calls

struct thread_file * get_file(int); //used to get a thread file

void syscall_init (void) 
{
  lock_init(&lock_filesys);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*
So validating is a bit weird due to how things are pushed on the stack
but main thing to note is
1 arg esp + 1
2 args esp + 4 and esp + 5 respectively
3 args esp + 5, esp + 6, and esp + 7

That's why you'll commonly see ptr + some random seeming number as
they're referring to the location of the pointers to the actual arguments in memory
If these don't validate for any reason it just kills the process with exit(-1)
Any returns get stored in frame's eax reg
*/
static void
syscall_handler (struct intr_frame *f UNUSED) //its a handler. It handles syscalls as per the name
{
  //stack pointer
  int * ptr = f->esp;

  //confirms that address is within the virtual memory space and exists
  //if not exits with status -1
  if(!validate(ptr)){
    exit(-1);
  }

  switch(* ptr)
  {
    case SYS_HALT:
      halt(); //calls provided shutdown_power_off() declared in threads/init.h
      break;

    case SYS_EXIT:
      //gets and validates top arg off stack representing exit status
      if(!validate(ptr+1)) exit(-1); 

      exit(*(ptr+1)); //exits with that arg (status)
      break;

    case SYS_EXEC:
      //validates pointer to char * and the char * with file name itself
      if(!validate(ptr+1) || !validate(*(ptr+1))) exit (-1);
      //puts return value in eax register
      f->eax = exec(*(ptr+1));
      break;

    case SYS_WAIT:
      //validates pid argument of the child process
      if(!validate(ptr+1)) exit(-1);
      //puts return value in eax
      f->eax = wait(*(ptr+1));
      break;

    case SYS_CREATE:
      //validates the argument pointers along with the ptr + 4 that points to the file name
      //to avoid name overflow
      if(!validate(ptr+4) || !validate(ptr+5) || !validate(*(ptr+4))) exit(-1);
      //returns whether file was created to eax
      f->eax = create(*(ptr+4), *(ptr+5));
      break;

    case SYS_REMOVE:
      //if the address of file name to remove and the file name stored are both in user space
      //we're good to go
      if(!validate(ptr+1) || !validate(*(ptr+1))) exit(-1);
      //returns to eax whether file was removed
      f->eax = remove(*(ptr+1));
      break;

    case SYS_FILESIZE:
      //validates address pointing to filesize
      if (!validate(ptr+1)) exit(-1);

      //returns size of file with given fd
      f->eax = filesize(*(ptr+1));
      break;

    case SYS_READ:
      //validates the file descriptor, buffer, and size pointers while additionally validating what is in
      //the buffer itself
      if (!validate(ptr+5) || !validate(ptr+6) || !validate(ptr+7) || !validate(*(ptr+6))) exit(-1);
      //returns to eax either bytes read or -1 if file was unable to be read
      f->eax=read(*(ptr+5),*(ptr+6),*(ptr+7));
      break;

    case SYS_WRITE:
      //basically same thing as read
      if (!validate(ptr+5) || !validate(ptr+6) || !validate(ptr+7)|| !validate(*(ptr+6))) exit(-1);
      //returns to eax the number of bytes written or 0 if none could be
      f->eax = write(*(ptr+5),*(ptr+6),*(ptr+7));
      break;
    
    case SYS_SEEK:
      //validates the pointers to arguments for fd and position
      if(!validate(ptr+4) || !validate(ptr+5)) exit(-1);
      //returns nothing. Simply changes position to be read/written next for the given fd
      seek(*(ptr+4),*(ptr+5));
      break;
      
    case SYS_TELL:
      //validates ptr to file descriptor 
      if(!validate(ptr+1)) exit(-1);
      //returns position for next byte to be read/written from the file with given fd
      f->eax = tell(*(ptr+1));
      break;

    case SYS_OPEN:
      //valids pointer to char * representing the file name to be opened and the file name itself
      if(!validate(ptr+1) || !validate(*(ptr+1))) exit(-1);
      
      //returns to eax the file descriptor of the file opened or -1 if not
      f->eax = open(*(ptr+1));  // open this file
      break;
    
    case SYS_CLOSE:
      if (!validate(ptr+1)) exit(-1);
      //closes file descriptor fd
      close(*(ptr+1));
      break;
      
    default:
      printf("Invalid System Call number\n");
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

  struct thread * parent = thread_current()->parent;

	thread_current()->exit_code = status;
	if(!list_empty(&parent->children)){
    //gets parent's child struct
    struct child * child = get_child(thread_current()->tid,parent);
    //if not null then sets relevant values and wakes parent if needed
    if(child != NULL){
      child->ret_val=status;
      child->used = 1;
      if(thread_current()->parent->waitedon_child == thread_current()->tid) 
        sema_up(&thread_current()->parent->child_wait_sema);
    }
  }
  thread_exit ();
}

/* Executes the program with the given file name. */
pid_t exec(const char * cmd_line)
{
  lock_acquire(&lock_filesys);
  /* Get and return the PID (also equivalent to child tid as these are mapped 1:1) of the process that is created. */
	pid_t child_pid = process_execute(cmd_line);
  lock_release(&lock_filesys);
	return child_pid;
}
//waits for a given pid
int wait(pid_t pid)
{
  return process_wait(pid); //calls process.c's process_wait which handles logic
}

//creates a file with provided name and size and returns file status
bool create(const char *file, unsigned initial_size)
{
  //if null file return error
  if(file == NULL) return -1;

  lock_acquire(&lock_filesys);
  bool file_status = filesys_create(file, initial_size);
  lock_release(&lock_filesys);
  return file_status;
}

//removes file with given name and returns whether successful
bool remove(const char *file)
{
  //if null filename, return error
  if(file == NULL) return -1;

  lock_acquire(&lock_filesys);
  bool file_status = filesys_remove(file);
  lock_release(&lock_filesys);
  return file_status;
}

//returns the size of the file open with the given file descriptor
int filesize(int fd)
{
  //gets the file with the given descriptor (can be NULL)
  struct thread_file * file = get_file(fd);
  //checks whether file is null in which case no fileent with that descriptor exists so returns error
  if(file == NULL) return -1;

  lock_acquire(&lock_filesys);
  //using file_length from file.c, get the length of the file in bytes while making sure no modifications
  //occur concurrently
  int length = file_length(file->file_addr); 

  lock_release(&lock_filesys);
  return length;
}

/*
Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), 
or -1 if the file could not be read (due to a condition other than end of file). Oh look its what the assignment said
*/
int read(int fd, void *buffer, unsigned length)
{
  unsigned length_read = 0;

  //gets keyboard input for a descriptor of 0 which is user input
  if (fd == 0)
  {
    while( length_read < length)
    {
      *((char *)buffer+length_read) = input_getc();
      length_read++;
    }
    return length_read;
  }
  
  //retrieves file, returns error if file is invalid (NULL)
  struct thread_file * file = get_file(fd);
  if(file == NULL) return -1;

  lock_acquire(&lock_filesys);
  length_read = file_read(file->file_addr, buffer, length);
  lock_release(&lock_filesys);
  return length_read;
}

/*
Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
The return will be the bytes written or 0 if none. 
*/
int write(int fd, const void *buffer, unsigned length)
{
  
  //this is behavior for STDOUT. Simply writes to standard output
	if(fd == 1)
	{
    putbuf(buffer, length);
    return length;
	}

  // Get the thread_file matching the fd and returns error if not valid
  struct thread_file * file = get_file(fd);
  if(file== NULL)
    return -1;
  
  lock_acquire(&lock_filesys);
  // write to the file using file_write from file.c
  int length_written = file_write(file->file_addr,buffer,length);
  lock_release(&lock_filesys);
  return length_written;
}

/*
 Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file.
 If position is placed past end of file, it will either fill the gap with zeros if written, or read nothing
*/
void seek(int fd, unsigned position)
{
  struct thread_file * file = get_file(fd);

  if(file == NULL) return;

  lock_acquire(&lock_filesys);
  //uses file.c's file_seek to update position in file
  file_seek(file->file_addr, position);
  lock_release(&lock_filesys);
}

/*
Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.
*/
unsigned tell(int fd)
{
  struct thread_file * file = get_file(fd);

  if(file == NULL) return -1;

  lock_acquire(&lock_filesys);
  //uses file.c's file_tell to find current position in file
  unsigned position = file_tell(file->file_addr);
  lock_release(&lock_filesys);
  return position;
}

/* 
Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one.
*/
void close(int fd)
{
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
    return;
  
  // get's the thread_file with the given fd
  struct thread_file * file = get_file(fd);

  //returns error if file is null
  if (file == NULL)
    return -1;
  
  lock_acquire(&lock_filesys);
  // closes file  using the good ol' file.c's predefined function
  file_close(file->file_addr);
  lock_release(&lock_filesys);

  /* Removing the thread file element from the list
     and freeing memory */
  list_remove(&file->elem);
  free(file);
}

/*
Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened.
File descriptors 0 and 1 will not be used as they are reserved for STDIN and STDOUT
*/
int open(const char *file)
{
  lock_acquire(&lock_filesys);
  struct file * fptr = filesys_open(file);
  lock_release(&lock_filesys);
  
  if (fptr == NULL)    return -1;
  
  struct thread_file * tfile = malloc (sizeof(struct thread_file));
  tfile->fd = ++thread_current()->fd_count;
  tfile->file_addr = fptr;
  list_push_front(&thread_current()->file_list,&tfile->elem);
  
  return tfile->fd;
}

/* confirms that the addr is valid and in user space and exists in directory*/
bool validate( void * ptr_to_check)
{
  //does what main description says
  if(is_user_vaddr(ptr_to_check) && pagedir_get_page(thread_current()->pagedir,ptr_to_check) != NULL)
	{
    return true;
	}
  else return false;
}

/* 
Does what it says and gets the file with the given file descriptor. Moved here 
because it is used so so many other places
*/
struct thread_file * get_file (int fd)
{
  struct thread * curr = thread_current();
  struct list_elem * e;

  for (e=list_begin(&curr->file_list);
    e != list_end (&curr->file_list); e = list_next(e))
  {
    struct thread_file * file = list_entry(e, struct thread_file,elem);
    if (file->fd == fd)
      return file;
  } 

  return NULL;
}

