#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/init.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "threads/synch.h"

#define MAX_ARGS 3 //allows for easy modification of max arguments


static void syscall_handler (struct intr_frame *);

bool lock_initialized = false;

struct thread_file
{
  struct list_elem file_elem;
  struct file *file_addr;
  int file_descriptor;
}

struct lock lock_filesys; //used for what it sounds like so 

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) //its a handler. It handles syscalls as per the name
{
  if(!lock_initialized){
    lock_init(&lock_filesys); //initializes lock to deny concurrent file access
    lock_initialized = true;
  }
  //confirms that address is within the virtual memory space 
  //if not exits with status -1
  check_valid_addr((const void *) f->esp); 

  int args[MAX_ARGS];

  void * phys_page_ptr; //points to location of physical page

  int esp = getpage_ptr((const void *) f->esp);

  switch(*(int *) esp)
  {
    case SYS_HALT:
      halt(); //calls provided shutdown_power_off() declared in threads/init.h
      break;

    case SYS_EXIT:
      get_stack_arguments(f, &args[0], 1); //gets top arg off stack representing exit status
      exit(args[0]); //exits with that arg (status)
      break;

    case SYS_EXEC:
      
      get_stack_arguments(f, &args[0], 1); //gets the command line argument from stack
      //confirms validity of command line input
      check_str((const void *)arg[0]);

      //get page
      args[0] = getpage_ptr((const void *)arg[0]);
      
      //puts return value in eax register
      f->eax = exec((const char *) args[0]);
      break;

    case SYS_WAIT:
      //gets pid of the child process to wait on off the stack
      get_stack_args(f, &arg[0], 1);
      //puts return value in eax
      f->eax = syscall_wait(arg[0]);
      break;

    case SYS_CREATE:
      //gets args for file name and initial file size
      get_stack_arguments(f, &args[0], 2);
      //confirms validity of file name
      check_str((const void *)args[0]);
      //yeah not commenting this bit anymore
      args[0] = getpage_ptr((const void *)arg[0]);
      //returns whether file was created to eax
      f->eax = create((const char *) args[0], (unsigned) args[1]);
      break;

    case SYS_REMOVE:
      //gets name of file to be removed
      get_stack_arguments(f, &args[0], 1);
      //confirms valid filename
      check_str((const void *)args[0]);

      args[0] = getpage_ptr((const void *)arg[0]);
      //returns to eax whether file was removed
      f->eax = remove((const char *) args[0]);
      break;

    case SYS_FILESIZE:
      //gets file descriptor to use
      get_stack_arguments(f, &args[0], 1);

      //returns size of file with given fd
      f->eax = filesize(args[0]);
      break;

    case SYS_READ:
      //gets arguments for file descriptor, buffer pointer, and size
      get_stack_arguments(f, &args[0], 3);
      //confirms that buffer values are valid
      check_buffer((const void *)args[1], args[2]);

      
      args[1] = getpage_ptr((const void *)arg[1]);

      //returns to eax either bytes read or -1 if file was unable to be read
      f->eax = read(args[0], (void *) args[1], (unsigned) args[2]);
      break;

    case SYS_WRITE:
      //same arguments as read except buff will be a const
      get_stack_arguments(f, &args[0], 3);
      //confirms valid buffer in reserved memory
      check_buffer((void *)args[1], args[2]);

      args[1] = getpage_ptr((const void *)arg[1]);

      //returns to eax the number of bytes written or 0 if none could be
      f->eax = write(args[0], (const void *)args[1], (unsigned)args[2]);
      break;
    
    case SYS_SEEK:
      //gets args for file descriptor of file and position to seek
      get_args(f, &arg[0], 2);
      //returns nothing. Simply changes position to be read/written next for the given fd
      seek(arg[0], (unsigned)arg[1]);
      break;
      
    case SYS_TELL:
      //gets file descriptor from stack
      get_args(f, &arg[0], 1);
      //returns position for next byte to be read/written from the file with given fd
      f->eax = tell(arg[0]);
      break;

    case SYS_OPEN:
      //gets name of file to open from stack
      get_args(f, &arg[0], 1);
      
      //check if the file name is valid whatsoever
       check_str((const void*)arg[0]);
     
      arg[0] = getpage_ptr((const void *)arg[0]);
      
      //returns to eax the file descriptor of the file opened or -1 if not
      f->eax = syscall_open((const char *)arg[0]);  // open this file
      break;
    
    case SYS_CLOSE:
      //gets the file descriptor for the file to be closed from stack
      get_args (f, &arg[0], 1);
      //closes file descriptor fd
      close(arg[0]);
      break;
      
    default:
      break;
  }
}

void halt (void)
{
  shutdown_power_off();
}

void exit (int status)
{
  thread_current()->exit_status = status;
  if(thread_functioning(cur-parent) && cur->cp){
    if(status < 0){
      status = -1;
    }
    cur ->cp->status = status;
  }
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

//executes command line and provides the pid of thread doing the executing in return
pid_t exec (const char *cmd_line)
{
    pid_t pid = process_execute(cmdline);
    struct child_process *child_process_ptr = find_child_process(pid);
    if (!child_process_ptr)
    {
      return -1;
    }
    /* check if process if loaded */
    if (child_process_ptr->load_status == 0)
    {
      sema_down(&child_process_ptr->load_sema);
    }
    /* check if process failed to load */
    if (child_process_ptr->load_status == 2)
    {
      remove_child_process(child_process_ptr);
      return -1;
    }
    return pid;
}
//waits for a given pid
int wait(pid_t pid)
{
  return process_wait(pid); //calls process.c's process_wait which handles logic
}

//creates a file with provided name and size and returns file status
bool create (const char *file, unsigned initial_size)
{
  lock_acquire(&lock_filesys);
  bool file_status = filesys_create(file, initial_size);
  lock_release(&lock_filesys);
  return file_status;
}

//removes file with given name and returns whether successful
bool remove (const char *file)
{
  lock_acqure(&lock_filesys);
  bool file_status = filesys_remove(file);
  lock_release(&lock_filesys);
  return file_status;
}

int filesize (int fd)
{
  lock_acquire(&lock_filesys);
  struct file *file_ptr = get_file(fd);
  if (!file_ptr)
  {
    lock_release(&lock_filesys);
    return -1;
  }
  int filesize = file_length(file_ptr); // from file.h
  lock_release(&lock_filesys);
  return filesize;
}

int read(int fd, void *buffer, unsigned length)
{
  if (length <= 0)
  {
    return length;
  }
  
  if (fd == 0)
  {
    unsigned i = 0;
    uint8_t *local_buffer = (uint8_t *) buffer;
    for (;i < length; i++)
    {
      // retrieve pressed key from the input buffer
      local_buffer[i] = input_getc(); // from input.h
    }
    return length;
  }
  
  /* read from file */
  lock_acquire(&lock_filesys);
  struct file *file_ptr = get_file(filedes);
  if (!file_ptr)
  {
    lock_release(&lock_filesys);
    return -1;
  }
  int bytes_read = file_read(file_ptr, buffer, length); // from file.h
  lock_release (&lock_filesys);
  return bytes_read;
}

int write (int fd, const void *buffer, unsigned size)
{
    if (byte_size <= 0)
    {
      return byte_size;
    }
    if (fd == 1)
    {
      putbuf (buffer, byte_size); // from stdio.h
      return byte_size;
    }
    
    // start writing to file
    lock_acquire(&lock_filesys);
    struct file *file_ptr = get_file(fd);
    if (!file_ptr)
    {
      lock_release(&lock_filesys);
      return ERROR;
    }
    int bytes_written = file_write(file_ptr, buffer, byte_size); // file.h
    lock_release (&lock_filesys);
    return bytes_written;
}

/* syscall_seek */
void seek (int fd, unsigned new_position)
{
  lock_acquire(&lock_filesys);
  struct file *file_ptr = get_file(filedes);
  if (!file_ptr)
  {
    lock_release(&lock_filesys);
    return;
  }
  file_seek(file_ptr, new_position);
  lock_release(&lock_filesys);
}

unsigned tell(int fd)
{
  lock_acquire(&lock_filesys);
  struct file *file_ptr = get_file(fd);
  if (!file_ptr)
  {
    lock_release(&lock_filesys);
    return ERROR;
  }
  off_t offset = file_tell(file_ptr); //from file.h
  lock_release(&lock_filesys);
  return offset;
}

/* syscall_close */
void close(int fd)
{
  lock_acquire(&file_system_lock);
  process_close_file(fd);
  lock_release(&file_system_lock);
}

//Gets a certain number of arguments from top of specified frame
void get_stack_arguments (struct intr_frame *f, int *args, int num_of_args)
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

/* checks whether an addr is within the valid user range */
void check_valid_addr (const void *ptr)
{
  if (!is_user_vaddr(ptr) || ptr == NULL || ptr < (void *) 0x08048000) //as specified in 1.4.1 where code segment begins growing
  {
    exit(-1);
  }
}

/* function to check if string is valid */
void check_str (const void* str)
{
    for (; * (char *) getpage_ptr(str) != 0; str = (char *) str + 1);
}

/* function to check if buffer is valid */
void check_buffer(const void* buf, unsigned size)
{
  unsigned i;
  char* local_buffer = (char *)buf;
  for (i = 0; i < size; i++)
  {
    check_valid_addr((const void*)local_buffer);
    local_buffer++;
  }
}


int get_page_ptr(const void *vaddr)
{
  void *page_ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!page_ptr)
  {
    exit(-1);
  }
  return (int)ptr;
}


/* finds a child with the given pid */
struct child_process* find_child_process(int pid)
{
  struct thread *t = thread_current();
  struct list_elem *e;
  struct list_elem *next;
  //searches through all children of current thread to find a child with the given pid and returns, else returns a null value
  for (e = list_begin(&t->child_list); e != list_end(&t->child_list); e = next)
  {
    next = list_next(e);
    struct child_process *cp = list_entry(e, struct child_process, elem);
    if (pid == cp->pid)
    {
      return cp;
    }
  }
  return NULL;
}

/* remove a specific child process and frees allocated space*/
void
remove_child_process (struct child_process *cp)
{
  list_remove(&cp->elem);
  free(cp);
}

/* Same as above but for allll child processes */
void remove_all_child_processes (void) 
{
  struct thread *t = thread_current();
  struct list_elem *next;
  struct list_elem *e = list_begin(&t->child_list);
  
  for (;e != list_end(&t->child_list); e = next)
  {
    next = list_next(e);
    struct child_process *cp = list_entry(e, struct child_process, elem);
    list_remove(&cp->elem); //remove child process
    free(cp);
  }
}

/* add file to file list and return file descriptor of added file*/
int
add_file (struct file *file_name)
{
  //allocates space for the file and returns -1 for error if failed.
  struct process_file *process_file_ptr = malloc(sizeof(struct process_file));
  if (!process_file_ptr)
  {
    return -1;
  }
  process_file_ptr->file = file_name;
  process_file_ptr->fd = thread_current()->fd; //gives file the current open descriptor
  thread_current()->fd++; //increments file descriptor to prevent duplicates (this should start at 2)
  list_push_back(&thread_current()->file_list, &process_file_ptr->elem); //adds to thread's file list
  return process_file_ptr->fd;
  
}

/* get file that matches file descriptor */
struct file*
get_file (int file_descriptor)
{
  struct thread *t = thread_current();
  struct list_elem* next;
  struct list_elem* e = list_begin(&t->file_list);
  //iterates through and searches for file descriptor matching file_descriptor and returns that file
  for (; e != list_end(&t->file_list); e = next)
  {
    next = list_next(e);
    struct process_file *process_file_ptr = list_entry(e, struct process_file, elem);
    if (file_descriptor == process_file_ptr->fd)
    {
      return process_file_ptr->file;
    }
  }
  return NULL; // nothing found
}

/* Closes a file descriptor*/
void process_close_file (int file_descriptor)
{
  struct thread *t = thread_current();
  struct list_elem *next;
  struct list_elem *e = list_begin(&t->file_list);
  //iterates through file list and closes/frees space allocated for process file if matching file descriptor, else closes all
  for (;e != list_end(&t->file_list); e = next)
  {
    next = list_next(e);
    struct process_file *process_file_ptr = list_entry (e, struct process_file, elem);
    if (file_descriptor == process_file_ptr->fd || file_descriptor == -1)
    {
      file_close(process_file_ptr->file);
      list_remove(&process_file_ptr->elem);
      free(process_file_ptr);
      if (file_descriptor != -1)
      {
        return;
      }
    }
  }
}