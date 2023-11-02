#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "kernel/console.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "lib/string.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "userprog/process.h"

struct file_info {
  struct file *file;
  char filename[100];
  int fd;
  struct thread *thread;
  struct list_elem elem;
};

static struct list file_list;
static int assigned_fd;
static struct lock fd_lock;

tid_t syscall_exec(const char* cmdline);
int syscall_wait (tid_t pid);
void syscall_exit(int status, struct thread *cur_thread);
int check_address (void *syscall_address,struct thread *cur_thread );
static void syscall_handler (struct intr_frame *);
int syscall_write(int fd, const char *buffer, unsigned size);
void unsafe(void);
bool syscall_create(const char *file, unsigned initial_size);
bool syscall_remove(const char *file);
int syscall_open(const char *file);
void syscall_close(int fd);
int syscall_filesize(int fd);
void syscall_halt(void);
int syscall_read(int fd, const char *buffer, unsigned size);
int syscall_tell(int fd);
void syscall_seek( int fd, unsigned new_position);
int same_filename (struct thread *t, void *aux, char *the_filename);
void close_files(void);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&file_list);
  assigned_fd = 2;
  lock_init(&fd_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  struct thread *cur_T = thread_current();
  void *syscall_address = f->esp;
  uintptr_t arg[3];

  //check if beginning syscall_address is a safe memory
  if (check_address(syscall_address,cur_T) == 0){
    unsafe();
  } else{
     if ( *(int *)syscall_address == SYS_WRITE){


        const char *buffer;
        unsigned size;
        int fd;
        syscall_address=syscall_address+4;
        if (check_address(syscall_address,cur_T) == 0){
            unsafe();
        } else{
          fd = *(int *) syscall_address;
          syscall_address=syscall_address+4;
          if (check_address(syscall_address,cur_T) == 0){
              unsafe();
          }else{
            void *temp = *(void**)syscall_address;
            if (check_address(temp,cur_T) == 0){
                unsafe();
            }
            buffer = (char*) temp;
            syscall_address=syscall_address+4;
            if (check_address(syscall_address,cur_T) == 0){
                unsafe();
               }else{
                size = *(unsigned *) syscall_address;
               }
          }
        }

        int result = syscall_write(fd, buffer, size);
        if (result != -10086){
          int a =-2;
          if (result == a){
            f->eax= 0;
          }else{
            f->eax= result;
          }
        }

        
    }else if (*(int *)syscall_address == SYS_EXIT){


        syscall_address=syscall_address+4;
        if (check_address(syscall_address,cur_T) == 0){
          unsafe();
        }else{
              int status = *(int *) syscall_address;
              syscall_exit(status,cur_T);   
        }

    }else if (*(int *)syscall_address == SYS_CREATE){

      const char *file;
      unsigned initial_size;
      if (check_address(syscall_address+4, cur_T) == 0 || check_address(syscall_address+8, cur_T) == 0)
        unsafe();
      syscall_address += 4;
      file = *(char **)syscall_address;
      syscall_address += 4;
      initial_size = *(unsigned *)syscall_address;
      if (check_address((void *)file, cur_T) == 0)
        unsafe();
      f->eax = syscall_create(file, initial_size);

    }else if (*(int *)syscall_address == SYS_REMOVE){

      const char *file;
      if (check_address(syscall_address+4, cur_T) == 0){
        unsafe();
      }
      syscall_address += 4;
      file = *(char **)syscall_address;
      if (check_address((void *)file, cur_T) == 0)
        unsafe();
      f->eax = syscall_remove(file);

    }else if (*(int *)syscall_address == SYS_OPEN){

      const char *file;
      if (check_address(syscall_address+4, cur_T) == 0){
        unsafe();
      }
      syscall_address += 4;
      file = *(char **)syscall_address;
      if (check_address((void *)file, cur_T) == 0)
        unsafe();
      f->eax = syscall_open(file);

    }else if (*(int *)syscall_address == SYS_CLOSE){

      int fd;
      if (check_address(syscall_address+4, cur_T) == 0){
        unsafe();
      }
      syscall_address += 4;
      fd = *(int *)syscall_address;
      syscall_close(fd);

    }else if (*(int *)syscall_address == SYS_FILESIZE){

      int fd;
      if (check_address(syscall_address+4, cur_T) == 0){
        unsafe();
      }
      syscall_address += 4;
      fd = *(int *)syscall_address;
      f->eax = syscall_filesize(fd);

    }else if  (*(int *)syscall_address == SYS_READ){
        const char *buffer;
        unsigned size;
        int fd;
  
        syscall_address=syscall_address+4;
        if (check_address(syscall_address,cur_T) == 0){
            unsafe();
          
        } else{
          fd = *(int *) syscall_address;
          syscall_address=syscall_address+4;
          if (check_address(syscall_address,cur_T) == 0){
              unsafe();
        
          }else{
            void *temp = *(void**)syscall_address;
            if (check_address(temp,cur_T) == 0){
                unsafe();
            }
            buffer = (char*) temp;
            syscall_address=syscall_address+4;
            if (check_address(syscall_address,cur_T) == 0){
                unsafe();
               
               }else{
                size = *(unsigned *) syscall_address;
               }
          }
        }
        int result = syscall_read(fd, buffer, size);
        if (result != -10086){
          f->eax= result;
        }
        
        
        

    } else if (*(int *)syscall_address == SYS_SEEK){
      int fd;
      unsigned new_position;
      syscall_address=syscall_address+4;
        if (check_address(syscall_address,cur_T) == 0){
            unsafe();
        } else{
          fd = *(int *) syscall_address;
          syscall_address=syscall_address+4;
          if (check_address(syscall_address,cur_T) == 0){
              unsafe();
          }else{
            new_position = *(unsigned *) syscall_address;
          }
        }

        syscall_seek(fd, new_position);
         

    }else if (*(int *)syscall_address == SYS_TELL){
      int fd;
      syscall_address=syscall_address+4;
        if (check_address(syscall_address,cur_T) == 0){
            unsafe();
        } else{
          fd = *(int *) syscall_address;
          int result = syscall_tell(fd);
          f->eax= result;
        }

    }else if (*(int *)syscall_address == SYS_HALT){
       syscall_halt();
     }else if (*(int *)syscall_address == SYS_EXEC){
      syscall_address += 4;
      if (check_address(syscall_address, cur_T) == 0)
      {
        unsafe();
      }
      else
      {
        char *cmd_line = *(char **)syscall_address;
        if (check_address(cmd_line, cur_T) == 0)
          unsafe();
        f->eax = syscall_exec(cmd_line);
      }
      }

     else if (*(int *)syscall_address == SYS_WAIT){
      syscall_address += 4;
      if (check_address(syscall_address, cur_T) == 0)
      {
        unsafe();
      }
      else
      {
        arg[0] = *(int *)syscall_address;
        f->eax = syscall_wait(arg[0]);
      }
     }
  }
}

int check_address (void *syscall_address,struct thread *cur_thread ){
  int correct =1;
  if (syscall_address == NULL){
    correct=0;
  }else if(syscall_address >=PHYS_BASE){
    correct=0;
  }else if (pagedir_get_page(cur_thread->pagedir, syscall_address) == NULL){
    correct=0;
  }
  return correct;
}

void unsafe(void){
  printf ("%s: exit(%d)\n", thread_current()->name, -1);  
  thread_exit();
}

void syscall_seek( int fd, unsigned new_position){
  struct file *the_file = NULL;
    for (struct list_elem *e = list_begin(&file_list); e != list_end(&file_list); e = list_next(e)){
      struct file_info *file_info = list_entry(e, struct file_info, elem);
      if (file_info->fd == fd){ 
        the_file= file_info->file;
      }
    }
    file_seek (the_file, new_position);
}
int syscall_write(int fd, const char *buffer, unsigned size){
  if (fd== 1){
    putbuf(buffer,size);
    return size;
  }else{
    char *the_filename = NULL;
    struct file *the_file = NULL;
    for (struct list_elem *e = list_begin(&file_list); e != list_end(&file_list); e = list_next(e)){
      struct file_info *file_info = list_entry(e, struct file_info, elem);
      if (file_info->fd == fd){ 
        the_file= file_info->file;
        the_filename =file_info->filename;
        if (file_info->thread != thread_current())
          return 0;
      }
    }

    if (the_file==NULL){
      // -10086 means fail
      return -10086;
    } else {

        if (thread_foreach_return (same_filename, NULL, the_filename )==1){
          // 1 means found duplicate
          return -2;
        }else{
           void* void_buffer = (void*)buffer;
            off_t wttiten_bytes = file_write (the_file, void_buffer, size);
           return wttiten_bytes;
        }
       
    }
    
  }
  
}

int same_filename (struct thread *t, void *aux, char *the_filename){
    // return 1 if found
    if (strstr(the_filename, t->name) != NULL){
      return 1;
    }
    return 0;
}

int syscall_read(int fd, const char *buffer, unsigned size){
    if (fd ==0 ){
      // return key?
      uint8_t key = input_getc();
      return key; 
    }else{
      struct file *the_file = NULL;
      for (struct list_elem *e = list_begin(&file_list); e != list_end(&file_list); e = list_next(e)){
        struct file_info *file_info = list_entry(e, struct file_info, elem);
        if (file_info->fd == fd){ 
          the_file= file_info->file;
          if (file_info->thread != thread_current())
            return -1;
        }
      }
      if (the_file == NULL){
        return -10086;
      }else{
            void* void_buffer = (void*)buffer;
            off_t read_bytes = file_read( the_file, void_buffer,  size);
            return read_bytes;
      }
  
    }
    

}

void syscall_exit(int status, struct thread *cur_T){
  printf ("%s: exit(%d)\n", cur_T->name, status); 
  cur_T->child->exit_status = status; 
  thread_exit();
}

int syscall_tell(int fd){
      struct file *the_file = NULL;
      for (struct list_elem *e = list_begin(&file_list); e != list_end(&file_list); e = list_next(e)){
        struct file_info *file_info = list_entry(e, struct file_info, elem);
        if (file_info->fd == fd){ 
          the_file= file_info->file;
          }
        }
        // file ==NULL
      off_t position = file_tell(the_file);
      return position;
}

bool syscall_create(const char *file, unsigned initial_size){ 
  return filesys_create(file, initial_size);
}

bool syscall_remove(const char *file){
  return filesys_remove(file);
}

int syscall_open(const char *file){
  struct file_info *file_info;
  struct file *opened_file = filesys_open(file);
  struct fd *fd;

  // if open failed
  if (opened_file == NULL) return -1;

  file_info = (struct file_info *)malloc(sizeof(struct file_info));
  fd = (struct fd *)malloc(sizeof(struct fd));

  if (file_info == NULL || fd == NULL) return -1;

  file_info->file = opened_file;
  strlcpy(file_info->filename, file, sizeof(char)*(strlen(file)+1));
  lock_acquire(&fd_lock);
  file_info->fd = assigned_fd++;
  lock_release(&fd_lock);
  file_info->thread = thread_current();
  list_push_back(&file_list, &file_info->elem);
  
  fd->fd = file_info->fd;
  list_push_back(&thread_current()->fd_list, &fd->elem);
  
  return file_info->fd;
}

void syscall_close(int fd){
  // find the file corresponding to fd, remove fd from opened file list
  for (struct list_elem *e = list_begin(&file_list); e != list_end(&file_list); e = list_next(e)){
    struct file_info *file_info = list_entry(e, struct file_info, elem);
    if (file_info->fd == fd){
      if (file_info->thread == thread_current()){
        file_close(file_info->file);
        list_remove(&file_info->elem);
        free(file_info);
      }
      return;
    }
  } 
}

int syscall_filesize(int fd){
  for (struct list_elem *e = list_begin(&file_list); e != list_end(&file_list); e = list_next(e)){
    struct file_info *file_info = list_entry(e, struct file_info, elem);
    if (file_info->fd == fd){ 
      return file_length(file_info->file);
    }
  }
  return 0;
}

void syscall_halt(void){
  shutdown_power_off();
}

tid_t
syscall_exec (const char *cmd_line)
{
  tid_t tid = process_execute (cmd_line);
  return tid;
}

int
syscall_wait (tid_t pid)
{
  return process_wait(pid);
}

void close_files(void){
  for (struct list_elem *e = list_begin(&thread_current()->fd_list); e != list_end(&thread_current()->fd_list);){
    struct fd *fd = list_entry(e, struct fd, elem);
    syscall_close(fd->fd);
    e = list_remove(&fd->elem);
    free(fd);
  }
}