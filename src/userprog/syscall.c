#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

#define MAX_ARGS 3

void load_str (void*, void* );
static int get_user (const uint8_t *);
static inline bool put_user (uint8_t *, uint8_t );
static char *strcopy (const char *);

static void syscall_handler (struct intr_frame *);
void pass_arg (struct intr_frame *f, int *, int );
bool load_addr (const void *, void* );
void load_buffer (void* , unsigned , void* , bool );
void reset_addr (void* ,int);

struct file_descriptor* get_file_descriptor (int fid)
{
  struct list_elem *e;
  struct thread *cur = thread_current();
  for (e = list_begin (&cur->fd_list); e != list_end (&cur->fd_list); e = list_next (e))
  {
    struct file_descriptor *fd = list_entry (e, struct file_descriptor, elem);
    if (fd->fid == fid)
	{
	   return fd;
    }
 }
 return NULL;
}

struct file* get_file (int fid)
{
  struct list_elem *e;
  struct thread *cur = thread_current();
  for (e = list_begin (&cur->fd_list); e != list_end (&cur->fd_list); e = list_next (e))
  {
    struct file_descriptor *fd = list_entry (e, struct file_descriptor, elem);
    if (fd->fid == fid)
	{
	   return fd->file;
    }
 }
 return NULL;
}

void close_file (int fid)
{

  struct thread *cur = thread_current();
  struct list_elem *next, *e = list_begin(&cur->fd_list);
  while (e != list_end (&cur->fd_list))
  {
    next = list_next(e);
    struct file_descriptor *fd = list_entry (e, struct file_descriptor, elem);
	if (!fd)
	  break;
    if (fd->fid == fid || fid == ALL)
	{
	  if (fd->isdir)
	  {
	     dir_close(fd->dir);
	  }
	  else
	  {
	     file_close(fd->file);
	  }
	  list_remove(&fd->elem);
	  free(fd);
	  if (fid != ALL)
	  {
	    return;
	  }
    }
	e = next;
  }
}

void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int arg[MAX_ARGS];
  if(!load_addr(f->esp, f->esp))
	exit(-1);
  switch (* (int *) f->esp)
  {
    case SYS_HALT:
    {
	  shutdown_power_off();
	  break;
    }
    case SYS_EXIT:
    {
	  pass_arg(f, arg, 1);
	  exit(arg[0]);
	  break;
    }
    case SYS_EXEC:
    {
	  pass_arg(f, arg, 1);
	  load_str(arg[0],f->esp);
	  f->eax = process_execute(arg[0]);
	  reset_addr((void *) arg[0], (int)strlen(arg[0]));
	  break;
    }
    case SYS_WAIT:
    {
	  pass_arg(f, arg, 1);
	  f->eax = process_wait(arg[0]);
	  break;
    }
    case SYS_CREATE:
    {
	  pass_arg(f, arg, 2);
	  load_str(arg[0],f->esp);
	  lock_acquire(&file_lock);
      bool result = filesys_create(arg[0], arg[1], 0);
      lock_release(&file_lock);
	  f->eax = result;
	  reset_addr((void *) arg[0], (int)strlen(arg[0]));
	  break;
    }
    case SYS_REMOVE:
    {
	  pass_arg(f, arg, 1);
	  load_str(arg[0], f->esp);
	  lock_acquire(&file_lock);
      bool result = filesys_remove(arg[0]);
      lock_release(&file_lock);
	  f->eax = result;
	  break;
    }
    case SYS_OPEN:
    {
	  pass_arg(f, arg, 1);
	  load_str(arg[0],f->esp);
	  lock_acquire(&file_lock);
      struct file *file = filesys_open(arg[0]);
      if (!file)
      {
        lock_release(&file_lock);
        f->eax = -1;
        break;
      }
	  struct file_descriptor *fd = malloc(sizeof(struct file_descriptor));
      if (!fd)
      {
	    f->eax = -1;
		lock_release(&file_lock);
		break;
      }
	  if (file_get_inode(file)->dir_flag)
      {
        fd->dir = (struct dir *)file;
        fd->isdir = true;
        fd->fid = thread_current()->next_fid;
        thread_current()->next_fid++;;
        list_push_back(&thread_current()->fd_list, &fd->elem);
	    lock_release(&file_lock);
        
      }
	  else
	  {
        fd->file = file;
	    fd->isdir = false;
        fd->fid = thread_current()->next_fid;
        thread_current()->next_fid++;
        list_push_back(&thread_current()->fd_list, &fd->elem);
        lock_release(&file_lock);
      }
	  f->eax = fd->fid;
	  reset_addr((void *) arg[0], (int)strlen(arg[0]));
	  break; 		
    }
    case SYS_FILESIZE:
    {
	  pass_arg(f, arg, 1);
	  lock_acquire(&file_lock);
      struct file_descriptor *fd = get_file_descriptor(arg[0]);
	  if (!fd||fd->isdir)
      {
	     lock_release(&file_lock);
         f->eax = -1;
		 break;
      }
      int size = file_length(fd->file);
      lock_release(&file_lock);
	  f->eax = size;
	  break;
    }
    case SYS_READ:
    {
      pass_arg(f, arg, 3);
	  load_buffer((void *) arg[1], (unsigned) arg[2], f->esp,  true);
	  int fid = arg[0];
	  int size = arg[2];
	  if (fid == STDIN_FILENO)
      {
        uint8_t* uaddr = (uint8_t *)arg[1];
	    int i;
        for (i = 0; i < size; i++)
	    {
	      if(!verify_user(uaddr)||!put_user(uaddr++, input_getc()))
	      {
	        exit(-1);
	      }
	    }
		f->eax = size;
        break;
      } 
      lock_acquire(&file_lock);
      struct file_descriptor *fd = get_file_descriptor(fid);
      if (!fd||fd->isdir)
      {
	    lock_release(&file_lock);
        f->eax = -1;
        break;
      }
      int bytes = file_read(fd->file, arg[1], size);
      lock_release(&file_lock);
      f->eax = bytes;
	  reset_addr((void *) arg[1], (int)arg[2]);
	  break;
    }
    case SYS_WRITE:
    { 
	  pass_arg(f, arg, 3);
	  load_buffer((void *) arg[1], (unsigned) arg[2], f->esp, false);
	  int fid = arg[0];
	  int size = arg[2];
	  if (fid == STDOUT_FILENO)
      {
        putbuf(arg[1], size);
        return size;
      }
      lock_acquire(&file_lock);
      struct file_descriptor *fd = get_file_descriptor(fid);
      if (!fd||fd->isdir)
      {
        lock_release(&file_lock);
        f->eax = -1;
		break;
      }
      int bytes = file_write(fd->file, arg[1], size);
      lock_release(&file_lock);
	  f->eax = bytes;
	  reset_addr((void *) arg[1], (int)arg[2]);
	  break;
    }
    case SYS_SEEK:
    {
	  pass_arg(f, arg, 2);
	  lock_acquire(&file_lock);
      struct file_descriptor *fd = get_file_descriptor(arg[0]);
	  if (!fd||fd->isdir)
      {
        lock_release(&file_lock);
        f->eax = -1;
		break;
      }
      file_seek(fd->file, arg[1]);
      lock_release(&file_lock);
	  f->eax = 0;
	  break;
    } 
    case SYS_TELL:
    { 
	  pass_arg(f, arg, 1);
	  lock_acquire(&file_lock);
      struct file_descriptor *fd = get_file_descriptor(arg[0]);
	  if (!fd||fd->isdir)
      {
        lock_release(&file_lock);
        f->eax = -1;
		break;
      }
      unsigned pos = file_tell(fd->file);
      lock_release(&file_lock);
      f->eax = pos;
	  break;
    }
    case SYS_CLOSE:
    { 
	  pass_arg(f, arg, 1);
      lock_acquire(&file_lock);
      close_file(arg[0]);
      lock_release(&file_lock);
	  f->eax = 0;
	  break;
    }
    case SYS_MMAP:
    {
	  pass_arg(f, arg, 2);
	  f->eax = mmap(arg[0], (void *) arg[1]);
	  break;
    }
    case SYS_MUNMAP:
    {
	  pass_arg(f, arg, 1);
	  munmap(arg[0]);
	  break;
    }
	 case SYS_CHDIR:
    {
	  pass_arg(f, arg, 1);
	  f->eax = filesys_chdir((const char *)arg[0]);
	  break;
    }
    case SYS_MKDIR:
    {
	  pass_arg(f, arg, 1);
	  f->eax = filesys_create((const char *)arg[0], 0, true);
	  break;
    }
    case SYS_READDIR:
    {
	  pass_arg(f, arg, 2);
	  bool success = -1;
	  struct file_descriptor *fd = get_file_descriptor(arg[0]);
      if (!fd)
	  {
        f->eax = success;  
	  }
	  else
	  {
        if (!fd->isdir)
	      f->eax = success;  
        else
		  f->eax = dir_readdir(fd->dir, (char *)arg[1]);
	  }
	  break;
    }
    case SYS_ISDIR:
    {
	  pass_arg(f, arg, 1);
	  struct file_descriptor *fd = get_file_descriptor(arg[0]);
      if (!fd)
	    f->eax = -1;
	  else
	    f->eax = fd->isdir;
	  break;
    }
    case SYS_INUMBER:
    {
	  pass_arg(f, arg, 1);
	  struct file_descriptor *fd = get_file_descriptor(arg[0]);
      if (!fd)
      {
        f->eax -1;
		break;
      }
      block_sector_t num;
      if (fd->isdir)
        num = dir_get_inode(fd->dir)->sector;
      else
        num = file_get_inode(fd->file)->sector;
	  f->eax = num;
	  break;
    }
  }
  reset_addr (f->esp ,1);
}

void exit (int return_code)
{
  struct thread *cur = thread_current();
  cur->info->return_code = return_code;
  printf ("%s: exit(%d)\n", cur->name, return_code);
  thread_exit();
}

int mmap (int fid, void *addr)
{
  struct thread *cur = thread_current();
  struct file *file = get_file(fid);
  if ( !verify_user(addr) || ((uint32_t) addr % PGSIZE) != 0 || !file )
  {
    return -1;
  }
  struct file *new_file = file_reopen(file);
  if (!new_file || file_length(file) == 0)
  {
    return -1;
  }
  int32_t ofs = 0;
  uint32_t bytes_size = file_length(new_file);
  cur->next_mid++;
  while (bytes_size > 0)
  {
    uint32_t read_size_bytes = bytes_size < PGSIZE ? bytes_size : PGSIZE;
    uint32_t page_zero_bytes = PGSIZE - read_size_bytes;
	struct sub_page_unit *pu = malloc(sizeof(struct sub_page_unit));
	pu->occupy = false;
    pu->page_type = MMAP;
    pu->vaddr = addr;
    pu->file = new_file;
    pu->ofs = ofs;
    pu->writable = true;
    pu->read_size = read_size_bytes;
    pu->zero_size = page_zero_bytes;
    pu->kernal_pin = false;
    struct file_map *mmap = malloc(sizeof(struct file_map));
    mmap->subpu = pu;
    mmap->mid = cur->next_mid;
    list_push_back(&cur->fm_list, &mmap->elem);
    if (hash_insert(&cur->subpu_hash, &pu->elem))
    {
      pu->page_type = INSERT_FAIL;
	  munmap(cur->next_mid);
	  return -1;
	}
    bytes_size -= read_size_bytes;
    ofs += read_size_bytes;
    addr += PGSIZE;
  }
  return cur->next_mid;
}

void munmap (int mid)
{
  struct thread *t = thread_current();
  struct list_elem *next, *e = list_begin(&t->fm_list);
  while (e != list_end (&t->fm_list))
  {
    next = list_next(e);
    struct file_map *mmap = list_entry (e, struct file_map, elem);
	struct sub_page_unit *pu = mmap->subpu;
    e = next;
    if ( mid == ALL || mid == mmap->mid )
	{
	  pu->kernal_pin = true;
	  if (pu->occupy)
	  {
	    if (pagedir_is_dirty(t->pagedir, pu->vaddr))
		{
		  lock_acquire(&file_lock);
		  file_write_at(pu->file, pu->vaddr, pu->read_size, pu->ofs);
		  lock_release(&file_lock);
		}
	    free_frame(pagedir_get_page(t->pagedir, pu->vaddr));
	    pagedir_clear_page(t->pagedir, pu->vaddr);
	  }
	  if (pu->page_type != INSERT_FAIL)
	  {
	    hash_delete(&t->subpu_hash, &pu->elem);
	  }
	  list_remove(&mmap->elem);
	  free(pu);
	  free(mmap);
	}
  }
}

void pass_arg (struct intr_frame *f, int *arg, int n)
{
  int i;
  int *addr;
  for (i = 0; i < n; i++)
  {
    addr = (int *) f->esp + i + 1;
    if (load_addr((const void *) addr, f->esp))
      arg[i] = *addr;
	else
      exit(-1);
  }
}

bool load_addr(const void *vaddr, void* esp)
{
  if (!is_user_vaddr(vaddr) || vaddr < USER_VADDR_BOTTOM)
  {
    exit(-1);
  }
  bool success = false;
  struct sub_page_unit *subpu = get_subpu((void *) vaddr);
  if (subpu)
  {
    lazy_load(subpu);
    success = subpu->occupy;
  }
  else if (vaddr >= esp - STACK_FAULT)
  {
    success = page_alloc((void *) vaddr);
  }
  if (!success)
  {
    exit(-1);
  }
  return true;
}

void load_str (void* str, void* esp)
{
  load_addr(str, esp);
  while (* (char *) str != 0)
    {
      str = (char *) str + 1;
      load_addr(str, esp);
    }
}


void load_buffer (void* addr, unsigned size, void* esp, bool write)
{
  int i;
  char* vaddr = (char *) addr;
  for (i = 0; i < size; i++)
  {
    if (load_addr((void*)vaddr, esp) && write)
	{
	  struct sub_page_unit *subpu = get_subpu((void *)vaddr);
	  if (!subpu->writable)
        exit(-1);
	}
      vaddr++;
  }
}

void reset_addr (void* addr, int size)
{
  int i;
  struct sub_page_unit *subpu;
  for (i = 0; i < size; i++)
  {
    subpu = get_subpu(addr);
    if (subpu)
      subpu->kernal_pin = false;
    addr++;
  }
}

bool
verify_user (const void *addr) 
{
  return (addr < PHYS_BASE && addr > USER_VADDR_BOTTOM);
}
 
/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
put_user (uint8_t *udst, uint8_t byte)
{
  int eax;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
       : "=m" (*udst), "=&a" (eax) : "q" (byte));
  return eax != 0;
}