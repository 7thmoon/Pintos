#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

#define STACK_FAULT 32
#define USER_VADDR_BOTTOM ((void *) 0x08048000)
#define ALL -1

struct lock file_lock;
bool verify_user (const void *);
void close_file (int );
void munmap (int );
void syscall_init (void);

#endif /* userprog/syscall.h */
