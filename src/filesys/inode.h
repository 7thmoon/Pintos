#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/off_t.h"
#include "threads/synch.h"
#include "devices/block.h"

#define LVL1_PTR 4          /* Level 1 block(direct) pointers number */        
#define LVL2_PTR 7          /* Level 2 block(indirect) pointers number */    
#define LVL3_PTR 1          /* Level 3 block(double indirect) pointers number */   
#define TOTAL_BLOCK_PTR 12  /* Total block pointers number */   

#define LVL1_INDEX 0        /* Level 1 block(direct) index */ 
#define LVL2_INDEX 4        /* Level 2 block(indirect)index */       
#define LVL3_INDEX 11       /* Level 3 block(double indirect) index */   
#define MULTI_LVL_PTR 128

#define MAX_FILE_SIZE 8318976

struct bitmap;
/* In-memory inode. */
struct inode 
{
  block_sector_t tbl[TOTAL_BLOCK_PTR];  /* Pointers to blocks */
  block_sector_t sector;                /* Sector number of disk location */
  block_sector_t parent;                /* Parent directory sector number */
  uint32_t index[3];                    /* Multilevel block index pointers 
                                         index[0] for level 1 block (direct)
										 index[1] for level 2 block (indirect)
										 index[2] for level 3 block (double indirect) */
  int open_cnt;                         /* Number of openers */
  bool removed;                         /* True if deleted, false otherwise */
  int deny_write_cnt;                   /* 0: writes ok, >0: deny writes */
  off_t length;                         /* File size in bytes */
  bool dir_flag;                        /* True if the inode is a directory */
  off_t length_for_read;                /* Bytes size for read */
  struct list_elem elem;                /* Element in inode list */
  struct lock lock;                     /* Lock for atomicity */
};

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  block_sector_t tbl[TOTAL_BLOCK_PTR];     /* Pointers to multilevel blocks */
  block_sector_t parent;                   /* Parent directory sector number */
  uint32_t index[3];                       /* Multilevel block index pointers 
                                              index[0] for level 1 block (direct)
                                              index[1] for level 2 block (indirect)
                                              index[2] for level 3 block (double indirect) */
  off_t length;                            /* File size in bytes. */
  unsigned magic;                          /* Magic number. */
  bool dir_flag;                           /* True if the inode is directory */
  uint32_t unused[109];                    /* Not used. */
};

struct multi_lvl_block                     /* For level 2 and 3 block */ 
{
  block_sector_t tbl[MULTI_LVL_PTR];       /* Pointers to data blocks */
};


void inode_init (void);
bool inode_create (block_sector_t, off_t, bool);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (struct inode *);
block_sector_t inode_get_parent (const struct inode *);
bool inode_add_parent (block_sector_t , block_sector_t);


#endif /* filesys/inode.h */
