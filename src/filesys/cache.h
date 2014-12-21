#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H
#include "devices/timer.h"
#include "threads/synch.h"
#include "devices/block.h"
#include <list.h>

#define MAX_CACHE_SIZE 64        /* Maximum cache block size*/
#define CACHE_AGING_FREQ 200     /* Frequency of updating count in aging algorithm*/
#define CACHE_WRITE_FREQ 20000   /* Write back frequency */
struct lock cache_lock;          /* Lock of the cache block*/
struct list cache_list;          /* The cache block implemented by list */

struct cache_entry {     
  uint8_t *cache_block;           /* The cache data block */
  block_sector_t sector;          /* The sector number of the data on disk */
  bool dirty;                     /* True if the data has been written to the entry*/
  bool accessed;                  /* True if the data has been accessed */
  int open_cnt;                   /* The count of processes using this entry */
  int count;                      /* The count using in aging algorithm */
  struct list_elem elem;          /* Element in cache list */
};

void cache_list_init (void);
struct cache_entry *block_in_cache (block_sector_t sector);
struct cache_entry* get_cache_block (block_sector_t sector, bool dirty);
struct cache_entry* evict_cache_block (block_sector_t sector, bool dirty);
void cache_tick(int64_t) ;
void cache_write_all();
void read_ahead_thread(block_sector_t sector);
void cache_read_ahead(block_sector_t sector);
#endif /* filesys/cache.h */
