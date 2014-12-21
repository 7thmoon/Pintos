#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "filesys/cache.h"

bool cache_init = false;

void cache_list_init (void)
{
  lock_init(&cache_lock);
  list_init(&cache_list);
  cache_init = true;
}

struct cache_entry* block_in_cache (block_sector_t sector)
{
  struct cache_entry *c;
  struct list_elem *e;
  for (e = list_begin(&cache_list); e != list_end(&cache_list); e = list_next(e))
  {
    c = list_entry(e, struct cache_entry, elem);
    if (c->sector == sector)
	{
	  return c;
	}
  }
  return NULL;
}

struct cache_entry* get_cache_block (block_sector_t sector, bool dirty)
{
  lock_acquire(&cache_lock);
  struct cache_entry *c = block_in_cache(sector);
  if (c)
  {
    c->open_cnt++;
    c->dirty |= dirty;
    c->accessed = true;
    lock_release(&cache_lock);
    return c;
  }
  if (list_size(&cache_list) < MAX_CACHE_SIZE)
  {
	uint8_t *buffer = malloc(BLOCK_SECTOR_SIZE*sizeof(uint8_t));
    c = malloc(sizeof(struct cache_entry));
	c->cache_block = buffer; 
    c->open_cnt = 1;
	c->count = 0;
    c->sector = sector;
    c->dirty = dirty;
    c->accessed = true;
    block_read(fs_device, c->sector, c->cache_block);
	list_push_back(&cache_list, &c->elem);
  }
  else
    c = evict_cache_block(sector, dirty);
  lock_release(&cache_lock);
  return c;
}

struct cache_entry* evict_cache_block (block_sector_t sector, bool dirty)
{
  struct cache_entry *c;
  struct cache_entry *evict = NULL;
  int lowest_count = 100;
  struct list_elem *e = list_begin(&cache_list);
  c = list_entry(e, struct cache_entry, elem);
  evict = c;
  lowest_count = c->count;
  while (e != list_end(&cache_list))
  {
    c = list_entry(e, struct cache_entry, elem);
    if (c->open_cnt > 0)
    {
	continue;
    }
    if (c->accessed)
    {
	c->accessed = false;
    }
    else
    {
      if (c->count <= lowest_count)
      {
        lowest_count = c->count;
        evict = c;
      }
    }
    e = list_next(e);
  }
  if (evict->dirty)
  {
    block_write(fs_device, evict->sector, evict->cache_block);
  }
  evict->open_cnt++;
  evict->sector = sector;
  block_read(fs_device, evict->sector, evict->cache_block);
  evict->dirty = dirty;
  evict->accessed = true;
  return evict;
}

void cache_tick(int64_t cur_ticks) 
{
  if(!cache_init)
    return; 
  struct cache_entry *c;
  struct list_elem *e;
  
  if (cur_ticks % CACHE_AGING_FREQ == 0)
  {
    e = list_begin(&cache_list);
    while (e != list_end(&cache_list) && e != NULL) 
    {
      c = list_entry(e, struct cache_entry, elem);
      c->count = c->count >> 1;
      c->count &= (c->accessed << (sizeof(c->count) - 1));
      c->accessed = false;
      e = list_next(e);
    }
  }
  if (cur_ticks % CACHE_WRITE_FREQ == 0) 
  {
     cache_write_all();
  }
}

void cache_write_all()
{
  lock_acquire(&cache_lock);
  struct list_elem *next, *e = list_begin(&cache_list);
  while (e != list_end(&cache_list))
  {
    next = list_next(e);
    struct cache_entry *c = list_entry(e, struct cache_entry, elem);
    if (c->dirty)
	{
	  block_write (fs_device, c->sector, c->cache_block);
	  c->dirty = false;
	}
    e = next;
 }
 lock_release(&cache_lock);
}

void read_ahead_thread(block_sector_t sector)
{
  if (sector)
  {
     sector = sector + 1;
     thread_create("cache_read_ahead", 0, cache_read_ahead, sector);
  }
}

void cache_read_ahead(block_sector_t sector)
{
  lock_acquire(&cache_lock);
  struct cache_entry *c = block_in_cache(sector);
  if (!c)
  {
	evict_cache_block (sector, false);
  }
  lock_release(&cache_lock);
}