#include "filesys/inode.h"
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

off_t inode_extend (struct inode *, off_t );
void inode_destory (struct inode *);
int get_chunk_size (struct inode *, off_t , off_t );

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->length)
  {
      uint32_t index;
      uint32_t multi_lvl_block[MULTI_LVL_PTR];
    if (pos < BLOCK_SECTOR_SIZE*LVL1_PTR)
	{
	  return inode->tbl[pos / BLOCK_SECTOR_SIZE];
	}
    else if (pos < BLOCK_SECTOR_SIZE*(LVL1_PTR + LVL2_PTR*MULTI_LVL_PTR))
	{
	  pos -= BLOCK_SECTOR_SIZE*LVL1_PTR;
	  index = pos / (BLOCK_SECTOR_SIZE*MULTI_LVL_PTR) + LVL1_PTR;
	  block_read(fs_device, inode->tbl[index], &multi_lvl_block);
	  pos %= BLOCK_SECTOR_SIZE*MULTI_LVL_PTR;
	  return multi_lvl_block[pos / BLOCK_SECTOR_SIZE];
	}
    else
	{
	  block_read(fs_device, inode->tbl[LVL3_INDEX], &multi_lvl_block);
	  pos -= BLOCK_SECTOR_SIZE*(LVL1_PTR + LVL2_PTR*MULTI_LVL_PTR);
	  index = pos / (BLOCK_SECTOR_SIZE*MULTI_LVL_PTR);
	  block_read(fs_device, multi_lvl_block[index], &multi_lvl_block);
	  pos %= BLOCK_SECTOR_SIZE*MULTI_LVL_PTR;
	  return multi_lvl_block[pos / BLOCK_SECTOR_SIZE];
	}
  }
  else
  {
    return -1;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool dir_flag)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;
  struct inode new_inode = {
    .index[0] = 0,
    .index[1] = 0,
    .index[2] = 0,
	.length = 0,
  };
  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
  {
    disk_inode->length = disk_inode->length < MAX_FILE_SIZE ? length : MAX_FILE_SIZE;
    disk_inode->magic = INODE_MAGIC;
    disk_inode->dir_flag = dir_flag;
    disk_inode->parent = ROOT_DIR_SECTOR;
	inode_extend(&new_inode, disk_inode->length);
    disk_inode->index[0] = new_inode.index[0];
    disk_inode->index[1] = new_inode.index[1];
    disk_inode->index[2] = new_inode.index[2];
    memcpy(&disk_inode->tbl, &new_inode.tbl, TOTAL_BLOCK_PTR*sizeof(block_sector_t));
    block_write (fs_device, sector, disk_inode);
    success = true; 
    free (disk_inode);
  }
  return success;
}

bool sector_extend (block_sector_t *sector, uint32_t *index, size_t *extend_sector)
{
  if ((*extend_sector) <= 0)
    return 0;
  static char zeros[BLOCK_SECTOR_SIZE];
  free_map_allocate(1, &sector[(*index)]);
  block_write(fs_device, sector[(*index)], zeros);
  (*extend_sector)--;
  (*index)++;
  return 1;
}
  
off_t inode_extend (struct inode *inode, off_t ext_length)
{
  struct multi_lvl_block lvl2_block;
  struct multi_lvl_block lvl3_block;
  size_t extend_sector = bytes_to_sectors(ext_length) - bytes_to_sectors(inode->length);
  
  if (extend_sector == 0)
  {
    return ext_length;
  }
  while (inode->index[0] < LVL2_INDEX)
  {
    if (!sector_extend (inode->tbl, &inode->index[0], &extend_sector))
	{
	  return ext_length;
	}
  }
  while (inode->index[0] < LVL3_INDEX)
  {
	if (inode->index[1] == 0)
    {
      free_map_allocate(1, &inode->tbl[inode->index[0]]);
    }
    else
    {
      block_read(fs_device, inode->tbl[inode->index[0]], &lvl2_block);
    }
	while (inode->index[1] < MULTI_LVL_PTR)
    {
	  if (!sector_extend (&lvl2_block.tbl, &inode->index[1], &extend_sector))
	  {
	    break;
	  }
    }
	block_write(fs_device, inode->tbl[inode->index[0]], &lvl2_block);
    if (inode->index[1] == MULTI_LVL_PTR)
    {
      inode->index[1] = 0;
      inode->index[0]++;
    }
    if (extend_sector == 0)
	{
	  return ext_length;
	}
  }
  if (inode->index[0] == LVL3_INDEX)
  {
    if (inode->index[2] == 0 && inode->index[1] == 0)
    {
      free_map_allocate(1, &inode->tbl[inode->index[0]]);
    }
    else
    {
      block_read(fs_device, inode->tbl[inode->index[0]], &lvl2_block);
    }
    while (inode->index[1] < MULTI_LVL_PTR)
    {
	  if (inode->index[2] == 0)
      {
        free_map_allocate(1, &lvl2_block.tbl[inode->index[1]]);
      }
      else
      {
        block_read(fs_device, lvl2_block.tbl[inode->index[1]], &lvl3_block);
      }
      while (inode->index[2] < MULTI_LVL_PTR)
      {
		if (!sector_extend (&lvl3_block.tbl, &inode->index[2], &extend_sector))
	    {
	      break;
	    }
      }
      block_write(fs_device, lvl2_block.tbl[inode->index[1]], &lvl3_block);
      if (inode->index[2] == MULTI_LVL_PTR)
      {
        inode->index[2] = 0;
        inode->index[1]++;
      }
      if (extend_sector == 0)
	  {
	    break;
	  }
    }
    block_write(fs_device, inode->tbl[inode->index[0]], &lvl2_block);
  }
  return ext_length - BLOCK_SECTOR_SIZE*extend_sector;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes); e = list_next (e)) 
  {
    inode = list_entry (e, struct inode, elem);
    if (inode->sector == sector) 
    {
      inode_reopen (inode);
      return inode; 
    }
  }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->lock);
  struct inode_disk data;
  block_read(fs_device, inode->sector, &data);
  inode->length = data.length;
  inode->length_for_read = data.length;
  inode->index[0] = data.index[0];
  inode->index[1] = data.index[1];
  inode->index[2] = data.index[2];
  inode->dir_flag = data.dir_flag;
  inode->parent = data.parent;
  memcpy(&inode->tbl, &data.tbl, TOTAL_BLOCK_PTR*sizeof(block_sector_t));
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
  {
      /* Remove from inode list and release lock. */
    list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
    if (inode->removed) 
    {
      free_map_release (inode->sector, 1);
	  inode_destory(inode);
    }
    else
	{
	  struct inode_disk disk_inode = {
	    .length = inode->length,
	    .magic = INODE_MAGIC,
	    .index[0] = inode->index[0],
	    .index[1] = inode->index[1],
	    .index[2] = inode->index[2],
	    .dir_flag = inode->dir_flag,
	    .parent = inode->parent,
	  };
	  memcpy(&disk_inode.tbl, &inode->tbl, TOTAL_BLOCK_PTR*sizeof(block_sector_t));
	  block_write(fs_device, inode->sector, &disk_inode);
	}
    free (inode); 
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}


int get_chunk_size (struct inode *inode, off_t offset, off_t size)
{
  int sector_ofs = offset % BLOCK_SECTOR_SIZE;

  /* Bytes left in inode, bytes left in sector, lesser of the two. */
  off_t inode_left = inode->length - offset;
  int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
  int min_left = inode_left < sector_left ? inode_left : sector_left;

  /* Number of bytes to actually write into this sector. */
  int chunk_size = size < min_left ? size : min_left;
  return chunk_size;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  off_t length = inode->length_for_read;

  if (offset >= length)
  {
    return bytes_read;
  }

  while (size > 0) 
  {
    int chunk_size = get_chunk_size(inode, offset, size);
    if (chunk_size <= 0)
      break;
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;	
    block_sector_t sector = byte_to_sector (inode, offset);	
    struct cache_entry *c = get_cache_block(sector, false);
    memcpy (buffer + bytes_read, (uint8_t *) (c->cache_block + sector_ofs), chunk_size);
    c->accessed = true;
    c->open_cnt--;

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
  off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  if (offset + size > inode->length)
  {
    if (!inode->dir_flag)
	{
	  lock_acquire(&inode->lock);
	}
    inode->length = inode_extend(inode, offset + size);
    if (!inode->dir_flag)
	{
	  lock_release(&inode->lock);
	}
  }
  while (size > 0) 
  {
    int chunk_size = get_chunk_size(inode, offset, size);
    if (chunk_size <= 0)
      break;	  
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;
	block_sector_t sector = byte_to_sector (inode, offset);	
    struct cache_entry *c = get_cache_block(sector, true);
    memcpy ((uint8_t *) (c->cache_block + sector_ofs), buffer + bytes_written, chunk_size);
    c->accessed = true;
    c->dirty = true;
    c->open_cnt--;
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  inode->length_for_read = inode_length(inode);
  return bytes_written;
}
 
/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

void inode_destory (struct inode *inode)
{
  size_t lvl1_sector = bytes_to_sectors(inode->length);
  size_t lvl2_sector;
  size_t lvl3_sector;
  size_t data_sector;
  if (inode->length <= BLOCK_SECTOR_SIZE*LVL1_PTR)
    lvl2_sector = 0;
  else
    lvl2_sector = DIV_ROUND_UP(inode->length - BLOCK_SECTOR_SIZE*LVL1_PTR, BLOCK_SECTOR_SIZE*MULTI_LVL_PTR);
  if (inode->length <= BLOCK_SECTOR_SIZE*(LVL1_PTR +LVL2_PTR*MULTI_LVL_PTR))
    lvl3_sector = 0;
  else
    lvl3_sector = LVL3_PTR;
	
  unsigned int index = 0;
  unsigned int i,j;
  struct multi_lvl_block lvl2_block;
  struct multi_lvl_block lvl3_block;
  while (lvl1_sector && index < LVL2_INDEX)
  {
    free_map_release (inode->tbl[index], 1);
    lvl1_sector--;
    index++;
  }
  while (lvl2_sector && index < LVL3_INDEX)
  {
    data_sector = lvl1_sector < MULTI_LVL_PTR ? lvl1_sector : MULTI_LVL_PTR;
    block_read(fs_device, inode->tbl[index], &lvl2_block);
    for (i = 0; i < data_sector; i++)
    {
      free_map_release(lvl2_block.tbl[i], 1);
    }
    free_map_release(inode->tbl[index], 1);
    lvl1_sector -= data_sector;
    lvl2_sector--;
    index++;
  }
  if (lvl3_sector)
  {
    block_read(fs_device, inode->tbl[index], &lvl2_block);
    for (i = 0; i < lvl2_sector; i++)
    {
      data_sector = lvl1_sector < MULTI_LVL_PTR ? lvl1_sector : MULTI_LVL_PTR;
	  block_read(fs_device, lvl2_block.tbl[i], &lvl3_block);
      for (j = 0; j < data_sector; j++)
      {
        free_map_release(lvl3_block.tbl[j], 1);
      }
      free_map_release(lvl2_block.tbl[i], 1);
	  
      lvl1_sector -= data_sector;
    }
    free_map_release(inode->tbl[index], 1);
  }
}


off_t
inode_length (struct inode *inode)
{
  return inode->length;
}
