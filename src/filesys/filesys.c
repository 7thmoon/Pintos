#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "threads/malloc.h"


/* Partition that contains the file system. */
struct block *fs_device;

struct dir* get_inner_dir (const char* );
char* parse_name (const char* );
static void do_format (void);
struct inode * get_node(char *, struct dir * );

char* parse_name (const char* name)
{
  char p[strlen(name) + 1];
  memcpy(p, name, strlen(name) + 1);

  char *save_ptr, *prev="", *token = strtok_r(p, "/", &save_ptr);
  while(token)
  {
    prev = token;
	token = strtok_r (NULL, "/", &save_ptr);
  }
  char *file = malloc(strlen(prev) + 1);
  memcpy(file, prev, strlen(prev) + 1);
  return file;
}

struct inode * get_node(char *name, struct dir *dir )
{
  struct inode *inode = NULL;
  if (strcmp(name, "..") == 0)
  {
    inode = inode_open(dir_get_inode(dir)->parent);
  }
  else
  {
    dir_lookup (dir, name, &inode);
  }
  return inode;
}

struct dir* get_inner_dir (const char* name)
{
  char p[strlen(name) + 1];
  memcpy(p, name, strlen(name) + 1);
  char *save_ptr, *token = strtok_r(p, "/", &save_ptr), *next = token ? strtok_r(NULL, "/", &save_ptr) : NULL;
  struct dir* inner_dir;
  struct inode *inode;
  if (!thread_current()->pwd || p[0] == '/')
    inner_dir = dir_open_root();
  else
    inner_dir = dir_reopen(thread_current()->pwd);
  while (next != NULL)
  {
    if (strcmp(token, ".") != 0)
	{
	  struct inode *inode;
	  if (strcmp(token, "..") == 0 )
	    inode = inode_open(dir_get_inode(inner_dir)->parent);
	  else
	    dir_lookup(inner_dir, token, &inode);
	  if(!inode)
	    return NULL;
	  if(!inode->dir_flag)
	  {
	    inode_close(inode);
		return NULL;;
	  }
	  dir_close(inner_dir);
	  inner_dir = dir_open(inode);
	}
    token = next;
    next = strtok_r(NULL, "/", &save_ptr);
  }
  return inner_dir;
}

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  cache_list_init();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  cache_write_all();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool dir_flag) 
{
  block_sector_t inode_sector = 0;
  struct dir *dir = get_inner_dir(name);
  char* file = parse_name(name);
  bool success = false;
  if (strcmp(file, ".") != 0 && strcmp(file, "..") != 0)
    {
      success = (dir != NULL
		         && free_map_allocate (1, &inode_sector)
		         && inode_create (inode_sector, initial_size, dir_flag)
		         && dir_add (dir, file, inode_sector));
    }
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);
  free(file);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  if (strlen(name) == 0)
  {
    return NULL;
  }
  struct dir* dir = get_inner_dir(name);
  struct inode * inode = NULL;
  
  if (!dir)
    return NULL;
  char* file = parse_name(name);
  if (strlen(file) == 0||  strcmp(file, ".") == 0)
  {
     free(file);
     return (struct file *) dir;
  }
  inode = get_node(file, dir);
  dir_close(dir);
  free(file);
  if (!inode)
  {
    return NULL;
  }
  if (!inode->dir_flag)
  {
    return file_open (inode);
  }
  return (struct file *) dir_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct dir* dir = get_inner_dir(name);
  char* file = parse_name(name);
  bool success = dir != NULL && dir_remove (dir, file);
  dir_close (dir);
  free(file);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

bool filesys_chdir (const char* name)
{
  struct dir* dir = get_inner_dir(name);
  struct inode *inode = NULL;
  
  if (!dir)
    return NULL;
  char* file = parse_name(name);
  if (strlen(file) == 0 ||  strcmp(file, ".") == 0)
  {
     free(file);
	 thread_current()->pwd = dir;
     return true;
  }
  inode = get_node(file, dir);
  dir_close (dir);
  free(file);
  if (!inode)
  {
    return false;
  }
  dir = dir_open (inode);
  if (dir)
  {
    dir_close(thread_current()->pwd);
    thread_current()->pwd = dir;
    return true;
  }
  return false;
}