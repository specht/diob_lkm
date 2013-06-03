/*
 * ATTENTION: In order for this to work, we need the address of the system call table/
 * 
 * Find out with:
 * grep " sys_call_table" /boot/System.map-`uname -r`
 * and set SYS_CALL_TABLE accordingly.
 * 
 * Also, this module cannot be safely unloaded because it is probable that someone
 * is currently in our read hook while we unload the module.
 */

#undef __KERNEL__
#define __KERNEL__

#undef MODULE
#define MODULE

#include <asm/cacheflush.h>
#include <asm/semaphore.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/vmalloc.h>

#include "crc16.h"

MODULE_LICENSE("GPL");

void ** SYS_CALL_TABLE = (void **)0xffffffff80296f40;

asmlinkage int (*original_open) (const char*, int, int);
asmlinkage int (*original_close) (int);
asmlinkage off_t (*original_lseek) (int, off_t, int);
asmlinkage ssize_t (*original_read) (int, void*, size_t);
asmlinkage ssize_t (*original_write) (int, const void*, size_t);
asmlinkage int (*original_fstat) (int, struct stat*);

// #define MAX_FD 256
#define MAX_HASH 0x10000
#define TRIGGER_COUNT 1024
#define MAX_READ_SIZE 65536
#define MAX_ACCELERATORS 256
#define BUFFER_SIZE_IN_KILOBYTES 4096
#define MIN_FILE_SIZE 16777216

// typedef struct _r_fd_watcher r_fd_watcher;
typedef struct _r_hash_watcher r_hash_watcher;
typedef struct _r_fd_accelerator r_fd_accelerator;
typedef unsigned short hash_t;

/*
struct _r_fd_watcher
{
    bool watch_this;
    unsigned short small_read_count;
    r_fd_accelerator* accelerator;
};
*/

struct _r_hash_watcher
{
    void* file_pointer;
    // TODO: This is cosy, but it wastes a lot of space because a full page
    // is probably allocated on ever vmalloc() call
    r_fd_accelerator* accelerator;
    unsigned short small_read_count;
};

struct _r_fd_accelerator
{
    size_t buffer_size;
    size_t buffer_length;
    off_t buffer_offset;
    void *buffer;
};

// static r_fd_watcher fd_watcher[MAX_FD];
static r_hash_watcher hash_watcher[MAX_HASH];
static unsigned int accelerator_count = 0;
static const char* PREFIXES[] = {
    "/media", 
    "/home", 
    NULL}; // NULL is required at the end to stop processing
    

static void disable_page_protection(void) 
{
    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (value & 0x00010000) 
    {
        value &= ~0x00010000;
        asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

static void enable_page_protection(void) 
{
    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (!(value & 0x00010000)) 
    {
        value |= 0x00010000;
        asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

static void init_watcher(hash_t hash)
{
    hash_watcher[hash].file_pointer = NULL;
    hash_watcher[hash].small_read_count = 0;
    hash_watcher[hash].accelerator = NULL;
}


static void reset_accelerator(hash_t hash)
{
//     printk("void reset_accelerator(fd = %d)\n", fd);
    if (hash_watcher[hash].accelerator)
    {
        if (hash_watcher[hash].accelerator->buffer)
        {
            vfree(hash_watcher[hash].accelerator->buffer);
            hash_watcher[hash].accelerator->buffer = NULL;
        }
        vfree(hash_watcher[hash].accelerator);
        hash_watcher[hash].accelerator = NULL;
    }
}

static void reset_watcher(hash_t hash)
{
//     printk("void reset_watcher(fd = %d)\n", fd);
    if (hash_watcher[hash].file_pointer)
    {
        printk("Now resetting watcher for hash %04x.\n", hash);
        hash_watcher[hash].file_pointer = false;
        hash_watcher[hash].small_read_count = 0;
        if (hash_watcher[hash].accelerator)
        {
            printk("Now resetting accelerator %p.\n", hash_watcher[hash].accelerator);
            reset_accelerator(hash);
        }
    }
}

asmlinkage int hook_open(const char* pathname, int flags, int mode)
{
    struct file* _file;
    unsigned short hash;
    struct stat _stat;
    mm_segment_t fs;
    int stat_result;
    
    int fd = original_open(pathname, flags, mode);
    
    rcu_read_lock();
    _file = fcheck_files(current->files, fd);
    rcu_read_unlock();
    
    if (!_file)
        return fd;
    
    hash = crc16_from_pointer(_file);
    
    reset_watcher(hash);

    // stat the file descriptor
    fs = get_fs();
    set_fs(get_ds());
    stat_result = original_fstat(fd, &_stat);
    set_fs(fs);
    
    if (stat_result == 0)
    {
        // stat was successful
        off_t filesize = _stat.st_size;
        bool is_regular_file = S_ISREG(_stat.st_mode);
        
        if (is_regular_file && filesize >= MIN_FILE_SIZE)
        {
            // file is a regular file and not too small
            bool prefix_match = false;
            const char** patterns = PREFIXES;
        
            /*
            while (*patterns)
            {
                const char *pattern = *(patterns++);
                const char *subject = pathname;
                bool good = true;
                while (*pattern && *subject)
                {
                    if (*pattern != *subject) 
                    {
                        good = false;
                        break;
                    }
                    pattern++;
                    subject++;
                }
                if (good)
                {
                    prefix_match = true;
                    break;
                }
            }
            */
            prefix_match = true;
            
            if (prefix_match)
            {
                hash_watcher[hash].file_pointer = _file;
                printk("[diob_lkm] hook_open(%s) - now watching (hash %04x).\n", pathname, hash);
            }
        }
    }
    return fd;
}

asmlinkage int hook_close(int fd)
{
    struct file* _file;
    unsigned short hash;
    
    rcu_read_lock();
    _file = fcheck_files(current->files, fd);
    rcu_read_unlock();
    
    if (_file)
    {
        hash = crc16_from_pointer(_file);
        if (hash_watcher[hash].file_pointer == _file)
        {
            printk("[%04x] int hook_close(fd = %d)\n", hash, fd);
            reset_watcher(hash);
        }
    }
    
    return original_close(fd);
}

asmlinkage off_t hook_lseek(int fd, off_t offset, int whence)
{
    struct file* _file;
    unsigned short hash;
    
    rcu_read_lock();
    _file = fcheck_files(current->files, fd);
    rcu_read_unlock();
    
    if (_file)
    {
        hash = crc16_from_pointer(_file);
        if (hash_watcher[hash].file_pointer == _file)
        {
            printk("[%04x] int hook_lseek(fd = %d, offset = %zd, whence = %d)\n", hash, fd, offset, whence);
            reset_watcher(hash);
        }
    }
    
    return original_lseek(fd, offset, whence);
}

asmlinkage ssize_t hook_read(int fd, void *buf, size_t count)
{
    struct file* _file;
    unsigned short hash;
    
    rcu_read_lock();
    _file = fcheck_files(current->files, fd);
    rcu_read_unlock();
    
    if (!_file)
        return original_read(fd, buf, count);

    hash = crc16_from_pointer(_file);
    
    if (hash_watcher[hash].file_pointer == _file)
    {
        // we're watching this file!
        if (!hash_watcher[hash].accelerator)
        {
            // there's no accelerator for this file descriptor yet
            if (count < MAX_READ_SIZE)
            {
                // it's a short read
                if (hash_watcher[hash].small_read_count < TRIGGER_COUNT)
                {
                    // we still haven't triggered
                    hash_watcher[hash].small_read_count += 1;
                    if (hash_watcher[hash].small_read_count == TRIGGER_COUNT)
                    {
                        printk("[diob_lkm] There's an awful lot of reading going on for hash %04x. Current read size is %zd.\n", hash, count);
                        if (accelerator_count < MAX_ACCELERATORS)
                        {
                            r_fd_accelerator* temp_accelerator;
                            // add another accelerator
                            temp_accelerator = vmalloc(sizeof(r_fd_accelerator));
                            if (temp_accelerator)
                            {
                                temp_accelerator->buffer_size = BUFFER_SIZE_IN_KILOBYTES * 1024;
                                temp_accelerator->buffer_length = 0;
                                temp_accelerator->buffer_offset = 0;
                                temp_accelerator->buffer = vmalloc(temp_accelerator->buffer_size);
                                if (temp_accelerator->buffer)
                                {
                                    // memory allocation was good
                                    mm_segment_t fs;
                                    ssize_t bytes_read = -1;

                                    // now fill the buffer
                                    fs = get_fs();
                                    set_fs(get_ds());
                                    bytes_read = original_read(fd, temp_accelerator->buffer, temp_accelerator->buffer_size);
                                    set_fs(fs);
                                    
                                    // TODO: bytes_read might be 0 or negative
                                    
                                    hash_watcher[hash].accelerator = temp_accelerator;
                                    accelerator_count += 1;
                                    printk("[diob_lkm] Added an accelerator for hash %04x, buffer %p.\n", hash, temp_accelerator->buffer);
                                    
                                    printk("We just filled the hash %04x buffer with %zd bytes.\n", hash, bytes_read);
                                    
                                    original_lseek(fd, -bytes_read, SEEK_CUR);
                                    
                                    // TODO check return value of original_lseek
                                    temp_accelerator->buffer_length = bytes_read;
                                    temp_accelerator->buffer_offset = 0;
                                }
                                else
                                {
                                    // buffer could not be allocated, clean up accelerator
                                    vfree(temp_accelerator);
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                reset_watcher(hash);
            }
        }
        
        if (hash_watcher[hash].accelerator)
        {
            r_fd_accelerator* a = hash_watcher[hash].accelerator;
            int loop;
            
            for (loop = 0; loop < 2; loop++)
            {
                // there's already an accelerator
                if (a->buffer_offset < a->buffer_length)
                {
                    // return at most the number of requested bytes (maybe less)
                    ssize_t copy_bytes = count;
                    
                    if (copy_bytes + a->buffer_offset >= a->buffer_length)
                        copy_bytes = a->buffer_length - a->buffer_offset;
                    if (copy_bytes < 0)
                        copy_bytes = 0;
                    if (copy_bytes > 0)
                    {
                        // don't serve 0 bytes from cache, it would mean early EOF
    //                     printk("Now serving %zd bytes from the buffer...\n", copy_bytes);
                        copy_to_user(buf, a->buffer + a->buffer_offset, copy_bytes);
                        // TODO: check return value
                        a->buffer_offset += copy_bytes;
                        
                        // advance file offset
                        original_lseek(fd, copy_bytes, SEEK_CUR);
                        return copy_bytes;
                    }
                }
                
                if (loop == 0)
                {
                    // we're still here, so fill up the buffer

                    // buffer is used up, refill it
                    mm_segment_t fs;
                    ssize_t bytes_read = -1;

                    // now fill the buffer
                    fs = get_fs();
                    set_fs(get_ds());
                    bytes_read = original_read(fd, a->buffer, a->buffer_size);
                    set_fs(fs);
                    
                    if (bytes_read == 0)
                    {
                        printk("Stopping buffering now, EOF.\n");
//                         reset_accelerator(fd);
                    }
                    else if (bytes_read < 0)
                    {
                        printk("There was a reading error: %zd, passing it on.\n", bytes_read);
                        return bytes_read;
//                         reset_accelerator(fd);
                    }
                    else
                    {
                        printk("We just re-filled the FD %d buffer with %zd bytes.\n", fd, bytes_read);
                        original_lseek(fd, -bytes_read, SEEK_CUR);
                        // TODO check return value of original_lseek
                        a->buffer_length = bytes_read;
                        a->buffer_offset = 0;
                    }
                }
            }
        }
    }
    return original_read(fd, buf, count);
}

asmlinkage ssize_t hook_write(int fd, const void *buf, size_t count)
{
    return original_write(fd, buf, count);
}

static int __init diob_init(void)
{
    int i;
    
    for (i = 0; i < MAX_HASH; i++)
        init_watcher(i);
    
    original_open = SYS_CALL_TABLE[__NR_open];
    original_close = SYS_CALL_TABLE[__NR_close];
    original_lseek = SYS_CALL_TABLE[__NR_lseek];
    original_read = SYS_CALL_TABLE[__NR_read];
    original_write = SYS_CALL_TABLE[__NR_write];
    original_fstat = SYS_CALL_TABLE[__NR_fstat];
    
    disable_page_protection();
    SYS_CALL_TABLE[__NR_open] = hook_open;
    SYS_CALL_TABLE[__NR_close] = hook_close;
    SYS_CALL_TABLE[__NR_lseek] = hook_lseek;
    SYS_CALL_TABLE[__NR_read] = hook_read;
    SYS_CALL_TABLE[__NR_write] = hook_write;
    enable_page_protection();
    
    printk("[diob_lkm] Successfully set up I/O hooks.\n");
    
    return 0;
}

static void __exit diob_cleanup(void)
{
    disable_page_protection();
    SYS_CALL_TABLE[__NR_open] = original_open;
    SYS_CALL_TABLE[__NR_close] = original_close;
    SYS_CALL_TABLE[__NR_lseek] = original_lseek;
    SYS_CALL_TABLE[__NR_read] = original_read;
    SYS_CALL_TABLE[__NR_write] = original_write;
    enable_page_protection();
    
    printk("[diob_lkm] Shutting down with %d accelerators.\n", accelerator_count);
    // release aquired buffers
    /*
    for (i = 0; i < accelerator_count; i++)
    {
        if (fd_accelerator[i].buffer)
        {
            printk("[diob_lkm] Releasing buffer %p.\n", fd_accelerator[i].buffer);
            vfree(fd_accelerator[i].buffer);
            fd_accelerator[i].buffer = NULL;
        }
    }
    */
    
    printk("[diob_lkm] Successfully restored I/O hooks.\n");
}

module_init(diob_init);
module_exit(diob_cleanup);
