/*
 * ATTENTION: In order for this to work, we need the address of the system call table/
 * 
 * Find out with:
 * grep " sys_call_table" /boot/System.map-`uname -r`
 * and set SYS_CALL_TABLE accordingly.
 * 
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

// we're using 16 bit hashes
#define MAX_HASH 0x10000

// a file must be at least this big to be watched
#define MIN_FILE_SIZE 16777216

// every read smaller or equal to this is considered a small read
#define MAX_READ_SIZE 65536

// allocate no more than this many accelerators
#define MAX_ACCELERATORS 256

/* define stage thresholds as (trigger_count, buffer size in kilobytes) tuples
 * ATTENTION: The trigger counts are 16 bit numbers and must not exceed 65534.
 *
 * Assuming a default read size of 4k:
 *  - 256k buffering is triggered after reading a total of 4 MB, 
 *  - 1M buffering is triggered after reading a total of 8 MB, 
 *  - 4M buffering is triggered after reading a total of 12 MB
 */
#define STAGE_THRESHOLD_COUNT 3
static unsigned int STAGE_THRESHOLDS[STAGE_THRESHOLD_COUNT][2] = {
    {1024, 256},
    {1024, 1024},
    {1024, 4096}
}; 


typedef struct _r_hash_watcher r_hash_watcher;
typedef struct _r_fd_accelerator r_fd_accelerator;
typedef unsigned short hash_t;

// this structure is 24 bytes big on a 64 bit machine
struct _r_hash_watcher
{
    void* file_pointer;
    // TODO: This is cosy, but it wastes a lot of space because a full page
    // is probably allocated on every vmalloc() call, we could use 8k instead of 1M
    // here
    r_fd_accelerator* accelerator;
    unsigned short stage;
    unsigned short small_read_count;
};

// this structure is 32 bytes big on a 64 bit machine
struct _r_fd_accelerator
{
    size_t buffer_size;
    size_t buffer_length;
    off_t buffer_offset;
    void *buffer;
};

// this structure uses 24 * 65536 bytes = 1.5 MiB in RAM
static r_hash_watcher hash_watcher[MAX_HASH];
static unsigned int accelerator_count = 0;

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
    hash_watcher[hash].stage  = 0;
    hash_watcher[hash].small_read_count = 0;
    hash_watcher[hash].accelerator = NULL;
}

static void reset_accelerator(hash_t hash)
{
    if (hash_watcher[hash].accelerator)
    {
        if (hash_watcher[hash].accelerator->buffer)
        {
            vfree(hash_watcher[hash].accelerator->buffer);
            hash_watcher[hash].accelerator->buffer = NULL;
        }
        vfree(hash_watcher[hash].accelerator);
        hash_watcher[hash].accelerator = NULL;
        accelerator_count--;
    }
}

// entirely reset a watcher
static void reset_watcher(hash_t hash)
{
    if (hash_watcher[hash].file_pointer)
    {
        hash_watcher[hash].file_pointer = NULL;
        hash_watcher[hash].stage = 0;
        hash_watcher[hash].small_read_count = 0;
        if (hash_watcher[hash].accelerator)
            reset_accelerator(hash);
    }
}

// rewind a watcher - keep watching the file, but disable buffering and 
// reset the stage and small_read_count
static void reset_watcher_stage(hash_t hash)
{
    if (hash_watcher[hash].file_pointer)
    {
        hash_watcher[hash].stage = 0;
        hash_watcher[hash].small_read_count = 0;
        if (hash_watcher[hash].accelerator)
            reset_accelerator(hash);
    }
}

// This function returns 0 if every is well or a negative value if there was an 
// error which should be returned by the calling function. This error may come
// either from read() or lseek() - passing lseek() errors off as read() errors
// should be OK in this context.
static int setup_accelerator(hash_t hash, unsigned int buffer_size, int fd)
{
    r_fd_accelerator* temp_accelerator = NULL;
    
    if (accelerator_count >= MAX_ACCELERATORS)
        // we already have enough accelerators, let's not hog the entire RAM
        return 0;
    
    printk(KERN_DEBUG "[diob_lkm] [%04x] Now buffering with %d bytes.\n", hash, buffer_size);
    
    temp_accelerator = vmalloc(sizeof(r_fd_accelerator));
    if (temp_accelerator)
    {
        temp_accelerator->buffer_size = buffer_size;
        temp_accelerator->buffer_length = 0;
        temp_accelerator->buffer_offset = 0;
        temp_accelerator->buffer = vmalloc(temp_accelerator->buffer_size);
        if (temp_accelerator->buffer)
        {
            // memory allocation was good
            mm_segment_t fs;
            ssize_t bytes_read;
            off_t lseek_result;

            // now fill the buffer
            fs = get_fs();
            set_fs(get_ds());
            bytes_read = original_read(fd, temp_accelerator->buffer, temp_accelerator->buffer_size);
            set_fs(fs);
            
            if (bytes_read < 0)
            {
                // there was an error, stop trying to buffer this file and let
                // user space handle this error
                // TODO: Alternatively, we could not stop buffering and try again
                // the next time.
                vfree(temp_accelerator->buffer);
                vfree(temp_accelerator);
                return (int)bytes_read;
            }
            else if (bytes_read == 0)
            {
                // we're already at the end of the file, there's nothing here to buffer
                vfree(temp_accelerator->buffer);
                vfree(temp_accelerator);
                // this will call read again which will return 0 again
                // TODO: Is it true that read() will return 0 twice at EOF?
                return 0;
            }
            
            lseek_result = original_lseek(fd, -bytes_read, SEEK_CUR);
            if (lseek_result < 0)
            {
                // there was an error, let the calling function return it
                vfree(temp_accelerator->buffer);
                vfree(temp_accelerator);
                return (int)lseek_result;
            }
            
            temp_accelerator->buffer_length = bytes_read;
            temp_accelerator->buffer_offset = 0;

            // if there was a previous accelerator, free it now
            if (hash_watcher[hash].accelerator)
                reset_accelerator(hash);
            
            // everything's fine, register this accelerator
            hash_watcher[hash].accelerator = temp_accelerator;
            accelerator_count += 1;
        }
        else
        {
            // buffer could not be allocated, clean up accelerator
            vfree(temp_accelerator);
        }
    }
    return 0;
}

asmlinkage int hook_open(const char* pathname, int flags, int mode)
{
    struct file* _file;
    hash_t hash;
    struct stat _stat;
    mm_segment_t fs;
    int stat_result;
    
    int fd = original_open(pathname, flags, mode);
    
    rcu_read_lock();
    _file = fcheck_files(current->files, fd);
    rcu_read_unlock();
    
    // we didn't get a file, ignore this
    if (!_file)
        return fd;
    
    hash = crc16_from_pointer(_file);

    // hash slot is already occupied with another file, ignore this
    if (hash_watcher[hash].file_pointer)
        return fd;
    
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
            reset_watcher(hash);
            hash_watcher[hash].file_pointer = _file;
            printk(KERN_DEBUG "[diob_lkm] [%04x] hook_open(%s) - now watching this file.\n", hash, pathname);
        }
    }
    return fd;
}

asmlinkage int hook_close(int fd)
{
    struct file* _file;
    hash_t hash;
    
    rcu_read_lock();
    _file = fcheck_files(current->files, fd);
    rcu_read_unlock();
    
    if (_file)
    {
        hash = crc16_from_pointer(_file);
        if (hash_watcher[hash].file_pointer == _file)
        {
            printk(KERN_DEBUG "[diob_lkm] [%04x] hook_close(fd = %d), no more watching this file.\n", hash, fd);
            reset_watcher(hash);
        }
    }
    
    return original_close(fd);
}

asmlinkage off_t hook_lseek(int fd, off_t offset, int whence)
{
    struct file* _file;
    hash_t hash;
    
    rcu_read_lock();
    _file = fcheck_files(current->files, fd);
    rcu_read_unlock();
    
    if (_file)
    {
        hash = crc16_from_pointer(_file);
        if (hash_watcher[hash].file_pointer == _file)
            reset_watcher_stage(hash);
    }
    
    return original_lseek(fd, offset, whence);
}

asmlinkage ssize_t hook_read(int fd, void *buf, size_t count)
{
    struct file* _file;
    hash_t hash;
    
    // I know, size_t shouldn't be negative, but this ensures that counts
    // is positive and at least 1.
    if (count < 1)
        goto default_read;
    
    rcu_read_lock();
    _file = fcheck_files(current->files, fd);
    rcu_read_unlock();
    
    if (!_file)
        return original_read(fd, buf, count);

    hash = crc16_from_pointer(_file);
    
    if (hash_watcher[hash].file_pointer == _file)
    {
        // we're watching this file!
        if (count <= MAX_READ_SIZE)
        {
            // this is a small read, now increase small_read_count and maybe bump stage, too
            if (hash_watcher[hash].stage < STAGE_THRESHOLD_COUNT)
            {
                if (hash_watcher[hash].small_read_count <= STAGE_THRESHOLDS[hash_watcher[hash].stage][0])
                {
                    hash_watcher[hash].small_read_count++;
                    if (hash_watcher[hash].small_read_count == STAGE_THRESHOLDS[hash_watcher[hash].stage][0] + 1)
                    {
                        // we've reached a trigger count, set up buffering and bump stage
                        int result = setup_accelerator(hash, STAGE_THRESHOLDS[hash_watcher[hash].stage][1] << 10, fd);
                        if (result == 0)
                        {
                            hash_watcher[hash].stage++;
                            hash_watcher[hash].small_read_count = 0;
                        }
                        else
                        {
                            // it's an error, return it to the caller
                            // DISCUSSION: this error comes from lseek(), and we're in read()
                            // EBADF: If it's a bad file descriptor, OK, pass it on.
                            // EINVAL: This shouldn't happen because we just read n bytes 
                            // and then rewinded by n bytes.
                            // EOVERFLOW: If this happens, it's OK, pass it on.
                            // ESPIPE: If fd is suddenly not a regular file anymore, it's OK, pass it on.
                            // ENXIO: We don't use no SEEK_DATA or SEEK_HOLE, it can't happen.
                            // Bottom line: It is ok to return the error code.
                            if (result < 0)
                                return result;
                        }
                    }
                }
            }
        }
        else
        {
            // this isn't a small read, disable buffering
            // TODO: If this happens too often for a file because it triggers 
            // buffering and untriggers buffering again and again we should 
            // probably stop watching that file.
            reset_watcher_stage(hash);
        }
        
        if (hash_watcher[hash].accelerator)
        {
            r_fd_accelerator* a = hash_watcher[hash].accelerator;
            
            if (a->buffer_offset == a->buffer_length)
            {
                // buffer is used up, refill it now
                mm_segment_t fs;
                ssize_t bytes_read;

                // now fill the buffer
                fs = get_fs();
                set_fs(get_ds());
                bytes_read = original_read(fd, a->buffer, a->buffer_size);
                set_fs(fs);
                
                if (bytes_read == 0)
                {
                    // we've hit EOF, do nothing and let the original read() report 
                    // the fact
                }
                else if (bytes_read < 0)
                {
                    // there was an error, stop watching this file and
                    // pass reading error on to user space
                    reset_watcher(hash);
                    return bytes_read;
                }
                else
                {
                    off_t lseek_result;
                    lseek_result = original_lseek(fd, -bytes_read, SEEK_CUR);
                    if (lseek_result < 0)
                    {
                        // there was an error, stop watching this file and
                        // pass lseek error on to user space
                        reset_watcher(hash);
                        return (int)lseek_result;
                    }
                    a->buffer_length = bytes_read;
                    a->buffer_offset = 0;
                }
            }
            
            if (a->buffer_offset < a->buffer_length)
            {
                // buffer is not yet used up
                // return at most the number of requested bytes 
                // (maybe less if the buffer doesn't have that much stored)
                ssize_t copy_bytes = count;
                ssize_t copy_bytes_left_over;
                
                if (copy_bytes + a->buffer_offset >= a->buffer_length)
                    copy_bytes = a->buffer_length - a->buffer_offset;
                if (copy_bytes < 0)
                    copy_bytes = 0;
                if (copy_bytes > 0)
                {
                    off_t lseek_result;
                    // don't serve 0 bytes from cache, it would mean EOF
                    copy_bytes_left_over = copy_to_user(buf, a->buffer + a->buffer_offset, copy_bytes);
                    if (copy_bytes_left_over > 0)
                    {
                        // Well, we couldn't copy all bytes. How could that happen?
                        if (copy_bytes_left_over < copy_bytes)
                        {
                            // If we copied at least something, return that.
                            copy_bytes = copy_bytes - copy_bytes_left_over;
                        }
                        else if (copy_bytes_left_over == copy_bytes)
                        {
                            // If we copied nothing at all, something is wrong, 
                            // stop watching this file and call the default read syscall
                            reset_watcher(hash);
                            goto default_read;
                        }
                    }
                    a->buffer_offset += copy_bytes;
                    
                    // advance file offset
                    lseek_result = original_lseek(fd, copy_bytes, SEEK_CUR);
                    if (lseek_result < 0)
                    {
                        // there was an error, stop watching this file and
                        // pass lseek error on to user space
                        reset_watcher(hash);
                        return (int)lseek_result;
                    }
                    return copy_bytes;
                }
            }
        }
    }
default_read:
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
    
    printk(KERN_INFO "[diob_lkm] Successfully set up I/O hooks.\n");
    
    return 0;
}

static void __exit diob_cleanup(void)
{
    int i;
    
    disable_page_protection();
    SYS_CALL_TABLE[__NR_open] = original_open;
    SYS_CALL_TABLE[__NR_close] = original_close;
    SYS_CALL_TABLE[__NR_lseek] = original_lseek;
    SYS_CALL_TABLE[__NR_read] = original_read;
    SYS_CALL_TABLE[__NR_write] = original_write;
    enable_page_protection();
    
    printk(KERN_INFO "[diob_lkm] Shutting down with %d accelerators, now releasing memory.\n", accelerator_count);
    for (i = 0; i < MAX_HASH; i++)
        reset_watcher(i);    
    
    printk(KERN_INFO "[diob_lkm] Successfully restored I/O hooks.\n");
}

module_init(diob_init);
module_exit(diob_cleanup);
