/*
 * Note: Before you can compile this, you need to follow the
 * instructions in sys_call_table.template.h.
 */

#undef __KERNEL__
#define __KERNEL__

#define DEBUG_LEVEL KERN_INFO

#undef MODULE
#define MODULE

#include <asm/cacheflush.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#include <linux/fdtable.h>
#endif

#define COLLECT_STATS

MODULE_LICENSE("GPL");

#include "sys_call_table.h"

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

// every read smaller than this is considered a small read
#define MAX_READ_SIZE 131072

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
// we need 64k of these entries, so it's 1.5 MB
struct _r_hash_watcher
{
    const void* file_pointer;
    // TODO: This is cosy, but it wastes a lot of space because a full page
    // is probably allocated on every vmalloc() call, we could use 8k instead of 1M
    // here
    r_fd_accelerator* accelerator;
    unsigned short stage;
    unsigned short small_read_count;
#ifdef COLLECT_STATS
    unsigned long free_read_calls;
#endif
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

unsigned short crc16_table[256] = {
    0x0000, 0xdc77, 0x2837, 0xf440, 0x506e, 0x8c19, 0x7859, 0xa42e,
    0xa0dc, 0x7cab, 0x88eb, 0x549c, 0xf0b2, 0x2cc5, 0xd885, 0x04f2,
    0xd161, 0x0d16, 0xf956, 0x2521, 0x810f, 0x5d78, 0xa938, 0x754f,
    0x71bd, 0xadca, 0x598a, 0x85fd, 0x21d3, 0xfda4, 0x09e4, 0xd593,
    0x321b, 0xee6c, 0x1a2c, 0xc65b, 0x6275, 0xbe02, 0x4a42, 0x9635,
    0x92c7, 0x4eb0, 0xbaf0, 0x6687, 0xc2a9, 0x1ede, 0xea9e, 0x36e9,
    0xe37a, 0x3f0d, 0xcb4d, 0x173a, 0xb314, 0x6f63, 0x9b23, 0x4754,
    0x43a6, 0x9fd1, 0x6b91, 0xb7e6, 0x13c8, 0xcfbf, 0x3bff, 0xe788,
    0x6436, 0xb841, 0x4c01, 0x9076, 0x3458, 0xe82f, 0x1c6f, 0xc018,
    0xc4ea, 0x189d, 0xecdd, 0x30aa, 0x9484, 0x48f3, 0xbcb3, 0x60c4,
    0xb557, 0x6920, 0x9d60, 0x4117, 0xe539, 0x394e, 0xcd0e, 0x1179,
    0x158b, 0xc9fc, 0x3dbc, 0xe1cb, 0x45e5, 0x9992, 0x6dd2, 0xb1a5,
    0x562d, 0x8a5a, 0x7e1a, 0xa26d, 0x0643, 0xda34, 0x2e74, 0xf203,
    0xf6f1, 0x2a86, 0xdec6, 0x02b1, 0xa69f, 0x7ae8, 0x8ea8, 0x52df,
    0x874c, 0x5b3b, 0xaf7b, 0x730c, 0xd722, 0x0b55, 0xff15, 0x2362,
    0x2790, 0xfbe7, 0x0fa7, 0xd3d0, 0x77fe, 0xab89, 0x5fc9, 0x83be,
    0xc86c, 0x141b, 0xe05b, 0x3c2c, 0x9802, 0x4475, 0xb035, 0x6c42,
    0x68b0, 0xb4c7, 0x4087, 0x9cf0, 0x38de, 0xe4a9, 0x10e9, 0xcc9e,
    0x190d, 0xc57a, 0x313a, 0xed4d, 0x4963, 0x9514, 0x6154, 0xbd23,
    0xb9d1, 0x65a6, 0x91e6, 0x4d91, 0xe9bf, 0x35c8, 0xc188, 0x1dff,
    0xfa77, 0x2600, 0xd240, 0x0e37, 0xaa19, 0x766e, 0x822e, 0x5e59,
    0x5aab, 0x86dc, 0x729c, 0xaeeb, 0x0ac5, 0xd6b2, 0x22f2, 0xfe85,
    0x2b16, 0xf761, 0x0321, 0xdf56, 0x7b78, 0xa70f, 0x534f, 0x8f38,
    0x8bca, 0x57bd, 0xa3fd, 0x7f8a, 0xdba4, 0x07d3, 0xf393, 0x2fe4,
    0xac5a, 0x702d, 0x846d, 0x581a, 0xfc34, 0x2043, 0xd403, 0x0874,
    0x0c86, 0xd0f1, 0x24b1, 0xf8c6, 0x5ce8, 0x809f, 0x74df, 0xa8a8,
    0x7d3b, 0xa14c, 0x550c, 0x897b, 0x2d55, 0xf122, 0x0562, 0xd915,
    0xdde7, 0x0190, 0xf5d0, 0x29a7, 0x8d89, 0x51fe, 0xa5be, 0x79c9,
    0x9e41, 0x4236, 0xb676, 0x6a01, 0xce2f, 0x1258, 0xe618, 0x3a6f,
    0x3e9d, 0xe2ea, 0x16aa, 0xcadd, 0x6ef3, 0xb284, 0x46c4, 0x9ab3,
    0x4f20, 0x9357, 0x6717, 0xbb60, 0x1f4e, 0xc339, 0x3779, 0xeb0e,
    0xeffc, 0x338b, 0xc7cb, 0x1bbc, 0xbf92, 0x63e5, 0x97a5, 0x4bd2
};

unsigned short crc16_from_pointer(const void* p)
{
    const unsigned char *puc = (const unsigned char*)p;
    unsigned short crc = 0;
    int k;
    
    for (k = 0; k < sizeof(p); k++)
        crc = crc16_table[(crc ^ *puc++) & 0xff];
    
    return crc;
}

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
#ifdef COLLECT_STATS
    hash_watcher[hash].free_read_calls = 0;
#endif
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
        if (hash_watcher[hash].accelerator)
            reset_accelerator(hash);
        init_watcher(hash);
    }
}

// rewind a watcher - keep watching the file, but disable buffering and
// reset the stage and small_read_count
static void reset_watcher_stage(hash_t hash)
{
    if (hash_watcher[hash].file_pointer)
    {
        if (hash_watcher[hash].stage > 0)
            printk(DEBUG_LEVEL "[diob_lkm] [%04x] Rewinding watcher, was at stage %d, small_read_count %d.\n",
                   hash, hash_watcher[hash].stage, hash_watcher[hash].small_read_count);
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
    
    printk(DEBUG_LEVEL "[diob_lkm] [%04x] Now buffering with %d bytes.\n", hash, buffer_size);
    
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
    mm_segment_t fs;
    struct stat _stat;
    long stat_result;
    volatile long fd;
    
    fd = original_open(pathname, flags, mode);
    
    fs = get_fs();
    set_fs(get_ds());
    stat_result = original_fstat(fd, &_stat);
    set_fs(fs);
    
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
    
    if (stat_result == 0)
    {
        // stat was successful
        off_t filesize = _stat.st_size;
        bool is_regular_file = S_ISREG(_stat.st_mode);
        bool file_belongs_to_root = _stat.st_uid == 0;
        
        if (!file_belongs_to_root && is_regular_file && filesize >= MIN_FILE_SIZE)
        {
            // file is a regular file and not too small
            reset_watcher(hash);
            hash_watcher[hash].file_pointer = _file;
            printk(DEBUG_LEVEL "[diob_lkm] [%04x] hook_open(%s) - now watching this file.\n", hash, pathname);
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
#ifdef COLLECT_STATS
            printk(DEBUG_LEVEL "[diob_lkm] [%04x] hook_close(fd = %d), saved %ld read calls.\n", hash, fd, hash_watcher[hash].free_read_calls);
#else
            printk(DEBUG_LEVEL "[diob_lkm] [%04x] hook_close(fd = %d)\n", hash, fd);
#endif
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
    ssize_t read_result;
    
    // increase use count
    try_module_get(THIS_MODULE);

    // I know, size_t shouldn't be negative, but this ensures that counts
    // is positive and at least 1.
    if (count < 1)
        goto default_read;
    
    rcu_read_lock();
    _file = fcheck_files(current->files, fd);
    rcu_read_unlock();
    
    if (!_file)
        goto default_read;

    hash = crc16_from_pointer(_file);
    
    if (hash_watcher[hash].file_pointer == _file)
    {
        // we're watching this file!
        if (count < MAX_READ_SIZE)
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
                            {
                                // decrease use count
                                module_put(THIS_MODULE);
                                return result;
                            }
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
                    
                    // decrease use count
                    module_put(THIS_MODULE);
                    
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
                        
                        // decrease use count
                        module_put(THIS_MODULE);
                        
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
                        
                        // decrease use count
                        module_put(THIS_MODULE);
                        
                        return (int)lseek_result;
                    }
#ifdef COLLECT_STATS
                        hash_watcher[hash].free_read_calls++;
#endif
                    // decrease use count
                    module_put(THIS_MODULE);
                    
                    return copy_bytes;
                }
            }
        }
    }
default_read:
    read_result = original_read(fd, buf, count);
    
    // decrease use count
    module_put(THIS_MODULE);
    
    return read_result;
}

asmlinkage ssize_t hook_write(int fd, const void *buf, size_t count)
{
    struct file* _file;
    hash_t hash;
    ssize_t write_result;
    
    // increase use count
    try_module_get(THIS_MODULE);

    rcu_read_lock();
    _file = fcheck_files(current->files, fd);
    rcu_read_unlock();
    
    if (_file)
    {
        hash = crc16_from_pointer(_file);
        if (hash_watcher[hash].file_pointer == _file)
            reset_watcher_stage(hash);
    }
    
    write_result = original_write(fd, buf, count);
    
    // decrease use count
    module_put(THIS_MODULE);
    
    return write_result;
}

static int __init diob_init(void)
{
    int i;
    
    if (!SYS_CALL_TABLE)
    {
        printk(KERN_INFO "[diob_lkm] Unable to load module because SYS_CALL_TABLE is not set.\n");
        return 1;
    }
    
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
