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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
#include <asm/semaphore.h>
#include <asm/uaccess.h>
#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");

void ** SYS_CALL_TABLE = (void **)0xffffffff80296f40;

asmlinkage int (*original_open) (const char*, int, int);
asmlinkage int (*original_close) (int);
asmlinkage off_t (*original_lseek) (int, off_t, int);
asmlinkage ssize_t (*original_read) (int, void*, size_t);
asmlinkage ssize_t (*original_write) (int, const void*, size_t);

#define MAX_FD 256
#define TRIGGER_COUNT 1024
#define MAX_READ_SIZE 65536
#define MAX_ACCELERATORS 256

typedef struct _r_fd_watcher r_fd_watcher;
typedef struct _r_fd_accelerator r_fd_accelerator;

struct _r_fd_watcher
{
    bool watch_this;
    unsigned short small_read_count;
    r_fd_accelerator* accelerator;
};

struct _r_fd_accelerator
{
    size_t buffer_size;
    size_t buffer_length;
    off_t buffer_offset;
    void *buffer;
};

static r_fd_watcher fd_watcher[MAX_FD];
static unsigned int accelerator_count = 0;
static const char* PREFIXES[] = {
    "/media", 
    "/home", 
    NULL}; // NULL is required at the end to stop processing

static void init_watcher(int fd)
{
    if (fd >= 0 && fd < MAX_FD)
    {
        fd_watcher[fd].watch_this = false;
        fd_watcher[fd].small_read_count = 0;
        fd_watcher[fd].accelerator = NULL;
    }
}


static void reset_accelerator(int fd)
{
    if (fd >= 0 && fd < MAX_FD)
    {
        if (fd_watcher[fd].accelerator)
        {
            if (fd_watcher[fd].accelerator->buffer)
            {
                vfree(fd_watcher[fd].accelerator->buffer);
                fd_watcher[fd].accelerator->buffer = NULL;
            }
            vfree(fd_watcher[fd].accelerator);
            fd_watcher[fd].accelerator = NULL;
        }
    }
}

static void reset_watcher(int fd)
{
//     printk("reset_watcher(%d)\n", fd);
    if (fd >= 0 && fd < MAX_FD && fd_watcher[fd].watch_this)
    {
        fd_watcher[fd].watch_this = false;
        fd_watcher[fd].small_read_count = 0;
        if (fd_watcher[fd].accelerator)
        {
            printk("Now resetting accelerator %p.\n", fd_watcher[fd].accelerator);
            reset_accelerator(fd);
        }
    }
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

asmlinkage int hook_open(const char* pathname, int flags, int mode)
{
    int fd = original_open(pathname, flags, mode);
    
    if (fd >= 0 && fd < MAX_FD)
    {
        off_t pos;
        bool prefix_match = false;
        const char** patterns = PREFIXES;
        
        reset_watcher(fd);
    
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
        
        if (prefix_match)
        {
            pos = original_lseek(fd, 0, SEEK_SET);
            printk("[diob_lkm] We just opened %s as FD %d. lseek says %zd.\n", pathname, fd, pos);
            if (pos == 0)
            {
                // it's seekable and an interesting path, we'll watch it
                fd_watcher[fd].watch_this = true;
                printk("[diob_lkm] We'll be watching that FD %d.\n", fd);
            }
        }
    }
    return fd;
}

asmlinkage int hook_close(int fd)
{
    if (fd >= 0 && fd < MAX_FD && fd_watcher[fd].watch_this)
        reset_watcher(fd);
    return original_close(fd);
}

asmlinkage off_t hook_lseek(int fd, off_t offset, int whence)
{
    if (fd >= 0 && fd < MAX_FD && fd_watcher[fd].watch_this)
        reset_watcher(fd);
    return original_lseek(fd, offset, whence);
}

asmlinkage ssize_t hook_read(int fd, void *buf, size_t count)
{
//     off_t old_file_pos;
//     ssize_t bytes_read;
    
    if (fd >= 0 && fd < MAX_FD && fd_watcher[fd].watch_this)
    {
        if (!fd_watcher[fd].accelerator)
        {
            // there's no accelerator for this file descriptor yet
            if (count < MAX_READ_SIZE)
            {
                // it's a short read
                if (fd_watcher[fd].small_read_count < TRIGGER_COUNT)
                {
                    // we still haven't triggered
                    fd_watcher[fd].small_read_count += 1;
                    if (fd_watcher[fd].small_read_count == TRIGGER_COUNT)
                    {
                        printk("[diob_lkm] There's an awful lot of reading going on for FD %d. Current read size is %zd.\n", fd, count);
                        if (accelerator_count < MAX_ACCELERATORS)
                        {
                            r_fd_accelerator* temp_accelerator;
                            // add another accelerator
                            printk("sizeof(r_fd_accelerator) is %zd bytes.\n", sizeof(r_fd_accelerator));
                            temp_accelerator = vmalloc(sizeof(r_fd_accelerator));
                            if (temp_accelerator)
                            {
                                temp_accelerator->buffer_size = 4096 * 1024;
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
                                    
                                    fd_watcher[fd].accelerator = temp_accelerator;
                                    accelerator_count += 1;
                                    printk("[diob_lkm] Added an accelerator for FD %d, buffer %p.\n", fd, temp_accelerator->buffer);
                                    
                                    printk("We just filled the buffer with %zd bytes.\n", bytes_read);
                                    
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
//                         old_file_pos = original_lseek(fd, 0, SEEK_CUR);
//                         disable_page_protection();
//                         fs = get_fs();
//                         set_fs(get_ds());
//                         bytes_read = original_read(fd, buffer, 4096 * 1024);
//                         set_fs(fs);
//                         enable_page_protection();
//                         if (bytes_read < 0)
//                             printk("[diob_lkm] Hm, there appears to be an error: %d\n", bytes_read);
//                         else
//                             printk("[diob_lkm] I just read %zd bytes!\n", bytes_read);
//                         original_lseek(fd, old_file_pos, SEEK_SET);
                    }
                }
            }
            else
            {
                reset_watcher(fd);
            }
        }
        if (fd_watcher[fd].accelerator)
        {
            r_fd_accelerator* a = fd_watcher[fd].accelerator;
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
                        reset_accelerator(a);
                    }
                    else
                    {
                        printk("We just re-filled the buffer with %zd bytes.\n", bytes_read);
                    }
                    original_lseek(fd, -bytes_read, SEEK_CUR);
                    // TODO check return value of original_lseek
                    a->buffer_length = bytes_read;
                    a->buffer_offset = 0;
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
    
    original_open = SYS_CALL_TABLE[__NR_open];
    original_close = SYS_CALL_TABLE[__NR_close];
    original_lseek = SYS_CALL_TABLE[__NR_lseek];
    original_read = SYS_CALL_TABLE[__NR_read];
    original_write = SYS_CALL_TABLE[__NR_write];
    
    disable_page_protection();
    SYS_CALL_TABLE[__NR_open] = hook_open;
    SYS_CALL_TABLE[__NR_close] = hook_close;
    SYS_CALL_TABLE[__NR_lseek] = hook_lseek;
    SYS_CALL_TABLE[__NR_read] = hook_read;
    SYS_CALL_TABLE[__NR_write] = hook_write;
    enable_page_protection();
    
    printk("[diob_lkm] Successfully set up I/O hooks.\n");
    
    for (i = 0; i < MAX_FD; i++)
        init_watcher(i);
    
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
