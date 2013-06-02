/*
 * ATTENTION: In order for this to work, we need the address of the sys_call_table:
 * grep "sys_call_table" /boot/System.map
 */

/*
 * Here's the strategy: Count the number of consecutive read calls for any file
 * descriptor. Reset this count whenever a file is opened, closed, or lseek'd.
 * If we reach a certain count, the file gets interesting.
 */

#undef __KERNEL__
#define __KERNEL__

#undef MODULE
#define MODULE

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <asm/semaphore.h>
#include <asm/cacheflush.h>

MODULE_LICENSE("GPL");

void ** SYS_CALL_TABLE = (void **)0xffffffff80296f40;
asmlinkage int (*original_open) (const char*, int, int);
asmlinkage int (*original_close) (int);
asmlinkage off_t (*original_lseek) (int, off_t, int);
asmlinkage ssize_t (*original_read) (int, void*, size_t);
asmlinkage ssize_t (*original_write) (int, const void*, size_t);

// watch this many file descriptors... we need to keep track of counts
#define MAX_FD 16384
#define TRIGGER_COUNT 500
unsigned int cons_read_counts[MAX_FD];

asmlinkage int hook_open(const char* pathname, int flags, int mode)
{
    int fd = original_open(pathname, flags, mode);
    cons_read_counts[fd] = 0;
    return fd;
}

asmlinkage int hook_close(int fd)
{
    cons_read_counts[fd] = 0;
    return original_close(fd);
}

asmlinkage off_t hook_lseek(int fd, off_t offset, int whence)
{
    cons_read_counts[fd] = 0;
    return original_lseek(fd, offset, whence);
}

asmlinkage ssize_t hook_read(int fd, void *buf, size_t count)
{
    if (cons_read_counts[fd] < TRIGGER_COUNT)
    {
        cons_read_counts[fd] += 1;
        if (cons_read_counts[fd] == TRIGGER_COUNT)
        {
            printk(KERN_INFO "[diob_lkm] There's an awful lot of reading going on for FD %d. Current read size is %d.\n", fd, count);
        }
    }
    return original_read(fd, buf, count);
}

asmlinkage ssize_t hook_write(int fd, const void *buf, size_t count)
{
    return original_write(fd, buf, count);
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

static int __init diob_init(void)
{
    int i;
    for (i = 0; i < MAX_FD; i++)
        cons_read_counts[i] = 0;
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
    printk(KERN_INFO "[diob_lkm] Successfully set up I/O hooks.\n");
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
    printk(KERN_INFO "[diob_lkm] Successfully removed I/O hooks.\n");
}

module_init(diob_init);
module_exit(diob_cleanup);
