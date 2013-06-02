/*
 * ATTENTION: In order for this to work, we need the address of the sys_call_table:
 * grep "sys_call_table" /boot/System.map
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

asmlinkage int hook_open(const char* pathname, int flags, int mode)
{
   return original_open(pathname, flags, mode);
}

asmlinkage int hook_close(int fd)
{
   return original_close(fd);
}

asmlinkage off_t hook_lseek(int fd, off_t offset, int whence)
{
   return original_lseek(fd, offset, whence);
}

asmlinkage ssize_t hook_read(int fd, void *buf, size_t count)
{
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
    printk(KERN_INFO "diob_lkm up and running. syscall @ %p, __NR_open is %x\n", SYS_CALL_TABLE, __NR_open);
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
    printk(KERN_INFO "Successfully set up I/O hooks.\n");
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
    printk(KERN_INFO "Successfully removed I/O hooks.\n");
}

module_init(diob_init);
module_exit(diob_cleanup);
