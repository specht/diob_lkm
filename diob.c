/*
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

void **sys_call_table;

asmlinkage int (*original_call) (const char*, int, int);

asmlinkage int our_sys_open(const char* file, int flags, int mode)
{
   printk("A file was opened\n");
   return original_call(file, flags, mode);
}

static void disable_page_protection(void) {

    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (value & 0x00010000) {
            value &= ~0x00010000;
            asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

static void enable_page_protection(void) {

    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (!(value & 0x00010000)) {
            value |= 0x00010000;
            asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

static int __init hello_init(void)
{
    sys_call_table = (unsigned long*)0xffffffff80296f40;
    printk(KERN_INFO "Hello world! We're up and running. syscall @ %p, __NR_open is %x\n", sys_call_table, __NR_open);
    original_call = sys_call_table[__NR_open];
    disable_page_protection();
    sys_call_table[__NR_open] = our_sys_open;
    enable_page_protection();
    printk(KERN_INFO "Successfully set new __NR_open.\n");
    return 0;	// Non-zero return means that the module couldn't be loaded.
}

static void __exit hello_cleanup(void)
{
    printk(KERN_INFO "Cleaning up module.\n");
    disable_page_protection();
    sys_call_table[__NR_open] = original_call;
    enable_page_protection();
    printk(KERN_INFO "Successfully re-set old __NR_open.\n");
}

module_init(hello_init);
module_exit(hello_cleanup);
