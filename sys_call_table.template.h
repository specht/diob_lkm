/*
 * ATTENTION: In order for this to work, we need the address of the system call table.
 *
 * Find out with:
 * grep " sys_call_table" /boot/System.map-`uname -r`
 * and set SYS_CALL_TABLE accordingly.
 *
 * ...then save this file as sys_call_table.h
 */
void ** SYS_CALL_TABLE = (void **)0x0000000000000000;
