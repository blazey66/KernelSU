#ifndef __KSU_H_KSU_KP
#define __KSU_H_KSU_KP

// ksud.c
extern void kp_stop_vfs_read_hook();
extern void kp_stop_execve_hook();
extern void kp_stop_input_hook();
extern void ksud_kprobes_init();
extern void ksud_kprobes_exits();

// sucompat.c
extern void kp_sucompat_init();
extern void kp_sucompat_exit();

#endif
