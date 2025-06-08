#include <linux/kprobes.h>
#include <linux/workqueue.h>
#include <linux/uaccess.h>

#include "kernel_compat.h"
#include "arch.h"
#include "klog.h"

// define workqueue
static struct work_struct stop_vfs_read_work;
static struct work_struct stop_execve_hook_work;
static struct work_struct stop_input_hook_work;

// define pre for kprobe

static int sys_execve_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	const char __user **filename_user =
		(const char **)&PT_REGS_PARM1(real_regs);
	const char __user *const __user *__argv =
		(const char __user *const __user *)PT_REGS_PARM2(real_regs);
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct filename filename_in, *filename_p;
	char path[32];

	if (!filename_user)
		return 0;

	memset(path, 0, sizeof(path));
	ksu_strncpy_from_user_nofault(path, *filename_user, 32);
	filename_in.name = path;

	filename_p = &filename_in;
	return ksu_handle_execveat_ksud(AT_FDCWD, &filename_p, &argv, NULL,
					NULL);
}

static int sys_read_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	unsigned int fd = PT_REGS_PARM1(real_regs);
	char __user **buf_ptr = (char __user **)&PT_REGS_PARM2(real_regs);
	size_t count_ptr = (size_t *)&PT_REGS_PARM3(real_regs);

	return ksu_handle_sys_read(fd, buf_ptr, count_ptr);
}

static int input_handle_event_handler_pre(struct kprobe *p,
					  struct pt_regs *regs)
{
	unsigned int *type = (unsigned int *)&PT_REGS_PARM2(regs);
	unsigned int *code = (unsigned int *)&PT_REGS_PARM3(regs);
	int *value = (int *)&PT_REGS_CCALL_PARM4(regs);
	return ksu_handle_input_handle_event(type, code, value);
}

static struct kprobe execve_kp = {
	.symbol_name = SYS_EXECVE_SYMBOL,
	.pre_handler = sys_execve_handler_pre,
};

static struct kprobe vfs_read_kp = {
	.symbol_name = SYS_READ_SYMBOL,
	.pre_handler = sys_read_handler_pre,
};

static struct kprobe input_event_kp = {
	.symbol_name = "input_event",
	.pre_handler = input_handle_event_handler_pre,
};

// for workqueue
static void do_stop_vfs_read_hook(struct work_struct *work)
{
	unregister_kprobe(&vfs_read_kp);
}

static void do_stop_execve_hook(struct work_struct *work)
{
	unregister_kprobe(&execve_kp);
}

static void do_stop_input_hook(struct work_struct *work)
{
	unregister_kprobe(&input_event_kp);
}

// for stop the hooks
void kp_stop_vfs_read_hook()
{
	bool ret = schedule_work(&stop_vfs_read_work);
	pr_info("unregister vfs_read kprobe: %d!\n", ret);
}

void kp_stop_execve_hook()
{
	bool ret = schedule_work(&stop_execve_hook_work);
	pr_info("unregister execve kprobe: %d!\n", ret);
}

void kp_stop_input_hook()
{
	static bool input_hook_stopped = false;
	if (input_hook_stopped) {
		return;
	}
	input_hook_stopped = true;
	bool ret = schedule_work(&stop_input_hook_work);
	pr_info("unregister input kprobe: %d!\n", ret);
}

// init workqueue
void ksud_kprobes_init()
{
	int ret;

	ret = register_kprobe(&execve_kp);
	pr_info("ksud: execve_kp: %d\n", ret);

	ret = register_kprobe(&vfs_read_kp);
	pr_info("ksud: vfs_read_kp: %d\n", ret);

	ret = register_kprobe(&input_event_kp);
	pr_info("ksud: input_event_kp: %d\n", ret);

	INIT_WORK(&stop_vfs_read_work, do_stop_vfs_read_hook);
	INIT_WORK(&stop_execve_hook_work, do_stop_execve_hook);
	INIT_WORK(&stop_input_hook_work, do_stop_input_hook);
}

// exit
void ksud_kprobes_exit()
{
	unregister_kprobe(&execve_kp);
	// this should be done before unregister vfs_read_kp
	// unregister_kprobe(&vfs_read_kp);
	unregister_kprobe(&input_event_kp);
}
