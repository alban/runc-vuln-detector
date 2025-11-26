// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024-2025 The Inspektor Gadget authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/common.h>
#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

enum cve_t {
  // several container breakouts due to internally leaked fds
  // https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv
  CVE_2024_21626 = 0,

  // container escape and denial of service due to arbitrary write gadgets and
  // procfs write redirects
  // https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm
  CVE_2025_52881 = 1,
};

enum illegal_reason_t {
  REASON_LEGAL = 0,
  REASON_PROCFS_PATH_MISMATCH = 1,
  REASON_NOT_DEV_NULL = 2,
};

#define TMPFS_MAGIC 0x01021994
#define PROC_SUPER_MAGIC 0x9fa0

#define MS_BIND 4096
#define MS_REMOUNT 32

// Macros from
// https://github.com/torvalds/linux/blob/v6.12/include/linux/kdev_t.h#L7-L12
// XXX: It only works with kdev_t, not dev_t (used in user space)!
#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)
#define MAJOR(dev) ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev) ((unsigned int)((dev)&MINORMASK))
#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

#define S_IFMT 00170000
#define S_IFCHR 0020000
#define S_IFDIR 0040000
#define S_ISCHR(m) (((m)&S_IFMT) == S_IFCHR)
#define S_ISDIR(m) (((m)&S_IFMT) == S_IFDIR)

#define BIND_MOUNT 0x1000

struct mount_ctx_t {
  const char *src;
  const char *dest;
  const char *fs;
  unsigned long mountflags;

  long unsigned int source_magic, target_magic;
  void *source_dentry, *target_dentry;
  dev_t source_rdev;
  umode_t source_mode, destination_mode;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64); // pid_tgid
  __type(value, struct mount_ctx_t);
} mount_ctx SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);
  __type(value, void *);
} kern_path_ctx SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);
  __type(value, void *);
} user_path_at_ctx SEC(".maps");

struct event {
  gadget_timestamp timestamp_raw;
  struct gadget_process proc;
  enum cve_t cve_raw;
  enum illegal_reason_t reason_raw;
  char details[128];
};

#ifndef SIGKILL
#define SIGKILL 9
#endif

const volatile bool kill = false;
GADGET_PARAM(kill);

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(runcwatcher, events, event);

static __always_inline int is_runc() {
  char comm[TASK_COMM_LEN];

  bpf_get_current_comm(&comm, sizeof(comm));

  /* fakemount */
  if (comm[0] == 'f' && comm[1] == 'a' && comm[2] == 'k' && comm[3] == 'e' &&
      comm[4] == 'm' && comm[5] == 'o' && comm[6] == 'u' && comm[7] == 'n' &&
      comm[8] == 't' && comm[9] == '\0')
    return 1;

  /* runc:[2:INIT] */
  if (comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'n' && comm[3] == 'c' &&
      comm[4] == ':' && comm[5] == '[' && comm[6] == '2' && comm[7] == ':' &&
      comm[8] == 'I' && comm[9] == 'N' && comm[10] == 'I' && comm[11] == 'T' &&
      comm[12] == ']' && comm[13] == '\0')
    return 1;

  return 0;
}

//
// CVE_2024_21626
//

SEC("tracepoint/syscalls/sys_enter_chdir")
int tracepoint__sys_enter_chdir(struct trace_event_raw_sys_enter *ctx) {
  struct event *event;

  if (!is_runc())
    return 0;

  char pattern[15] = "/proc/self/fd/";
  char path[15];
  int ret;

  ret = bpf_probe_read_user_str(path, sizeof(path), (void *)ctx->args[0]);
  if (ret <= 0)
    return 0;

  if (pattern[0] != path[0] || pattern[1] != path[1] || pattern[2] != path[2] ||
      pattern[3] != path[3] || pattern[4] != path[4] || pattern[5] != path[5] ||
      pattern[6] != path[6] || pattern[7] != path[7] || pattern[8] != path[8] ||
      pattern[9] != path[9] || pattern[10] != path[10] ||
      pattern[11] != path[11] || pattern[12] != path[12] ||
      pattern[13] != path[13])
    return 0;

  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  /* event data */
  gadget_process_populate(&event->proc);
  event->cve_raw = CVE_2024_21626;
  event->timestamp_raw = bpf_ktime_get_boot_ns();
  bpf_probe_read_user_str(&event->details, sizeof(event->details),
                          (void *)ctx->args[0]);

  /* emit event */
  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  if (kill)
    bpf_send_signal(SIGKILL);

  return 0;
}

//
// Other CVEs
//

SEC("tracepoint/syscalls/sys_enter_mount")
int ig_mount_e(struct syscall_trace_enter *ctx) {
  struct mount_ctx_t mctx = {};
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  if (!is_runc())
    return 0;

  mctx.src = (const char *)ctx->args[0];
  mctx.dest = (const char *)ctx->args[1];
  mctx.fs = (const char *)ctx->args[2];
  mctx.mountflags = ctx->args[3];

  bpf_map_update_elem(&mount_ctx, &pid_tgid, &mctx, BPF_ANY);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_mount")
int ig_mount_x(struct syscall_trace_exit *ctx) {
  if (!is_runc())
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct mount_ctx_t *mctx = bpf_map_lookup_elem(&mount_ctx, &pid_tgid);
  if (!mctx)
    return 0;

  bpf_map_delete_elem(&mount_ctx, &pid_tgid);

  enum illegal_reason_t reason = REASON_LEGAL;

  int is_initial_bind_mount =
      (mctx->mountflags & MS_BIND) && !(mctx->mountflags & MS_REMOUNT);

  if (is_initial_bind_mount) {
    if (mctx->source_magic == PROC_SUPER_MAGIC &&
        mctx->target_magic == PROC_SUPER_MAGIC &&
        (mctx->source_dentry != mctx->target_dentry)) {
      reason = REASON_PROCFS_PATH_MISMATCH;
    }

    int is_dev_null = S_ISCHR(mctx->source_mode) &&
                      MAJOR(mctx->source_rdev) == 1 &&
                      MINOR(mctx->source_rdev) == 3;

    if (mctx->source_magic != PROC_SUPER_MAGIC &&
        mctx->target_magic == PROC_SUPER_MAGIC && !is_dev_null) {
      reason = REASON_NOT_DEV_NULL;
    }
  }

  if (reason != REASON_LEGAL) {
    struct event *event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
      return 0;

    gadget_process_populate(&event->proc);
    event->timestamp_raw = bpf_ktime_get_boot_ns();
    event->cve_raw = CVE_2025_52881;
    event->reason_raw = reason;

    bpf_probe_read_user_str(event->details, sizeof(event->details), mctx->src);

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    if (kill)
      bpf_send_signal(SIGKILL);
  }

  return 0;
}

SEC("kprobe/user_path_at_empty")
int BPF_KPROBE(user_path_at_e, int dfd, char *name, unsigned flags,
               struct path *path) {
  if (!is_runc())
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct mount_ctx_t *mctx = bpf_map_lookup_elem(&mount_ctx, &pid_tgid);
  if (mctx == NULL)
    return 0;

  bpf_map_update_elem(&user_path_at_ctx, &pid_tgid, &path, BPF_ANY);

  return 0;
}

SEC("kretprobe/user_path_at_empty")
int BPF_KPROBE(ig_user_path_at_x, long ret) {
  if (!is_runc())
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct path **path = bpf_map_lookup_elem(&user_path_at_ctx, &pid_tgid);
  if (path == NULL)
    return 0;

  /* Cleanup user_path_at_ctx.*/
  bpf_map_delete_elem(&user_path_at_ctx, &pid_tgid);

  struct mount_ctx_t *mctx = bpf_map_lookup_elem(&mount_ctx, &pid_tgid);
  if (mctx == NULL)
    return 0;

  umode_t i_mode = BPF_CORE_READ(*path, dentry, d_inode, i_mode);
  mctx->destination_mode = i_mode;

  mctx->target_dentry = BPF_CORE_READ(*path, dentry);
  mctx->target_magic = BPF_CORE_READ(*path, dentry, d_inode, i_sb, s_magic);

  return 0;
}

SEC("kprobe/kern_path")
int BPF_KPROBE(ig_kern_path_e, const char *name, unsigned int flags,
               struct path *path) {
  if (!is_runc())
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct mount_ctx_t *mctx = bpf_map_lookup_elem(&mount_ctx, &pid_tgid);
  if (mctx == NULL)
    return 0;

  /* Let's save path, we will use it on the kretprobe once it is filled by this
   * function Note we use struct path**, as we can't store a direct reference to
   * kernel memory here. But using &path we get the pointer to a pointer, that
   * lives in our code, and can get the struct path* on the kretprobe.
   */
  bpf_map_update_elem(&kern_path_ctx, &pid_tgid, &path, BPF_ANY);
  return 0;
}

SEC("kretprobe/kern_path")
int BPF_KPROBE(ig_kern_path_x, long ret) {
  if (!is_runc())
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct path **path = bpf_map_lookup_elem(&kern_path_ctx, &pid_tgid);
  if (path == NULL)
    return 0;

  /* Cleanup kern_path_ctx */
  bpf_map_delete_elem(&kern_path_ctx, &pid_tgid);

  struct mount_ctx_t *mctx = bpf_map_lookup_elem(&mount_ctx, &pid_tgid);
  if (mctx == NULL)
    return 0;

  dev_t rdev = BPF_CORE_READ(*path, dentry, d_inode, i_rdev);
  mctx->source_rdev = rdev;
  umode_t i_mode = BPF_CORE_READ(*path, dentry, d_inode, i_mode);
  mctx->source_mode = i_mode;

  mctx->source_dentry = BPF_CORE_READ(*path, dentry);
  mctx->source_magic = BPF_CORE_READ(*path, dentry, d_inode, i_sb, s_magic);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
