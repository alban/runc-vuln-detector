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
  // https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv
  CVE_2024_21626 = 0,
};

struct event {
  gadget_timestamp timestamp;
  struct gadget_process proc;
  enum cve_t cve_raw;
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

  /* runc:[2:INIT] */
  if (comm[0] != 'r' || comm[1] != 'u' || comm[2] != 'n' || comm[3] != 'c' ||
      comm[4] != ':' || comm[5] != '[' || comm[6] != '2' || comm[7] != ':' ||
      comm[8] != 'I' || comm[9] != 'N' || comm[10] != 'I' || comm[11] != 'T' ||
      comm[12] != ']' || comm[13] != '\0')
    return 0;

  return 1;
}

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
  event->timestamp = bpf_ktime_get_boot_ns();
  bpf_probe_read_user_str(&event->details, sizeof(event->details),
                          (void *)ctx->args[0]);

  /* emit event */
  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  if (kill)
    bpf_send_signal(SIGKILL);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
