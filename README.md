[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/runc-vuln-detector)](https://artifacthub.io/packages/search?repo=runc-vuln-detector)

# runc-vuln-detector

This gadget detects when the following runc vulnerabilities are exploited and blocks the attacks.

- ✅ [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv)
- ✅ [CVE-2025-31133](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2): container escape via "masked path" abuse due to mount race conditions
- 🛠️ [CVE-2025-52881](https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm): container escape and denial of service due to arbitrary write gadgets and procfs write redirects
- ❌ [CVE-2025-52565](https://github.com/opencontainers/runc/security/advisories/GHSA-qw9x-cqr3-wc7r): container escape with malicious config due to /dev/console mount and related races

## Usage

### Basic usage

In normal conditions, the kernel keyrings is not available from a container:

```bash
$ docker run -ti --rm busybox cat /proc/keys | wc -l
0
```

Thanks to CVE-2025-31133, a container workload can access the kernel keyrings /proc/keys.

```bash
$ docker run (hidden-arguments)
# here is printed the content of /proc/keys on the host
```

This can be detected by the gadget:

```bash
$ sudo -E ig run ghcr.io/alban/runc-vuln-detector:latest --verify-image=false --fields=comm,cve,details,reason
WARN[0000] gadget signature verification is disabled due to using corresponding option
WARN[0002] gadget signature verification is disabled due to using corresponding option
COMM             CVE               DETAILS     REASON
runc             CVE_2025_52881    /dev/null   REASON_PROCFS_PATH_MISMATCH
runc             CVE_2025_52881    /dev/null   REASON_PROCFS_PATH_MISMATCH
runc             CVE_2025_52881    /dev/null   REASON_PROCFS_PATH_MISMATCH
runc             CVE_2025_52881    /dev/null   REASON_PROCFS_PATH_MISMATCH
runc             CVE_2025_52881    /dev/null   REASON_PROCFS_PATH_MISMATCH
runc             CVE_2025_52881    /dev/null   REASON_PROCFS_PATH_MISMATCH
runc             CVE_2025_52881    /dev/null   REASON_PROCFS_PATH_MISMATCH
```

Alternatively, this can be blocked by the gadget with the `--kill` parameter:

```bash
$ sudo -E ig run ghcr.io/alban/runc-vuln-detector:latest --verify-image=false --fields=comm,cve,details,reason --kill
WARN[0000] gadget signature verification is disabled due to using corresponding option
WARN[0002] gadget signature verification is disabled due to using corresponding option
COMM             CVE               DETAILS     REASON
runc:[2:INIT]    CVE_2025_52881    /dev/null   REASON_PROCFS_PATH_MISMATCH
```

The container is stopped in this way:

```bash
$ docker run (hidden-arguments)
docker: Error response from daemon: failed to create task for container: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: %!w(<nil>): unknown.
```

### On Kubernetes

TODO

### Prometheus metrics

TODO

## Limitations

This gadget is for demonstration only and has not been properly reviewed for use in production.
It is possible that malicious software could bypass its detection capabilities.
