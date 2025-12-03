[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/runc-vuln-detector)](https://artifacthub.io/packages/search?repo=runc-vuln-detector)

# runc-vuln-detector

This gadget aims to detect and mitigate runc vulnerabilities. Support for different CVEs is as follows:

- ✅ [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv): several container breakouts due to internally leaked fds
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

### On Kubernetes without installing Inspektor Gadget

For testing on a single node without installing Inspektor Gadget:

```bash
$ kubectl debug --profile=sysadmin node/minikube -ti \
        --image=ghcr.io/inspektor-gadget/ig:latest -- \
        ig run ghcr.io/alban/runc-vuln-detector:latest \
        --verify-image=false --fields=comm,cve,details,reason
COMM             CVE                               DETAILS                           REASON
runc             CVE_2025_52881                    /dev/null                         REASON_PROCFS_PATH_MISMATCH
runc             CVE_2025_52881                    /dev/null                         REASON_PROCFS_PATH_MISMATCH
runc             CVE_2025_52881                    /dev/null                         REASON_PROCFS_PATH_MISMATCH
runc             CVE_2025_52881                    /dev/null                         REASON_PROCFS_PATH_MISMATCH
runc             CVE_2025_52881                    /dev/null                         REASON_PROCFS_PATH_MISMATCH
runc             CVE_2025_52881                    /dev/null                         REASON_PROCFS_PATH_MISMATCH
```

The problematic workload was started with:

```bash
$ kubectl apply -f pod.yaml # hidden content
```

Alternatively, this can be blocked by the gadget with the `--kill` parameter:

```bash
$ kubectl debug --profile=sysadmin node/minikube -ti \
        --image=ghcr.io/inspektor-gadget/ig:latest -- \
        ig run ghcr.io/alban/runc-vuln-detector:latest \
        --verify-image=false --fields=comm,cve,details,reason \
        --kill
COMM             CVE                               DETAILS                           REASON
runc:[2:INIT]    CVE_2025_52881                    /dev/null                         REASON_PROCFS_PATH_MISMATCH
```

The container is stopped in this way:
```bash
$ kubectl describe pod test-pod
...
Events:
  Type     Reason     Age                From               Message
  ----     ------     ----               ----               -------
  Normal   Scheduled  15s                default-scheduler  Successfully assigned default/test-pod to minikube
  Normal   Pulled     13s                kubelet            Successfully pulled image "busybox" in 1.187747515s (1.187753075s including waiting)
  Normal   Pulling    12s (x2 over 14s)  kubelet            Pulling image "busybox"
  Normal   Created    11s (x2 over 13s)  kubelet            Created container busybox
  Warning  Failed     11s (x2 over 13s)  kubelet            Error: failed to start container "busybox": Error response from daemon: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: %!w(<nil>): unknown
```

### On Kubernetes after installing Inspektor Gadget

After [installing Inspektor Gadget on Kubernetes](https://inspektor-gadget.io/docs/latest/reference/install-kubernetes) using `kubectl gadget deploy --verify-image=false --otel-metrics-listen=true`, you can start the gadget with the following command:

```bash
$ kubectl gadget run \
        ghcr.io/alban/runc-vuln-detector:latest \
        --fields=comm,cve,details,reason
COMM             CVE                               DETAILS                           REASON
runc:[2:INIT]    CVE_2025_52881                    /dev/null                         REASON_PROCFS_PATH_MISMATCH
runc:[2:INIT]    CVE_2025_52881                    /dev/null                         REASON_PROCFS_PATH_MISMATCH
runc:[2:INIT]    CVE_2025_52881                    /dev/null                         REASON_PROCFS_PATH_MISMATCH
runc:[2:INIT]    CVE_2025_52881                    /dev/null                         REASON_PROCFS_PATH_MISMATCH
runc:[2:INIT]    CVE_2025_52881                    /dev/null                         REASON_PROCFS_PATH_MISMATCH
runc:[2:INIT]    CVE_2025_52881                    /dev/null                         REASON_PROCFS_PATH_MISMATCH
```

This is running the gadget in the interactive mode and this will only be deployed on the current nodes. Nodes created afterwards (e.g. with the Cluster Autoscaler) won't be monitored.

Alternatively, the gadget could be deployed in a non-interactive mode with a manifest file. In this case, the gadget will be deployed on all nodes, including those created afterwards by the Cluster Autoscaler.

```bash
$ cat > manifest.yaml <<EOF
apiVersion: 1
kind: instance-spec
image: ghcr.io/alban/runc-vuln-detector:latest
name: runc-vuln-detector
paramValues:
  operator.oci.ebpf.kill: "true"
  operator.cli.fields: comm,cve,details,reason
EOF
$ kubectl gadget run --detach -f manifest.yaml
INFO[0000] installed as "fb20bc58666709934a61dffa3ad8a388"
$ kubectl gadget list
ID           NAME                       TAGS                       GADGET                    STATUS
fb20bc586667 runc-vuln-detector                                    ghcr.io/alban/runc-vuln-… Running
```

### Prometheus metrics

We will use a different manifest:

```bash
$ cat > manifest.yaml <<EOF
apiVersion: 1
kind: instance-spec
image: ghcr.io/alban/runc-vuln-detector:latest
name: runc-vuln-detector
paramValues:
  operator.oci.ebpf.kill: "true"
  operator.otel-metrics.otel-metrics-name: runcwatcher:runcwatcher
EOF
$ kubectl gadget run --detach -f manifest.yaml
```

```bash
$ POD_NAME=$(kubectl get pods -n gadget -o jsonpath="{.items[0].metadata.name}")
$ kubectl -n gadget port-forward $POD_NAME 2224:2224 &
$ curl http://localhost:2224/metrics -s | grep ^runcwatcher
runcwatcher_total{cve="CVE_2025_52881",otel_scope_name="runcwatcher",otel_scope_schema_url="",otel_scope_version="",reason="REASON_PROCFS_PATH_MISMATCH"} 2
```

## Limitations

This gadget is for demonstration only and has not been properly reviewed for use in production.
It is possible that malicious software could bypass its detection capabilities.
