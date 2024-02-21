[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/runc-vuln-gadget)](https://artifacthub.io/packages/search?repo=runc-vuln-gadget)

# runc-vuln-gadget

This gadget detects when the following runc vulnerability is exploited and blocks its usage.

[CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv)

## How to use

Thanks to CVE-2024-21626, a container workload can access the host filesystem:

```bash
$ docker run -ti --rm --workdir=/proc/self/fd/9 ubuntu grep ^ID= ../../../etc/os-release
ID=fedora
```

runc-vuln-gadget is able to detect and block CVE-2024-21626:

```bash
$ IG_EXPERIMENTAL=true sudo -E ig run ghcr.io/alban/runc-vuln-gadget:latest
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME MNTNS_ID   PID    COMM          PATH
                      4026533066 409484 runc:[2:INIT] /proc/self/fd/9

```

```
$ docker run -ti --rm --workdir=/proc/self/fd/9 ubuntu grep ^ID= ../../../etc/os-release
docker: Error response from daemon: cannot start a stopped process: unknown.
```

## Limitations

This gadget is for demonstration only and not designed for real-world security.
Malicious software can easily bypass its detection capabilities.
