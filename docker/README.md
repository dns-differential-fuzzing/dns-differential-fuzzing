# How to use the Containers?

Building containers:

```shell
podman build -t dnscap -f Dockerfile.dnscap .
podman build -t tcpdump -f Dockerfile.tcpdump .
```

Examples:

Print all DNS messages to/from the fuzzing AuthNS with dnscap.

```shell
podman run -it --privileged=true --rm --name tcpdump dnscap -i any -g -z 127.250.0.1
# -
podman run --rm -it -v /tmp/config:/config:rw,Z --net=container:tcpdump --name bind9 bind9
```
