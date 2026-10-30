# Kubernetes and Helm

The raw manifests in `deploy/kubernetes` and chart in `deploy/helm/lumen` use the
same OCI image and Rust DNS core. The default Service is internal `ClusterIP` and
publishes UDP/TCP 53. The pod runs as UID 65532 with a read-only root filesystem,
dropped capabilities, limits, a seccomp profile, and a 30-second termination
grace period.

```sh
kubectl apply -k deploy/kubernetes
# or
helm upgrade --install lumen deploy/helm/lumen --namespace lumen --create-namespace
```

Edit the config ACL for the real pod and client networks. The default NetworkPolicy
accepts DNS only from the same namespace and permits resolver egress on DNS and
encrypted-DNS ports. Review it for the cluster CNI. Encrypted listeners can mount
an existing TLS Secret through `tls.existingSecret`; the config must name files
under `/etc/lumen/tls`.

The TCP probes prove that the listener accepts connections. The Kind CI smoke
test separately sends deterministic UDP and TCP DNS queries for the locally
blocked `health.lumen.invalid` name. Neither test proves public recursion. The
current service has no disk state, so no PVC is required.

Kubernetes SNAT, Services, and proxies can hide the original client IP. Per-device
policy is valid only when packet source IP preservation has been proved for the
chosen Service and CNI. Do not use an external LoadBalancer until ACLs, source IP,
UDP/TCP routing, and open-resolver exposure have been tested. Dual-stack can be
set with Helm `service.ipFamilyPolicy` and `service.ipFamilies`; it remains unverified.
