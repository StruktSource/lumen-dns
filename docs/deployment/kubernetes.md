# Kubernetes and Helm

Raw manifests ([`deploy/kubernetes`](../../deploy/kubernetes)) and a Helm chart ([`deploy/helm/lumen`](../../deploy/helm/lumen)) run the same container image and DNS core as every other platform.

> [!NOTE]
> Status: experimental. The raw manifests have passed a hosted Kind UDP and TCP smoke test, and raw and Helm installs passed locally. Dual-stack is unverified. See the [compatibility matrix](compatibility.md).

## Install

```sh
kubectl apply -k deploy/kubernetes
# or
helm upgrade --install lumen deploy/helm/lumen --namespace lumen --create-namespace
```

## What you get

- An internal `ClusterIP` Service publishing UDP and TCP 53.
- A pod running as UID 65532 with a read-only root filesystem, dropped capabilities, resource limits, a seccomp profile, a 30-second termination grace period, and **no service-account token mounted**.
- **One replica** in managed mode with a small PVC (the chart's `persistence.*` values) for accounts and settings. SQLite must not be shared by multiple pods, and high-availability state replication is future work.

## Configure it

1. **Edit the config ACL** for your real pod and client networks.
2. **Review the NetworkPolicy.** The default accepts DNS only from the same namespace and permits resolver egress on DNS and encrypted-DNS ports. It lists both Service port 53 and pod target port 5353 so CNIs that enforce before or after Service translation behave the same. Check it against your cluster's CNI.
3. **Encrypted DNS (optional).** Mount an existing TLS Secret through `tls.existingSecret`. The config must name files under `/etc/lumen/tls`.
4. **Dual-stack (optional).** Set Helm `service.ipFamilyPolicy` and `service.ipFamilies`. This is unverified.

## Open the web console

```sh
kubectl port-forward deploy/lumen 8080:8080
kubectl logs deploy/lumen      # shows the setup code
```

Then browse to <http://127.0.0.1:8080>. Setup asks for the code from the logs.

## Important cautions

- **Probes are not proof.** The TCP probes show the listener accepts connections. The Kind CI smoke test separately sends deterministic UDP and TCP queries for the locally blocked `health.lumen.invalid` name. Neither proves public recursion works.
- **Client IPs.** SNAT, Services, and proxies can hide the original client IP. Per-device policy is valid only after you have proved source-IP preservation for your Service and CNI.
- **No LoadBalancer yet.** Do not use an external LoadBalancer until ACLs, source IP, UDP and TCP routing, and open-resolver exposure have been tested.

## Related

- [Serve your network](../guides/serve-your-network.md)
- [Docker and Compose](docker.md)
