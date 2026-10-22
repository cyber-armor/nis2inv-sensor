# nis2inv-sensor

The network sensor of the NIS2 inventory platform. It runs on a small Linux host (VM or appliance) inside a network
segment, discovers what is connected (ARP, DHCP, LLDP / CDP, SNMP, mDNS / SSDP / WS-Discovery, gentle IT port probes;
passive only on OT segments) and reports to the platform over HTTPS. It publishes no ports.

This repository holds the release pipeline and this page. The image is built from the product's source and signed.

## Install

In the platform's Console: **Settings → Sensors → Add a sensor** (with the installer). Copy the command it shows and
run it on the sensor host (Ubuntu / Debian, a user who may use sudo). The command downloads the installer from the
platform, checks its SHA-256 and its OpenSSH signature, then runs it; the installer exchanges a one-time code for the
sensor's token.

Installer signing key (compare before the first install on a site):

```
installer@cyber-armor  ED25519  SHA256:u4LuitTdduvbYoZHugrGo+ABg3LQaFlgI4CgmwaXhSU
```

## Image

`ghcr.io/cyber-armor/nis2inv-sensor:<version>` — linux/amd64 and linux/arm64, with an SBOM and a provenance
attestation. Every release is signed keyless with [cosign](https://github.com/sigstore/cosign); check it with:

```bash
cosign verify ghcr.io/cyber-armor/nis2inv-sensor:<version> \
  --certificate-identity https://github.com/cyber-armor/nis2inv-sensor/.github/workflows/release.yml@refs/tags/sensor-v<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Host requirements

- Outbound TCP 443 to the platform and to `ghcr.io` / `pkg-containers.githubusercontent.com` (or the offline bundle).
- Host network, capability `NET_RAW` only, read-only root filesystem.
- With a host firewall, allow the unicast replies to discovery queries on the scan interface:
  `ufw allow in on <scan NIC> proto udp from <segment> to any port 32768:60999`.
