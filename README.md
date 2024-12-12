# SNIProxy

_SNIProxy_ is a TLS proxy, based on the TLS
[Server Name Indication (SNI)](https://en.wikipedia.org/wiki/Server_Name_Indication).
The SNI is contained in TLS handshakes and _SNIProxy_ uses it to route
connections to backends. _SNIProxy_ does not need the TLS encryption keys and
cannot decrypt the TLS traffic that goes through.

_SNIProxy_ is meant to be simple to use and configure, with sane defaults and
few parameters.

A first version was written in [Go](https://go.dev) and can be found in the
[archive/go](https://github.com/atenart/sniproxy/tree/archive/go) branch. It was
latter rewritten in [Rust](https://www.rust-lang.org).

## Container image

```shell
$ podman run --name sniproxy -p 80:80/tcp -p 443:443/tcp \
     -v $(pwd)/sniproxy.yaml:/sniproxy.yaml:ro \
     ghcr.io/atenart/sniproxy:latest
```

The above works with Docker too, just replace `podman` with `docker`.

_SNIProxy_ handles HTTP connections and redirects those to their HTTPS
counterparts. If this is not needed, the above `-p 80:80/tcp` can be omitted.

## Parameters

The log level can be controlled using the `--log-level` CLI parameter. By
default `INFO` and above levels are reported. The configuration file can be
selected by the `--config` CLI parameter, and defaults to `sniproxy.yaml`.

See `sniproxy --help` for a list of available parameters.

## Configuration file

_SNIProxy_'s configuration file is written in the
[YAML](https://en.wikipedia.org/wiki/YAML) format.

```text
---
bind_https: <address:port to bind to for HTTPS requests (default: "[::]:443)">
bind_http: <address:port to bind to for HTTP requests (default: "[::]:80)">
routes:
  - domains:
      - <domain to match in the SNI>
      - <domain to match in the SNI>
    backend:
      address: <address:port of the backend; address can be a resolvable hostname>
      proxy_protocol: <optional; HAProxy protocol version (1 or 2)>
    alpn_challenge_backend:
      address: <optional; address:port for the ALPN challenge backend>
      proxy_protocol: <optional; HAProxy protocol version (1 or 2)>
    alpn_challenge_bypass_acl: <optional; boolean>
    denied_ranges:
      - <optional; ip/cidr range to block>
      - <optional; ip/cidr range to block>
    allowed_ranges:
      - <optional; ip/cidr range to allow>
  - domains:
    ...
```

A configuration for a single route can be as simple as:

```yaml
---
routes:
  - domains:
      - "example.net"
    backend:
      address: "1.2.3.4:443"
```

Domain names can be a regular expression:

```yaml
---
routes:
  - domains:
      # Matches example.net and all its subdomains.
      - "example.net"
      - "*.example.net"
    backend:
      address: "1.2.3.4:443"
```

### Optional parameters

_SNIProxy_ has a built-in ACL logic and can block and allow connections based on
the client IP address. When at least one range is explicitly allowed, all other
ranges are automatically denied (0.0.0.0/0 & ::/0). When an address can be found
in two ranges, the most specific wins. If the exact same range is both allowed
and denied, the deny rule wins.

```yaml
---
routes:
  - domains:
      - "example.net"
    backend:
      address: "1.2.3.4:8080"
    denied_ranges:
      - "10.0.0.42/32"
  - domains:
      - "foo.example.com"
    backend:
      address: "5.6.7.8:443"
    denied_ranges:
      - "10.0.0.42/32"
      - "10.0.0.43/32"
      - "192.168.0.0/24"
    allowed_ranges:
      - "192.168.0.42/32"
```

_SNIProxy_ can use a different backend for ALPN requests:

```yaml
---
routes:
  - domains:
      - "example.net"
    backend:
      address: "[1111::1]:8080"
    alpn_challenge_backend:
      address: "alpn-backend:8080"
```

The ACL rules can be bypassed for ALPN challenge requests:

```yaml
---
routes:
  - domains:
      - "example.net"
    backend:
      address: "[1111::1]:8080"
    alpn_challenge_backend:
      address: "alpn-backend:8080"
    alpn_challenge_bypass_acl: true
    allowed_ranges:
      - "192.168.0.0/24"
```

[HAProxy PROXY protocol](https://www.haproxy.org/download/2.0/doc/proxy-protocol.txt)
v1 and v2 are supported for backend connections:

```yaml
---
routes:
  - domains:
      - "example.net"
    backend:
      address: "[1111::1]:8080"
      proxy_protocol: 2
    alpn_challenge_backend:
      address: "alpn-backend:8080"
      proxy_protocol: 1
```
