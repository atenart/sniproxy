# SNIProxy

_SNIProxy_ is a TLS proxy which, based on the
[TLS SNI](https://en.wikipedia.org/wiki/Server_Name_Indication) contained in TLS
handshakes, routes TCP connections to backends. The proxy does not need the TLS
encryption keys and can not decrypt the TLS traffic.

_SNIProxy_ is meant to be simple to use and configure, with sane defaults and
few parameters.

## Docker image

```shell
$ docker run --name sniproxy -p 443:443/tcp \
	-v $(pwd)/sniproxy.conf:/sniproxy.conf \
	atenart/sniproxy:latest -conf sniproxy.conf
```

_SNIProxy_ can be bound to a custom address or port using the `-bind` command
line option.

```shell
$ docker run --name sniproxy -p 443:443/tcp \
	-v $(pwd)/sniproxy.conf:/sniproxy.conf \
	atenart/sniproxy:latest -bind 192.168.0.1:8080 -conf sniproxy.conf
```

## Configuration file

The configuration is made of a list of blocks. Each block represents a route. A
route is defined by a list of hostnames, a backend to route the connection to
and optional parameters. Empty blocks (`{}`) can be omitted.

```
hostname0, hostname1, … {
	backend <IP/hostname>:port {
		optional-parameter
	}
	parameter0
	parameter1 arg0, arg1, …
	…
}
```

A route can be as simple as:

```
example.net {
	backend 1.2.3.4:8080
}
```

Hostnames can contain regexp:

```
# Matches example.net and all its subdomains.
example.net, *.example.net {
	backend localhost:1234
}
```

### Optional parameters

[HAProxy's PROXY protocol](https://www.haproxy.org/download/2.0/doc/proxy-protocol.txt)
v1 and v2 are supported.

```
example.net {
	backend 1.2.3.4:443 {
		# Send a PROXY header using the PROXY protocol v1.
		send-proxy
	}
}

blog.example.net {
	backend 1.2.3.5:443 {
		# Send a PROXY header using the PROXY protocol v2.
		send-proxy-v2
	}
}
```

_SNIProxy_ also has the ability to block or allow connections based on the
client IP address. Single IPs or subnets (using a CIDR range) are supported.

```
# Deny a single client. All other connections will be routed to the backend.
example.net {
	backend 1.2.3.4:443
	deny 10.0.0.42
}

# Lists can be used as well, either using commas (,) or using multiple
# statements.
example.net {
	backend 1.2.3.4:443
	deny 10.0.0.42, 10.0.0.43, 10.0.0.44
	deny 10.0.0.45
}

# When at least one IP is allowed, all IPs are denied automatically (0.0.0.0/0
# and ::/0).
example.net {
	backend 1.2.3.4:443
	# 192.168.0.42 is allowed, all other IPs are denied.
	allow 192.168.0.42
}

# Example with ranges.
example.net {
	backend 1.2.3.4:443
	deny 192.168.0.0/24
}

# The most specific range wins (if the range is the same, deny wins).
example.net {
	backend 1.2.3.4:443
	# Deny 192.168.0.0/22 except for 192.168.0.2 and 192.168.1.8/29.
	deny 192.168.0.0/22
	allow 192.168.1.8/29, 192.168.0.2
}
```

_SNIProxy_ can use a different dedicated backend for ACME TLS.

```
example.net {
	backend 1.2.3.4:443
	acme 1.2.3.5:443
}
```
