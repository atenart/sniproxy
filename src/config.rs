use std::{
    cmp, fmt, fs,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
};

use anyhow::{anyhow, bail, Result};
use ipnet::IpNet;
use regex::RegexSet;
use serde::{de, Deserialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("hostname not found")]
    HostnameNotFound,
    #[error("no backend")]
    NoBackend,
    #[error("access denied")]
    AccessDenied,
}

/// Main (internal) configuration.
#[derive(Debug, Deserialize)]
pub(crate) struct Config {
    /// TCP address & port to bind to for the TLS SNI proxy. Defaults to
    /// `[::]:443`.
    #[serde(default = "default_bind_https")]
    pub(crate) bind_https: SocketAddr,
    /// TCP address & port to bind to for the HTTP to HTTPS redirection.
    /// Defaults to `[::]:80`.
    #[serde(default = "default_bind_http")]
    pub(crate) bind_http: SocketAddr,
    /// List of routes.
    routes: Vec<Route>,
}

impl Config {
    /// Parses a file in YAML formatted str and converts it to a `Config`
    /// representation.
    pub(crate) fn from_str(input: &str) -> Result<Config> {
        let config: Self = serde_yaml::from_str(input)?;

        // Sanity check the configuration:
        for (i, route) in config.routes.iter().enumerate() {
            // Routes must have at least one of the backend types.
            if route.backend.is_none() && route.alpn_challenge_backend.is_none() {
                bail!("Route {i} has neither a backend nor an alpn_challenge_backend");
            }

            let check_address = |address: &str| {
                // First check if the address is a valid ip:port one.
                if address.parse::<SocketAddr>().is_ok() {
                    return Ok(());
                }

                // If not, it should be an hostname:port one. Split once
                // starting from the left to catch invalid definitions (port
                // validation will fail if more than a single ':' is used).
                match address.split_once(':') {
                    Some((addr, port)) => {
                        if addr.is_empty() {
                            bail!("{address} requires an address/hostname part");
                        }

                        // Backend addresses must have an explicit & valid port.
                        if let Err(e) = port.parse::<u16>() {
                            bail!("{address} has an invalid port ({e})")
                        }
                    }
                    None => bail!("No port found in {address}"),
                }
                Ok(())
            };
            if let Some(backend) = &route.backend {
                check_address(&backend.address)?;
            }
            if let Some(backend) = &route.alpn_challenge_backend {
                check_address(&backend.address)?;
            }
        }

        Ok(config)
    }

    /// Parses a file in YAML file and converts it to a `Config` representation.
    pub(crate) fn from_file(path: PathBuf) -> Result<Config> {
        Self::from_str(&fs::read_to_string(&path).map_err(|e| {
            anyhow!(
                "Could not read configuration file '{}': {e}",
                path.display()
            )
        })?)
    }

    /// Returns a reference to a route matching the input domain, if any.
    pub(crate) fn get_route(&self, domain: &str) -> Option<&Route> {
        self.routes.iter().find(|r| r.domains.is_match(domain))
    }

    /// Returns a reference to a backend matching the input domain, if any.
    pub(crate) fn get_backend(
        &self,
        hostname: &str,
        peer: &SocketAddr,
        is_challenge: bool,
    ) -> Result<&Backend> {
        // Get the corresponding route.
        let route = match self.get_route(hostname) {
            Some(route) => route,
            None => bail!(Error::HostnameNotFound),
        };

        // Check ACLs (or opt-in bypass for ALPN challenges).
        if !is_challenge || !route.alpn_challenge_bypass_acl {
            // Check ACLs.
            if !route.is_allowed(peer) {
                bail!(Error::AccessDenied);
            }
        }

        // Get the right backend.
        let backend = match is_challenge {
            false => route.backend.as_ref(),
            true => route
                .alpn_challenge_backend
                .as_ref()
                .or(route.backend.as_ref()),
        }
        .ok_or_else(|| anyhow!(Error::NoBackend))?;

        Ok(backend)
    }

    /// Do we need an HTTP server.
    pub(crate) fn need_http(&self) -> bool {
        self.routes.iter().any(|r| r.http_redirect)
    }
}

/// Represents a single route between an SNI and a backend.
#[derive(Debug, Deserialize)]
pub(crate) struct Route {
    /// List of valid domains for this route (regexp).
    #[serde(deserialize_with = "deserialize_regex")]
    domains: RegexSet,
    /// Backend to proxy the connection to when the route is used.
    pub(crate) backend: Option<Backend>,
    /// Backend to use if the request is an ALPN challenge.
    pub(crate) alpn_challenge_backend: Option<Backend>,
    /// Bypass ACLs for ALPN challenges, if an ALPN challenge backend is used.
    #[serde(default)]
    pub(crate) alpn_challenge_bypass_acl: bool,
    /// Allow and deny ACLs, containing a list of IP ranges to allow or deny for
    /// this route. If 'allow' is used, all non-matching addresses are denied.
    /// A 'deny' rule wins over an 'allow' one and the most specific subnet
    /// takes precedence.
    ///
    /// Denied IP ranges. If a request matches, it'll be denied.
    ///
    /// For how allowed ranges compare to denied ones, see `allowed_ranges`.
    #[serde(default)]
    denied_ranges: Vec<IpNet>,
    /// Allowed IP ranges. When not used, non-denied requests will pass through,
    /// otherwise when at least one IP range is in the allowed ranges, all
    /// non-matching requests are denied.
    ///
    /// If an IP matches both a denied and an allowed IP range, the most
    /// specific range wins. Otherwise, the denied range wins over the allowed
    /// one.
    #[serde(default)]
    allowed_ranges: Vec<IpNet>,
    /// Redirect HTTP requests comming to `bind_http` and `bind_https` to their
    /// HTTPS counterparts (using the request Host header).
    #[serde(default = "default_true")]
    pub(crate) http_redirect: bool,
}

impl Route {
    /// Checks if a client IP address is allowed by the route ACLs.
    pub(crate) fn is_allowed(&self, addr: &SocketAddr) -> bool {
        if self.denied_ranges.is_empty() && self.allowed_ranges.is_empty() {
            return true;
        }

        // Get the client IP address, v4 or v6.
        let client_ip = addr.ip();

        // Look for the minimum CIDR allowing our request, or None if not found.
        let mut cidr = None;
        self.allowed_ranges.iter().for_each(|r| {
            if Self::contains(r, &client_ip) {
                cidr = match cidr {
                    Some(cidr) => Some(cmp::max(cidr, r.prefix_len())),
                    None => Some(r.prefix_len()),
                };
            }
        });

        // If we didn't match an allowed range, while having no denied ranges
        // defined; deny the request.
        if cidr.is_none() && !self.allowed_ranges.is_empty() && self.denied_ranges.is_empty() {
            return false;
        }

        // Looks for denied range matches with a CIDR <= of what we found in the
        // allowed ranges (or 0 if no allowed range was defined).
        let cidr = cidr.unwrap_or(0);
        for r in self.denied_ranges.iter() {
            if Self::contains(r, &client_ip) && r.prefix_len() >= cidr {
                return false;
            }
        }

        true
    }

    /// Check if a subnet contains an IP address, including IPv4-mapped IPv6
    /// addresses in IPv4 subnets.
    fn contains(net: &IpNet, ip: &IpAddr) -> bool {
        if let (IpNet::V4(v4net), IpAddr::V6(v6)) = (net, ip) {
            if let Some(ref v4) = v6.to_ipv4_mapped() {
                return v4net.contains(v4);
            }
        }

        net.contains(ip)
    }
}

/// Represents a backend (host and its specific options).
#[derive(Debug, Deserialize)]
pub(crate) struct Backend {
    /// Backend address in the <addr>:<port> form; <addr> can be either an IP
    /// address or an hostname.
    pub(crate) address: String,
    /// HAProxy PROXY protocol. Disable: None, v1: Some(1), v2: Some(2).
    pub(crate) proxy_protocol: Option<u8>,
}

impl Backend {
    pub(crate) fn to_socket_addr(&self) -> Result<SocketAddr> {
        self.address
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("Could not convert {} to an IP:port pair", self.address))
    }
}

/// Deserialize a set of custom regex expressions from a sequence of strings to
/// a `RegexSet`.
fn deserialize_regex<'a, D>(deserializer: D) -> Result<RegexSet, D::Error>
where
    D: de::Deserializer<'a>,
{
    struct RegexVisitor;

    impl<'a> de::Visitor<'a> for RegexVisitor {
        type Value = RegexSet;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string containing a regex")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: de::SeqAccess<'a>,
        {
            let mut patterns = Vec::new();

            while let Some(val) = seq.next_element::<&str>()? {
                // The following has to be done in the right order!
                let val = val.replace('.', r"\.");
                let val = val.replace('*', ".*");

                patterns.push(format!("^{val}$"));
            }

            RegexSet::new(&patterns).map_err(de::Error::custom)
        }
    }

    deserializer.deserialize_seq(RegexVisitor)
}

// Default values.
fn default_bind_https() -> SocketAddr {
    "[::]:443".parse().unwrap()
}
fn default_bind_http() -> SocketAddr {
    "[::]:80".parse().unwrap()
}
fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_configs() {
        // At least one route should be defined.
        assert!(Config::from_str("").is_err());

        // Config with a backend but no domain.
        assert!(Config::from_str(
            "
routes:
  - backend:
      address: 127.0.0.1:443
        "
        )
        .is_err());

        // Configs with a malformed backend.
        assert!(Config::from_str(
            "
routes:
  - domains:
      - example.net
    backend:
      address: 127.0.0.1
        "
        )
        .is_err());
        assert!(Config::from_str(
            "
routes:
  - domains:
      - example.net
    backend:
      address: :443
        "
        )
        .is_err());
        assert!(Config::from_str(
            "
routes:
  - domains:
      - example.net
    backend:
      address: foobar
        "
        )
        .is_err());
        assert!(Config::from_str(
            "
routes:
  - domains:
      - example.net
    backend:
      address: foo:bar:443
        "
        )
        .is_err());

        // Config with a route but not backend.
        assert!(Config::from_str(
            "
routes:
  - domains:
      - example.net
        "
        )
        .is_err());
    }

    #[test]
    fn simple_config() {
        let cfg = Config::from_str(
            "
routes:
  - domains:
      - example.net
    backend:
      address: 127.0.0.1:443
        ",
        )
        .unwrap();
        assert_eq!(cfg.bind_https, "[::]:443".parse().unwrap());
        assert_eq!(cfg.bind_http, "[::]:80".parse().unwrap());
        assert_eq!(cfg.need_http(), true);

        // Invalid routes.
        assert!(cfg.get_route("").is_none());
        assert!(cfg.get_route("foo.example.net").is_none());
        assert!(cfg.get_route(".*example.*").is_none());

        // The one valid route.
        let route = cfg.get_route("example.net").unwrap();

        assert_eq!(route.backend.as_ref().unwrap().address, "127.0.0.1:443");
        assert!(route.backend.as_ref().unwrap().proxy_protocol.is_none());

        assert!(route.alpn_challenge_backend.is_none());
        assert_eq!(route.alpn_challenge_bypass_acl, false);

        assert_eq!(route.is_allowed(&"10.0.42.1:12345".parse().unwrap()), true);
        assert_eq!(route.is_allowed(&"[1111::1]:12345".parse().unwrap()), true);

        // Config with an IPv6 backend.
        assert!(Config::from_str(
            "
routes:
  - domains:
      - example.net
    backend:
      address: \"[::1]:443\"
        ",
        )
        .is_ok());

        // Config with an alpn challenge backend only.
        assert!(Config::from_str(
            "
routes:
  - domains:
      - example.net
    alpn_challenge_backend:
      address: 127.0.0.1:443
        ",
        )
        .is_ok());

        // Config with an hostname as a backend.
        assert!(Config::from_str(
            "
routes:
  - domains:
      - example.net
    alpn_challenge_backend:
      address: foo.example.net:443
        ",
        )
        .is_ok());
    }

    #[test]
    fn full_config() {
        let cfg = Config::from_str(
            "
bind_https: \"[2222::42]:8433\"
bind_http: 127.0.0.1:8080
routes:
  - domains:
      - example.net
    backend:
      address: 127.0.0.1:443
      proxy_protocol: 2
    alpn_challenge_bypass_acl: true
    alpn_challenge_backend:
      address: 10.0.42.1:443
      proxy_protocol: 1
    denied_ranges:
      - 10.0.10.0/24
      - 10.0.1.1/32
      - 10.0.2.42/32
    allowed_ranges:
      - 10.0.10.128/29
      - 10.0.2.42/32
  - domains:
      - \"*.foo.example.com\"
      - foo.example.net
    http_redirect: false
    backend:
      address: \"[1234::42:1]:10443\"
    allowed_ranges:
      - 10.0.42.0/27
        ",
        )
        .unwrap();
        assert_eq!(cfg.bind_https, "[2222::42]:8433".parse().unwrap());
        assert_eq!(cfg.bind_http, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(cfg.need_http(), true);

        // Invalid routes.
        assert!(cfg.get_route("").is_none());
        assert!(cfg.get_route("foo.example.com").is_none());
        assert!(cfg.get_route("extrafoo.example.com").is_none());
        assert!(cfg.get_route("extrafoo.example.net").is_none());

        // Test first route.
        let route = cfg.get_route("example.net").unwrap();
        assert_eq!(route.backend.as_ref().unwrap().address, "127.0.0.1:443");
        assert_eq!(route.backend.as_ref().unwrap().proxy_protocol, Some(2));

        let alpn_backend = route.alpn_challenge_backend.as_ref().unwrap();
        assert_eq!(alpn_backend.address, "10.0.42.1:443");
        assert_eq!(alpn_backend.proxy_protocol, Some(1));
        assert_eq!(route.alpn_challenge_bypass_acl, true);

        // First route ACLs.
        assert_eq!(
            route.is_allowed(&"10.0.10.127:12345".parse().unwrap()),
            false
        );
        assert_eq!(route.is_allowed(&"10.0.1.1:10001".parse().unwrap()), false);
        assert_eq!(route.is_allowed(&"10.0.1.2:10001".parse().unwrap()), true);
        assert_eq!(
            route.is_allowed(&"[::ffff:10.0.1.1]:10001".parse().unwrap()),
            false
        );
        assert_eq!(
            route.is_allowed(&"[::ffff:10.0.1.2]:10001".parse().unwrap()),
            true
        );
        assert_eq!(
            route.is_allowed(&"10.0.10.132:12345".parse().unwrap()),
            true
        );
        assert_eq!(route.is_allowed(&"172.16.99.1:1337".parse().unwrap()), true);
        assert_eq!(
            route.is_allowed(&"[4242::1:2:3:4:5:6]:11337".parse().unwrap()),
            true
        );

        // Check deny wins over allow.
        assert_eq!(route.is_allowed(&"10.0.2.42:1337".parse().unwrap()), false);

        // We get the same route for the following matches.
        let tmp1 = cfg.get_route("0.foo.example.com").unwrap() as *const Route;
        let tmp2 = cfg.get_route("subdomain.foo.example.com").unwrap() as *const Route;
        let tmp3 = cfg.get_route("foo.example.net").unwrap() as *const Route;
        assert!(tmp1 == tmp2 && tmp2 == tmp3);

        // Test the second route.
        let route = cfg.get_route("a.b.c.d.foo.example.com").unwrap();
        assert_eq!(
            route.backend.as_ref().unwrap().address,
            "[1234::42:1]:10443"
        );
        assert!(route.backend.as_ref().unwrap().proxy_protocol.is_none());
        assert_eq!(route.http_redirect, false);
        assert!(route.alpn_challenge_backend.is_none());
        assert_eq!(route.alpn_challenge_bypass_acl, false);

        // Second route ACLs.
        assert_eq!(
            route.is_allowed(&"10.0.10.127:12345".parse().unwrap()),
            false
        );
        assert_eq!(
            route.is_allowed(&"[1111::42:128]:8001".parse().unwrap()),
            false
        );
        assert_eq!(route.is_allowed(&"10.0.42.0:10001".parse().unwrap()), true);
        assert_eq!(route.is_allowed(&"10.0.42.31:10001".parse().unwrap()), true);
        assert_eq!(
            route.is_allowed(&"10.0.42.32:10001".parse().unwrap()),
            false
        );
    }

    #[test]
    fn multiple_matches() {
        let cfg = Config::from_str(
            "
routes:
  - domains:
      - first.example.net
    backend:
      address: 127.0.0.1:443
  - domains:
      - \"*.example.net\"
    backend:
      address: 127.0.0.2:443
        ",
        )
        .unwrap();

        let route = cfg.get_route("first.example.net").unwrap();
        assert_eq!(route.backend.as_ref().unwrap().address, "127.0.0.1:443");

        let route = cfg.get_route("other.example.net").unwrap();
        assert_eq!(route.backend.as_ref().unwrap().address, "127.0.0.2:443");
    }
}
