# Real client address (`HugConf.spec.realIP`)

Behind a CDN or proxy (for example Cloudflare), the TCP peer seen by HAProxy is the proxy, not the visitor.
`spec.realIP` of the `HugConf` makes the **HTTP and HTTPS** frontends take the visitor address from a request
header, but only when the TCP peer is a trusted proxy. TCP and TLS passthrough frontends are not affected
(no header is visible there). Nothing is added to the `Defaults` section.

```yaml
spec:
  realIP:
    header: CF-Connecting-IP
    trustedPeersFile: /usr/local/hug/aux/cloudflare-ips.lst   # or trustedCIDRs: [...]
    mode: set-src                                              # or logOnly
```

| Field              | Description                                                                                         |
|--------------------|-----------------------------------------------------------------------------------------------------|
| `header`           | Request header holding the client address.                                                          |
| `trustedPeersFile` | Absolute path of a file with one CIDR per line (IPv4 and IPv6). Exactly one of file or CIDRs.       |
| `trustedCIDRs`     | Inline list of trusted peer CIDRs.                                                                  |
| `mode`             | `set-src` (default): rewrites the source address (`%ci`, ACLs and stick tables see it). `logOnly`: stores it in `txn.realip`, reference `%[var(txn.realip)]` in your log format. |

Generated configuration (placed before all other `http-request` rules of the frontend):

```
acl hug_trusted_peer src -f /usr/local/hug/aux/cloudflare-ips.lst
acl hug_realip_header_found req.hdr(CF-Connecting-IP) -m found
http-request set-src req.hdr(CF-Connecting-IP) if hug_trusted_peer hug_realip_header_found
```

## Things to know

- Both conditions are required: without the trusted-peer test any visitor could spoof its address.
  An invalid `realIP` spec is ignored (logged as an error) and the client address is left untouched.
- The list file is only read when HAProxy starts or reloads. A change of its content needs a reload
  (or a pod restart). A stale list silently disables the rewrite.
- The file must exist **before** the `HugConf` change: an unreadable file makes the configuration check fail.
- Changing `realIP` regenerates every HTTP/HTTPS frontend, so expect one reload.
- Frontends have no `option forwardfor` of their own: check `X-Forwarded-For` separately.

Example: [hugconf.yaml](../../example/customresource/realip/hugconf.yaml).
