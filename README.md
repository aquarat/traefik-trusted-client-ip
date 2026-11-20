# Trusted Client IP (Traefik plugin)

A small [Traefik](https://traefik.io) middleware that sets the client IP from a header written by an upstream you trust (by default Cloudflare's `CF-Connecting-IP`). It only does this when the request really arrives from that upstream, and it removes forwarding headers the client sent itself.

## The problem it solves

Cloudflare (and most CDNs) **append** the visitor's address to whatever `X-Forwarded-For` the visitor sent. A visitor who sends `X-Forwarded-For: 203.0.113.77` reaches your origin with:

```
X-Forwarded-For: 203.0.113.77, <real visitor IP>
```

Traefik's `forwardedHeaders.trustedIPs` can only trust or distrust a peer's `X-Forwarded-For` **as a whole**. If you trust your CDN or tunnel connector, the spoofed entry is passed through. Many applications take the **leftmost** entry as the client (Synapse, Vaultwarden's `IP_HEADER`, and plenty of others). They then log, rate-limit and lock out the address the visitor chose.

Cloudflare already tells you the real address in `CF-Connecting-IP`, which visitors cannot set. This plugin uses that header and nothing else.

## What it does

For every request:

- **The TCP peer is in `trustedCIDRs`** (your cloudflared connector, or Cloudflare's edge ranges):
  - If `sourceHeader` holds exactly one valid IP:
    - `X-Forwarded-For` and `X-Real-Ip` are set to that IP alone.
    - `Forwarded` is removed.
    - With `rewriteRemoteAddr` (the default), the request's remote address becomes that IP as well. Router-level middlewares that look at the remote address, such as `ipAllowList`, then see the real visitor, and so does Traefik's own `X-Forwarded-For` append.
  - If the header is missing or invalid (a list, a port, a zone, garbage), the forwarding headers are removed so backends fall back to the peer address. Set `onMissing: reject` to answer 400 instead.
- **Any other peer:** `sourceHeader`, `X-Forwarded-For`, `X-Real-Ip` and `Forwarded` are removed (`stripUntrusted`, default on). A client that reaches Traefik directly, for example on the LAN, cannot pretend to be someone else.

IPv4-mapped IPv6 addresses (`::ffff:198.51.100.9`) are normalised to IPv4.

Because Traefik appends the remote address after middlewares run, a backend normally receives `X-Forwarded-For: <ip>, <ip>`: the same real address twice. That is correct whether the backend reads the leftmost or the rightmost entry.

## Configuration

| Option | Default | Meaning |
|---|---|---|
| `trustedCIDRs` | none | Peers whose `sourceHeader` is believed. A bare IP means /32 or /128. With none set, the plugin only strips headers. |
| `sourceHeader` | `CF-Connecting-IP` | Header holding the client IP. For example `True-Client-IP` (Akamai, or Cloudflare Enterprise) or `Fastly-Client-IP`. |
| `rewriteRemoteAddr` | `true` | Also set the request's remote address to the client IP. |
| `stripUntrusted` | `true` | Remove forwarding headers from untrusted peers. |
| `onMissing` | `strip` | A trusted peer sent no valid IP: `strip` the forwarding headers, or `reject` with 400. |

### Static configuration

From the plugin catalogue:

```yaml
experimental:
  plugins:
    trustedclientip:
      moduleName: github.com/aquarat/traefik-trusted-client-ip
      version: v0.1.0
```

Or as a local plugin, with no download at startup: put the source at `./plugins-local/src/github.com/aquarat/traefik-trusted-client-ip/`, relative to Traefik's working directory (`/plugins-local/...` in the official image).

```yaml
experimental:
  localPlugins:
    trustedclientip:
      moduleName: github.com/aquarat/traefik-trusted-client-ip
```

### Dynamic configuration

```yaml
http:
  middlewares:
    client-ip:
      plugin:
        trustedclientip:
          trustedCIDRs:
            - 172.19.0.1/32   # e.g. the address cloudflared connects from
```

Apply it to a whole entry point so every router gets it, including new ones:

```yaml
entryPoints:
  websecure:
    address: ":443"
    http:
      middlewares:
        - client-ip@file
```

If Cloudflare connects to Traefik directly rather than through a tunnel, list Cloudflare's published ranges (<https://www.cloudflare.com/ips/>) in `trustedCIDRs`, and keep them up to date.

## Caveats

- **If the plugin fails to load, Traefik drops every router that uses the middleware.** With an entry-point middleware that means everything on that entry point. Try it on one router first, and re-test after Traefik upgrades.
- Traefik's access log takes its client host before entry-point middlewares run, so it can still show a spoofed `X-Forwarded-For`. Backends get the corrected headers.
- This plugin trusts the TCP peer address Traefik sees. Anything that can connect from a trusted address (for example another container behind the same Docker gateway) can set `sourceHeader`, so keep `trustedCIDRs` as narrow as possible.

## Development

```sh
go test -race ./...
# Traefik runs plugins in the yaegi interpreter; test there too:
go run github.com/traefik/yaegi/cmd/yaegi@v0.16.1 test -v .   # inside a GOPATH layout, see CI
```

The Go package is named `traefik_trusted_client_ip` because Traefik derives the package name from the last element of the module path, replacing `-` with `_`.

## Licence

MIT, see [LICENSE](LICENSE).
