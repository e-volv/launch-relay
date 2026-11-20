# e-volv Launch relay

A small proxy you run next to your apps. It holds an up-to-date copy of your e-volv Launch flag configuration, serves it to SDKs on your network, and keeps serving the last snapshot from disk if it loses contact with e-volv.

## Run

```bash
docker run -p 8080:8080 \
  -e EVOLVE_RELAY_KEYS=production=evk_srv_... \
  -e EVOLVE_RELAY_CLIENT_KEYS=production=evk_pub_... \
  -v evolve-relay:/var/lib/evolve-relay \
  ghcr.io/e-volv/launch-relay:0.1.0
```

| Variable                   | Meaning                                                                                     |
| -------------------------- | ------------------------------------------------------------------------------------------- |
| `EVOLVE_RELAY_KEYS`        | Each environment and its server key, comma separated: `production=evk_srv_...` (required)    |
| `EVOLVE_RELAY_CLIENT_KEYS` | Client keys the relay accepts per environment: `production=evk_pub_a\|evk_pub_b`             |
| `EVOLVE_RELAY_DATA_DIR`    | Where snapshots are written; defaults to `/var/lib/evolve-relay` in the image               |
| `EVOLVE_RELAY_UPSTREAM`    | e-volv API origin; defaults to `https://api.e-volv.io`                                      |

A client key that is not listed exactly is refused with 401. Point your SDKs' base URL at the relay.

Docs: https://e-volv.io/docs/flags/relay
