# Performance profile

Measured on 2026-11-03 on a 2019 Intel MacBook (i7-9750H), with every container sharing Docker Desktop and the load generator on the same machine. These figures are from one laptop, so re-measure on real hardware before quoting any of them to a bank.

## The finding

Earlier runs reported that throughput stayed flat from 1 to 10 clients, and put that down to queueing in the product. **That was wrong: the flat line came mostly from the test client.** On Node 26, the global `fetch` opens a single HTTP/2 connection to a host and sends one request at a time over it.

The same install at 10 clients, changing only the client:

| Client | Tokenize, batch of 10 | Detokenize, batch of 10 |
| --- | --- | --- |
| Node 26 global `fetch` | 61 batches/s, p95 227 ms | 153 batches/s, p95 73 ms |
| Node 26, undici over HTTP/1.1 | 278 batches/s, p95 55 ms | 554 batches/s, p95 25 ms |
| Node 26, undici over HTTP/2, 100 streams | 297 batches/s, p95 49 ms | 537 batches/s, p95 26 ms |
| Node 24 global `fetch`, in Docker through a relay | 259 batches/s, p95 66 ms | 391 batches/s, p95 40 ms |
| Go SDK | 324 batches/s, p95 44 ms | 717 batches/s, p95 20 ms |

These are single runs, so small differences between rows mean little. With Node 26's `fetch`, Node's CPU was about 83% idle, which is what ruled out CPU as the limit. Node 22 gave mixed results in one run and was not looked at further.

**Customers are affected.** The Node SDK uses the global `fetch` by default, so a single Node 26 process is held to about 150 detokenize batches/s whatever its concurrency. Until the SDK changes, pass an undici-based client through the SDK's `fetch` option.

## Results through the full install

`RV_E2E_LOAD=1 scripts/e2e.sh`, with its load step on undici over HTTP/1.1, then `scripts/loadgen` with the Go SDK. Two fresh installs gave almost the same numbers.

| Measure | Spec target | Node p95 | Go p95 | Throughput | Result |
| --- | --- | --- | --- | --- | --- |
| Tokenize, batch of 10, one client | under 30 ms | 18, 19 ms | 20 ms | about 70 batches/s | Met |
| Detokenize, batch of 10, one client | under 30 ms | 7, 8 ms | 8 ms | about 160 batches/s | Met |
| Tokenize, batch of 10, 10 concurrent | under 30 ms | 43, 43 ms | 37 ms | 300 to 335 batches/s | **Not met**, close |
| Detokenize, batch of 10, 10 concurrent | under 30 ms | 29, 33 ms | 22 ms | 525 to 620 batches/s | Borderline |
| Log processor, through the edge | 20,000 lines/s per 2 cores | n/a | n/a | about 29,000 lines/s | **Unproven**: not limited to 2 cores |

The spec's latency target assumes a client in Lagos and a real server, and neither was tested.

## What limits tokenize now

Throughput does keep rising with clients: the Go SDK reached 471 tokenize and 810 to 1,008 detokenize batches/s at 40 clients. The vault's handler on its own, with no edge or TLS in front, went from 41 to 229 tokenize and 130 to 910 detokenize requests/s between 1 and 40 clients.

- **Tokenize is about 2.5 times slower than detokenize** at one client. Its transaction issues at least two statements per value, one by one, so a batch of 10 makes over 20 database round trips.
- **CPU profiles** of the handler show most samples in network system calls and thread wake-ups, not in crypto or detection. That test's database was behind Docker's port forward, which inflates network time, so treat the split as a rough guide.
- **Disk sync is not the limit:** `pg_test_fsync` measured 0.3 to 0.7 ms.

Not established: how much each round trip costs in a real deployment, and how much of the gap to 30 ms sending these statements as one pipelined batch would close. That change is the obvious next step for tokenize.

Group commit has not been evaluated. The earlier conclusion that it showed no clear gain came from runs capped by the client, so it should be disregarded.

## Reproducing

```
RV_LOAD_PROFILE=/some/dir scripts/test-integration.sh -run TestLoadProfile   # handler only, with pprof output
RV_E2E_LOAD=1 scripts/e2e.sh                                                 # full install; also writes deploy/compose/e2e-load.env
cd scripts/loadgen && go run . -cfg ../../deploy/compose/e2e-load.env        # Go client
```
