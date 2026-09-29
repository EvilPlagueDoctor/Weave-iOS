# Weave Groups v2 — Phase 5 Production Hardening

Version: `0.9.0-groups-v2-phase5-production-hardening` (versionCode 24)

This phase keeps the Phase 1–4 protocol model intact and hardens the implementation for long-running, higher-volume and adversarial use. It deliberately treats overload/rate limiting as an availability concern, not as proof of maliciousness.

## 1. Abuse guard

A new in-memory `GroupAbuseGuardV2` performs cheap sliding-window admission before expensive signature, DHT or private-witness processing. Limits reset on app restart and never create reputation penalties or daemon bans.

Ten-minute limits:

| Action | Per peer | Per peer/group |
|---|---:|---:|
| Authenticated canonical events | 600 | 300 |
| Open service requests | 180 | 180 |
| Public witness canonical events | 180 | 120 |
| Custody store requests | 180 | 90 |
| Custody receipts | 240 | 120 |
| Recovery requests | 90 | 30 |
| Recovery batches | 120 | 60 |

The guard keeps at most 2,048 active buckets, prunes stale buckets, and logarithmically suppresses repeated rate-limit logging. Drops log `ABUSE_RATE_LIMIT ... reputation_penalty=false`.

## 2. Structural validation before expensive work

`SignedGroupEventV2` now rejects unreasonable structures before signature verification/DHT reads, including oversized IDs/keys, excessive target branches, invalid hashes/signatures, invalid subkeys/schema versions, excessive lifetime and unreasonable future timestamps.

Key bounds:
- target branches: 32
- IDs: 192 UTF-8 bytes
- DHT keys: 384 UTF-8 bytes
- payload subkey: 0..4095
- schema version: 1..1024
- event lifetime: at most 8 days
- future clock skew: at most 10 minutes
- compact canonical event bytes: at most 2 KiB on witness/custody wire paths
- transport/custody packet: at most 8 KiB

## 3. Custody admission hardening

Custody no longer evicts existing valid custody records merely to admit arbitrary new traffic. New records are refused at quota instead.

Quotas:
- 100 events per author/group
- 1,000 events per group
- 5,000 total custody events
- 24 receipts per event
- 5,000 total receipts
- 2,048 recovery replay records
- 512 recovery cursors
- 10,000 branch-decision records

Transient replay/cursor/terminal-decision bookkeeping is expiry/oldest-pruned. A refused custody record is not a rejection of the post and is not negative reputation evidence.

## 4. Bounded asynchronous custody work

Custody/recovery uses three workers with a bounded queue of 96 jobs. Queue saturation rejects excess work rather than permitting unbounded memory growth. This logs `CUSTODY_WORK_REJECT ... reputation_penalty=false`.

## 5. Recovery hardening

Recovery remains receipt-first, but background work is substantially bounded:
- 6 custody targets per event
- 4 recovery custodians per group
- 6 groups per sweep
- 24 recovery requests per sweep
- 64 outstanding recovery requests
- sweep interval: 10 minutes
- max 8 pages from one custodian in one chain
- max 96 recovered events from one custodian in one chain
- cursor max 160 bytes
- stale outbound request bookkeeping expires after 30 minutes

Repeated cursors terminate the chain (`RECOVERY_PAGINATION_STOP reason=cursor-loop`). Page/event ceilings terminate an oversized chain (`reason=session-cap`).

Recovery requests and batches also enforce signed timestamp/window bounds. Locally quarantined custodians are not used for recovery.

## 6. Public witness CPU hardening

Authenticated service-request senders pass a rate gate before Weave attempts compact witness decoding or iterates member-only private intake keys. This prevents an arbitrary requester from cheaply forcing repeated AES-GCM attempts across all private groups.

## 7. Event-store bounds

The encrypted canonical event vault is bounded:
- 4,000 total events
- 1,200 per group
- 300 per author/group
- 8 conflicting bodies retained per Event ID
- 16 evidence source IDs per transport

Expired/low-value/non-pending records are preferred for eviction. Pending valid moderation work is preserved preferentially.

## 8. Local workflow/state bounds

Additional local limits prevent UI/workflow structures from growing forever:
- 2,000 pending items
- 2,000 moderation tasks
- 256 cached post details
- 512 authority-presence entries
- 512 authority-continuity watches

Presence entries age out after 30 days and continuity watches after 90 days.

## 9. Production cleanup

The old Phase-1 manual event import/copy/re-ingest/conflict-test controls and controller methods have been removed. They were useful protocol test surfaces but are not appropriate in the production UI.

`DebugImport` remains in the persisted enum for backward readability of older diagnostic EventStore records; no production UI can create new DebugImport events.

Temporary Phase-3 custody-only test instrumentation is not present.

## 10. Reputation invariant

Phase 5 does not change the Phase-4 trust rule:

**Overload, offline status, route failure, timeout, cache eviction, quota refusal or failure to serve custody are not proof of dishonesty and do not reduce reputation.**

Strong negative reputation remains limited to authenticated/provable contradictions such as invalid signed custody evidence or cryptographically attributable equivocation.
