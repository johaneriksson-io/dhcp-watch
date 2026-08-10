---
date: 2026-08-09
topic: live-hosts-web-page
---

# Live Hosts Web Page

## Summary

Add a LAN-only web page served by dhcp-watch that shows currently detected hosts (identity + last-seen), updates live as DHCP events arrive, ages hosts out after a quiet period, and seeds the roster from the existing log when the process starts so the list is not empty after a restart.

---

## Problem Frame

dhcp-watch already detects hosts from DHCP traffic and surfaces them via console output, `/tmp/dhcp_watch.log`, and optional Telegram alerts. There is no at-a-glance view of who has been seen lately. Checking the console or log is awkward for a quick “who’s on the network right now?” glance, especially when the watcher runs on a Pi on the LAN.

---

## Actors

- A1. Operator: Person on the home LAN who opens the page to see recently detected hosts.
- A2. dhcp-watch process: Captures DHCP, maintains the host roster, serves the page, and pushes updates.

---

## Key Flows

- F1. View live roster
  - **Trigger:** Operator opens the page on the LAN while dhcp-watch is running.
  - **Actors:** A1, A2
  - **Steps:** Page loads current roster; connection stays open for live updates; host rows appear/update as DHCP events arrive; hosts disappear after the quiet period with no further activity.
  - **Outcome:** Operator sees a current list of recently detected hosts without refreshing.
  - **Covered by:** R1, R2, R3, R4, R5

- F2. Recover roster after restart
  - **Trigger:** dhcp-watch starts (or restarts) after prior detections were logged.
  - **Actors:** A2
  - **Steps:** Process reads recent log entries; hosts still within the quiet period relative to their last logged sighting are seeded into the live roster; page (when opened) shows that seeded state and then continues with live updates.
  - **Outcome:** The live list is not empty solely because of a restart, when the log has recent enough entries.
  - **Covered by:** R6, R7

---

## Requirements

**Page and access**
- R1. dhcp-watch serves a web page reachable from other devices on the LAN (not public internet; no authentication required for v1).
- R2. The page shows a single live host list. Each row includes host identity (hostname, IP, and/or MAC as available from detection) and last-seen time.

**Liveness**
- R3. When the page is open, new or updated detections appear without a manual refresh (push / live stream).
- R4. When a host is seen again within the quiet period, its last-seen time updates and it remains on the list.
- R5. When a host has no DHCP activity for the quiet period, it is removed from the live list.

**Log fallback**
- R6. On process start, seed the live roster from the existing dhcp-watch log using entries that are still within the quiet period.
- R7. The log is a data source for seeding only — there is no separate history browser, search, or archive UI in v1.

**Operational defaults**
- R8. Quiet period defaults to 10 minutes (aligned with the existing debounce window), and may be made configurable later without changing the product shape.

---

## Acceptance Examples

- AE1. **Covers R2, R3, R4.** Given the page is open and host `phone` is already listed, when a new DHCP event for the same MAC arrives, the row’s last-seen updates in place without a page reload.
- AE2. **Covers R5.** Given host `laptop` was last seen 10+ minutes ago (quiet period elapsed) and no further DHCP activity, when the operator views the list, `laptop` is not shown.
- AE3. **Covers R6, R7.** Given dhcp-watch was restarted 2 minutes ago and the log contains a host seen 3 minutes before restart, when the operator opens the page, that host appears on the live list (still within the quiet period) and there is no separate “history” view.
- AE4. **Covers R1.** Given dhcp-watch is running on a Pi, when the operator opens the page from another device on the same LAN, the roster loads; the product does not require exposing the page beyond the LAN.

---

## Success Criteria

- From a phone or laptop on the home LAN, the operator can open one URL and see who has been detected recently, with the list updating as devices appear.
- After a watcher restart, recent hosts from the log still show until they age out — the page is useful without waiting for new DHCP traffic.
- A planner can implement without inventing product behavior for access model, update model, drop-off, or log fallback.

---

## Scope Boundaries

- No remote / public access, VPN setup, or auth in v1
- No history browser, search, filtering, or export UI
- No vendor / device-type labels, ignore-list controls, or Telegram changes on the page
- No separate sidecar web process — the watcher serves the page
- No redesign of packet capture or alert semantics beyond what’s needed to maintain and expose the live roster

---

## Key Decisions

- **Watcher serves the page (Approach A):** One process on the Pi; true live events; fewer moving parts than a sidecar.
- **Quiet-period drop-off:** “Currently detected” means seen lately, not ever seen this session.
- **Log as seed, not a second UI:** Recovers usefulness after restart without building a history product.
- **Minimal row content:** Identity + last-seen only for v1.
- **Quiet period default = 10 minutes:** Matches existing `DEBOUNCE_SECONDS` (600); configurability can follow later.

---

## Dependencies / Assumptions

- dhcp-watch continues to run with privileges needed for packet capture; the web page is an additional surface of that same process.
- The existing log file remains available and parseable enough to seed recent hosts (format may need hardening during planning if ambiguous).
- LAN-only reachability is sufficient security for v1 (home network trust model).

---

## Outstanding Questions

### Deferred to Planning

- [Affects R1][Technical] How the process binds and advertises the listen address/port (config vs defaults).
- [Affects R3][Technical] Push transport choice (e.g. SSE vs WebSocket) given a simple Python stack.
- [Affects R6][Technical] Exact log parsing rules for seeding (timestamp completeness, unknown fields, malformed lines).
