# Study & Rebuild Plan — from operating this IPS to building it

Historical exercise plan: start with DEVELOPER_STUDY_ROADMAP.md for the current complete curriculum and PROJECT_AI_HANDBOOK.md for current source relationships. Several references below no longer exist; the old fixed 2x-mirror and unconditional zero-day/train-serve claims are not current guarantees. Deliberate break-it exercises belong only in isolated copies/labs. The new roadmap covers site-v3 collection, policy analysis and production evidence as well as this legacy SDN track.

A self-study track that turns *this* project into your curriculum. No new project needed — you go back
through what you have, with your hands instead of your prompts. Pair it with `DEVELOPER_LEARNING_GUIDE.md`
(skills→files) and `codebase_overview.md` (the two line-by-line traces).

## The one rule
**Understanding = you can reproduce it and explain it without an AI.** So every unit below has four
steps, and a unit is not "done" until you pass its self-test **cold** (closed book, no AI):
1. **Read** the file with the overview open.
2. **Rebuild** the target slice from a blank file, from memory. Diff against the original — the diffs
   are exactly what you didn't understand.
3. **Break it** — cause the failure the design prevents, so you *feel* why the code is shaped that way.
4. **Self-test** — answer the question out loud (or write it) with everything closed.

Keep a **`scars_log.md`**: every break-it bug you cause, what you saw, and why the fix exists. That
file becomes your real résumé of understanding.

Suggested pace: 1 unit / week, ~5–7 focused hours each. Faster is usually fooling yourself.

---

## Unit 0 — Networking fluency (run this in the background the whole time)
Everything here is downstream of packets. Install Wireshark; from Kali, run your own `hping3 -S`,
`nmap -sS`, and `arpspoof` against a device, and **watch the frames**.
- **Self-test:** point at a packet and name it (SYN vs SYN-ACK vs RST vs ARP request/reply); explain
  what a SYN flood does to a server's connection table; explain why an ARP spoof works at L2.
- **Pair:** any "TCP/IP fundamentals" + Wireshark intro. This is the fastest thing to get genuinely
  fluent in, and it makes the feature engineering click.

## Unit 1 — Warm-up: `Controller/ipsctl.py` (45 lines, UDP)
- **Rebuild:** write a UDP client that sends `argv` to `host:9999` from scratch.
- **Break it:** send to the wrong port; send while the controller's down. Watch it fail silently
  (UDP is fire-and-forget) — understand *why there's no error*.
- **Self-test:** why UDP not TCP for the control channel? (Hint: it must reach the controller *under a
  flood* when TCP queues are saturated.)
- **Pair:** Python sockets basics.

## Unit 2 — The AE engine: `Controller/ae_inference.py` (~160 lines, pure NumPy)
The best rebuild target — self-contained, no framework magic.
- **Rebuild:** implement `score(row)` from a blank file: vectorize → `(x-mean)/scale` → forward pass
  (`x@W+b`, ReLU) → MSE → `conf = err/(err+threshold)`. Diff against the original.
- **Break it:** feed a row with a missing feature; change the layer order; use `conf = err` instead of
  the normalized form and see how the bands stop making sense.
- **Self-test:** why is the AE trained on *normal only*? Why does that make it a zero-day detector?
  Why pure-NumPy at runtime instead of loading TensorFlow?
- **Pair:** NumPy (matrix ops, broadcasting), and StatQuest on autoencoders/neural nets.

## Unit 3 — The RF engine: `Controller/ml_inference.py` (~300 lines, sklearn)
- **Rebuild:** write `RFPreprocessor.transform` from memory (drop → one-hot protocol → reindex to 86 →
  scale → select 66). Then explain why the pipeline is pickled *with* that class.
- **Break it:** load `rf_pipeline.joblib` in a plain script without importing `ml_inference` → watch
  the `Can't get attribute 'RFPreprocessor'` unpickle error. Now you understand the pickling gotcha.
  Then set `n_jobs=-1` and run the controller → **watch it hang** (this is the big one — see Unit 5).
- **Self-test:** what's train/serve skew, and how does this project *structurally* prevent it? (Same
  `traffic_capture` code path feeds both the dataset and live inference.)
- **Pair:** scikit-learn pipelines + StatQuest (Random Forest, precision/recall, ROC).

## Unit 4 — Ryu + the `packet_in` path: `Controller_main_Claude.py::_packet_in_handler`
- **Read:** Appendix 1 of `codebase_overview.md`, then the handler. Then do Ryu's `simple_switch_13.py`
  tutorial and **diff** it against this handler to see what was added.
- **Rebuild:** write a minimal learning switch (`packet_in` → learn MAC → install flow → PacketOut).
- **Break it:** remove the amplification guard (`if msg.reason == OFPR_ACTION: return`) → watch the
  duplicate-packet storm and the false "ICMP flood" during a normal ping. Cause it, then re-read the
  comment block that explains it.
- **Self-test:** what does `output:CONTROLLER, 0xffff` do and why is it the thing that feeds the whole
  ML pipeline? Why doesn't `pingall` succeeding prove the controller is connected?
- **Pair:** OpenFlow match/action model; `ovs-ofctl dump-flows`.

## Unit 5 — THE CRUX: the block path + concurrency
`block_attacker` → `_block_q` → `_block_worker` → `_do_block_attacker` (Appendix 1). **If you master one
thing in this codebase, make it this.**
- **Rebuild:** on paper, draw which thread each function runs on (hub greenlet vs the flush OS thread
  vs the Snort thread) and where the queue is the boundary.
- **Break it:** make the flush thread call `datapath.send_msg` directly (bypass the queue) → watch the
  controller **deadlock the instant a block fires**. This is *the* bug the whole design exists to
  prevent. Then revert and confirm the queue handoff fixes it.
- **Self-test:** explain, cold: *why can a real OS thread not call `send_msg`, but the WSGI/REST handler
  can?* (eventlet green primitives are only safe on the hub thread; REST handlers already run on it.)
  This is your #1 interview answer for this project.
- **Pair:** Python threading vs cooperative concurrency; **Beazley's "Understanding the Python GIL"**;
  read `memory/controller-eventlet-hub-hazards`.

## Unit 6 — The feature pipeline: `Controller/traffic_capture.py` (the biggest file)
`record_packet` (producer) → `_flush_flows` (consumer) → rate/RF/AE → CSV (Appendix 2).
- **Rebuild:** just the snapshot-and-reset block under `_flow_lock` — explain why you copy-then-zero
  inside the lock and compute outside it (double-buffer; don't block the producer during scoring).
- **Break it:** hold the lock through the whole scoring loop → watch capture stall under load. Remove
  the protocol-consistency guard → watch a SYN attacker's ICMP/ARP flows mislabel as "SYN Flood."
- **Self-test:** why ratios/entropy instead of raw packet counts? (Immune to the Mininet 2× mirror
  double-count.) What is `is_baseline_mature` and why does a cold baseline cause false positives?
- **Pair:** pandas; your own `feature_engineering_rationale` (restore from the tag if you want it back).

## Unit 7 — The Snort tier: `Controller/snort_monitor.py` + `snort3/*.rules`
- **Rebuild:** write one Snort rule (e.g. an ICMP flood `detection_filter`), load it, and watch it
  appear in `alert_json`, then watch the controller block on it.
- **Break it:** set the `count` threshold to 1 → watch normal pings trigger it (false positives), then
  reason about why the real thresholds are where they are.
- **Self-test:** signature vs rate vs RF vs AE — name each tier's blind spot and which other tier covers
  it. Why is Snort gated by DETECT and RF/AE gated by ML mode?
- **Pair:** Snort 3 rule syntax; IDS/IPS concepts.

## Unit 8 — REST + dashboard: `IPSRestController` + `Dashboard/index.html`
- **Break it:** put `float('inf')` into a `/ips/blocked` value → watch the dashboard's blocked table
  go silently empty (invalid `Infinity` JSON). You lived this bug — now cause it deliberately.
- **Self-test:** trace one dashboard number from the browser back to the line of Python that produced it.

---

## Capstone — extend the system *unaided*
You're past junior when you can add one of these end-to-end without an AI writing it, and explain every
choice:
- A **new Snort rule + a matching feature** in `traffic_capture`, and predict its effect before running.
- A **CUSUM low-and-slow detector** on the AE error stream (a 5th signal), wired through the *queue*
  (not a direct `send_msg`).
- Wire the **QoS data-rate threshold** (restore `QoS/` from the tag) so steering is by measured Mbps.

## The competency ladder (self-assess honestly)
- **Vibe:** can run the runbooks; can't explain why any of it is shaped that way.
- **Advanced beginner:** can operate + read `dump-flows` + explain the four tiers' jobs.
- **Junior (target):** can rebuild Units 2–5 cold, cause+explain the eventlet hang and the amplification
  storm, add a Snort rule + feature and predict its effect, and debug "printed BLOCKED but nothing
  blocked" by reasoning about the JSON/dashboard path.
- **Solid:** can extend a tier, retrain on real data and defend the numbers, and teach Unit 5 to someone else.

## How to use me (Claude) so you learn instead of copy
- Attempt first, then: *"review my attempt"* — not *"implement X."*
- State a hypothesis before asking: *"I think it's the flow key — am I right?"*
- Ask me to **quiz you** on a unit, or to **grade your explanation** and name what's shallow.
- For anything I build, ask *"what would the naive version have broken?"* — the tradeoff is the lesson.
- (I'll be giving the rationale by default now — push back and ask "why not X?" when I do.)

Start point: **Unit 5's self-test.** If you can answer *why the flush thread can't call `send_msg`*
cold, you're further than most. If you can't, that's exactly where to begin.
