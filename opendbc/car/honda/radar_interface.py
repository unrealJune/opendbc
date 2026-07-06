#!/usr/bin/env python3
import math
from dataclasses import dataclass, field
from math import pi, sin

from opendbc.can import CANParser
from opendbc.car import Bus, structs
from opendbc.car.interfaces import RadarInterfaceBase
from opendbc.car.honda.hondacan import CanBus
from opendbc.car.honda.values import DBC, HONDA_BOSCH_A


def _create_nidec_can_parser(car_fingerprint):
  radar_messages = [0x400] + list(range(0x430, 0x43A)) + list(range(0x440, 0x446))
  messages = [(m, 20) for m in radar_messages]
  return CANParser(DBC[car_fingerprint][Bus.radar], messages, 1)


# 36802-TBA Bosch radar FINE per-track object table (0x280 block).
# Cross-car CONFIRMED 2026-06-07 (3 cars / 6 routes; 8905 tracks fused leadOne.dRel at R^2=0.975).
# This SUPERSEDES the coarse 0x2C8/0x2C9 selected-lead as the range source: the radar broadcasts up to
# 8 track records, each a 4-frame burst on consecutive IDs. Only the HEADER ID of each record carries
# RANGE, and only on the sub-frame tagged b1==0x74 (moving) OR b1==0x94 (stationary/decelerating motion
# class). Both share the SAME byte layout; the tag high nibble encodes motion class (7=moving, 9=stationary).
# The parser gates on BOSCH_RADAR_HDR_TAG_SET, skips idle/saturation
# sentinels, emits up to 8 RadarPoints (stable trackId per slot), and lets radard select the lead.
# IMPORTANT: these object frames are physically on openpilot CanBus.camera (rlog src=2, confirmed
# across 6 routes), NOT CanBus.radar (bus 0). The Bus.radar key below is only the DBC-name lookup;
# the parser's CAN bus is CanBus(CP).camera. Reconfirm the bus with a read-only sniff before trusting dRel.
#
# SLOT LIST -- the 8 header IDs in SWEEP/TRANSMIT ORDER (address-ascending; 0x280 leads, 0x2DC terminates,
# confirmed on-wire 2026-07-01). slot index == position in this list == trackId // TRACKID_STRIDE.
# 0x288 and 0x28C were ADDED 2026-07-01 (phantom-fix drives 00000002/00000003): a per-header validity sniff
# (tmp_radar/slot_map.py) showed the radar fills a near GROUP {0x280,0x284,0x288,0x28C} + a far GROUP
# {0x2D0,0x2D4,0x2D8,0x2DC}, but the OLD 6-slot list read the near group only PARTIALLY -- it polled the
# far slots 0x2D4/0x2D8/0x2DC (valid 1%/0%/0% of sweeps) while SKIPPING 0x288 (valid ~30%, 1059 tracks,
# median ~62 m) and 0x28C (~12%, 433 tracks). Reading the full 8-slot table is the physically-correct decode
# and gives fuller mid/far object coverage. 0x2DC stays LAST -> the sweep-coherent trigger (S4) is unaffected.
#
# SCOPE / VALIDATION (be honest): this was investigated as a fix for the 40-70 m false-closing / follow-too-far
# symptom, but an offline old-6-slot-vs-new-8-slot replay of both drives (tmp_radar/validate_replay.py,
# diag_lateral.py) showed it is NEUTRAL for that symptom -- only ~8% of the added-slot points are the actual
# vision lead (92% are OTHER objects), so lead coverage barely moved (22%->23%) and the false-closing did not
# drop. It is also NEUTRAL for phantom risk (closer-in-path frames 6.9%->7.0%). The real cause of the
# follow-too-far / jumping-chevron / tunnel-wall-phantom is radard (openpilot) fusing a CLOSER near-slot object
# than the vision lead and flip-flopping leadOne between them; the parser's per-slot vRel is faithful to the
# measured range motion. See tmp_radar/RADARD_HANDOFF.md. Kept here as a correctness/coverage improvement, NOT
# as the symptom fix.
BOSCH_RADAR_HDR_MSGS = [0x280, 0x284, 0x288, 0x28C, 0x2D0, 0x2D4, 0x2D8, 0x2DC]

# Range-carrier header tags: sub-frames with b1==0x74 (moving) OR b1==0x94 (stationary/decelerating
# motion class) carry RANGE in b2:b3 with the SAME byte layout. High nibble = motion class (7=moving,
# 9=stationary); low nibble 0x4 = range carrier. 0x94 was the dominant tag during real stops
# (corpus: unmatched-stop windows 0x94:642 vs 0x74:1) -- the old 0x74-only gate dropped every stop
# frame as metadata -> no RadarPoint -> vision-only during stops (nrdrbranchdebug-73z).
# 0x34 is NOT admitted (corpus r weak/unvalidated -- documented coverage gap).
# BOSCH_RADAR_HDR_TAG is kept for the canonical/primary-tag reference (tests + DBC decode asserts).
BOSCH_RADAR_HDR_TAG = 0x74       # moving-class range carrier (canonical; kept for backward compat)
BOSCH_RADAR_HDR_TAG_SET = frozenset({0x74, 0x94})  # allow-list: 0x74 moving + 0x94 stationary

# Idle / unset / saturation sentinels (any one -> not an active track). STRENGTH is b0 raw (idle 0xFE),
# RANGE_RAW is b2:b3 raw int (0x8000 ~114 m unset; >=0xFF80 ~230 m saturation rail).
BOSCH_RADAR_STRENGTH_IDLE = 0xFE
BOSCH_RADAR_RAW_UNSET = 0x8000
BOSCH_RADAR_RAW_SAT = 0xFF80

# --- Native Doppler exposure (RX-only telemetry; NO control change) ------------------------------
# The radar's SELECTED-lead coarse output 0x2C8 (RADAR_SELECTED_0) carries REL_SPEED -- a REAL
# published relative velocity (Doppler) for the radar's own ACC target, unlike the FINE per-track vRel
# which the parser DERIVES from range. Mined 2026-07-01 (tmp_radar/mine_*.py; drives 00000007 highway
# + 00000003 night): the selected lead associates to FINE SLOT 0 (0x280, the closest track) at r=0.84
# vs slot0's own range-rate, so the native Doppler is attached to SLOT 0's RadarPoint (field
# vRelNative). The zero-point is rock-stable (REL_SPEED=0 at raw ~124, DBC-encoded) but the SCALE is
# coarse/drive-dependent (~0.7-1.1 m/s/LSB). It is EXPOSED, NOT fused into vRel: an offline replay
# showed a standalone vRel veto using it damps ~10-26% of REAL closings (unsafe without vision), while
# a safe version yields no benefit -- the fusion belongs radard-side (with vision + path). radard reads
# vRelNative to cross-check the DERIVED vRel's false-closing. See tmp_radar/RADARD_HANDOFF.md.
BOSCH_RADAR_SELECTED_MSG = 0x2C8
BOSCH_RADAR_SEL_STRENGTH_IDLE = frozenset({0x00, 0xFE})  # B0 idle/unset sentinels -> no selected lead
BOSCH_RADAR_SEL_RANGE_UNSET = 0x8000
BOSCH_RADAR_SEL_RANGE_SAT = 0xFF80
# Association sanity gate: only attach the selected-lead Doppler to slot 0 when it AGREES with slot0's
# own DERIVED vRel within this bound. Calibration-free cross-check that rejects the case where the radar
# selected a DIFFERENT object than slot 0. Generous -- the false-closing disagreements radard cares
# about are 1-4 m/s; this only rejects gross wrong-object mismatches (and NaN slot0 vRel).
BOSCH_RADAR_SEL_VREL_AGREE = 8.0  # m/s

# b4:b5 FIELD IDENTITY = AZIMUTH ANGLE (offset-binary, center 0x8000), NOT range-rate.
# SETTLED 2026-06-08 by a three-source rlog regression against the vision-model lead (no flash, no TX,
# no Ghidra, no controlled/tape capture) -- radar-re/latscale/_rlog/{peter-3d,peter-49,joey}.md and
# radar-re/latscale/LATSCALE-SHIPPED.md. ~20,880 matched (radar-track <-> model-lead) frames across
# three cars:
#   * AZIMUTH wins every discriminating (high-lateral-motion) segment; richest segment (peter-3d seg168,
#     lateral -4.14..+5.38 m) full-sin R^2=0.946, Pearson r(off, asin(y0/rng)) = -0.965.
#   * RANGE-RATE is FALSIFIED: off vs relative velocity is flat to noise everywhere (R^2 0.01-0.08 on the
#     discriminating segments; pooled Pearson r ~= +0.045). b4:b5 is NOT a free vRel -- vRel stays DERIVED.
# So yRel is the lateral PROJECTION of the (range, azimuth) polar measurement, computed trigonometrically
# from dRel and the offset-binary angle -- NOT a linear m/LSB on the raw field:
#     yRel = +dRel * sin((b4b5 - 0x8000) * LAT_SCALE_DEG_PER_LSB * pi/180)
# LAT_RAW is already (b4b5 - 0x8000) per the DBC offset -32768, so it feeds the sin directly.
#
# SIGN (fixed 2026-07-06): the ORIGINAL 2026-06-08 sign was a convention error, not a data error. radard
# expects track yRel == -lead.y (see match prob / lat gate: |c.yRel + lead.y|). The original regression's
# own correlation was NEGATIVE (peter-3d: r(off, asin(y0/rng)) = -0.965, i.e. vision y ~ -sin(k*raw)),
# which after the -lead.y convention means yRel must be +dRel*sin(k*raw) -- but the sign was shipped as
# negative and was UNDETECTABLE on in-path-only drives (yRel ~ 0 either way). The 2026-07 roadtrip
# (tmp_radar/az_cal2-4.py, 10,439 matched pairs, 1,039 with |y_vis| >= 1 m of real lateral excitation)
# settles it: candidate shoot-out vs the radard target (-vision_y) gives shipped-sign p90 error 3.04 m
# vs flipped-sign 0.62 m. The flip also explains the far-range mis-placement that blocked fusion (a track
# published at +5.1 m when the lead sat at -1.8 m) -- the object was on the CORRECT side all along.
#
# SCALE (re-fit 2026-07-06 on the excited pairs, errors-in-variables-bracketed): k = 0.001186 deg/LSB,
# half-sample CV std 0.000009; per-range bins agree (5-20 m: 0.001201, 20-35 m: 0.001152) -- consistent
# with the original band's top end (joey 0.000902, peter-3d 0.0007-0.00086) which was attenuated by
# zero-excitation data. The linear-lateral (m/LSB) alternative model is REJECTED (slope varies 0.31 ->
# 0.47 mm/LSB across range bins; angle-model slope is range-stable). BORESIGHT: -64 +/- 30 LSB (~0.08
# deg) -- negligible and unstable, shipped as 0; a parked corner-reflector read (calibration app target
# mode) can pin it if it ever matters.
BOSCH_RADAR_LAT_SCALE_DEG_PER_LSB = 0.001186  # deg/LSB; roadtrip excited-pair re-fit, CV std 9e-6

# Staleness gate: if no fresh 0x280 header is seen for this long, clear all points and return an EMPTY
# RadarData (not None) so radard drops the lead within a cycle (no frozen phantom). RadarPoints carry no
# per-point monotime, so radard trusts points unconditionally -- a stalled source must be cleared here.
BOSCH_RADAR_STALE_S = 0.15  # ~3 missed 20 Hz frames

# vRel discontinuity guard (slot-reuse defense). trackId == slot index, so if object A vacates a slot and
# object B enters the SAME slot in the next cycle WITHOUT an intervening empty/sentinel cycle, the naive
# d(dRel)/dt derivative would teleport vRel to a physically impossible value (e.g. an observed ~1928 m/s)
# for what radard then treats as one continuous object. Any implied |vRel| above this bound is therefore
# NOT a real relative speed -- it is a track swap. We REJECT that sample (vRel -> NaN, and re-seed the
# per-track history baseline to the NEW object's position) so the next clean cycle derives a real vRel
# from the new object instead of carrying a phantom. The bound is deliberately generous: a genuine
# fast-closing lead (stationary object at highway speed ~31 m/s, or a head-on ~60 m/s) is far below it,
# so no real lead is ever rejected; only the swap artifact (which is ~20x over) is.
#
# PHANTOM-BRAKE FIX (nrdrbranchdebug, route 0543acc22b): the original 100 m/s bound was FAR too loose --
# replay of the bookmarked drive showed the 0x280 decode emitting |vRel| up to 89.6 m/s and feeding
# radard 303 fused leads whose closing speed disagreed with the vision model by >4 m/s (118 of them with
# the radar inventing a hard-closing lead that vision did not see), the direct cause of the phantom
# braking. A genuine fast-closing lead for this Honda use case is a stationary object at highway speed
# (~31 m/s) or a hard head-on (~40 m/s); anything implying a faster instantaneous jump is a decode/swap
# artifact, so 30 m/s is the tighter slot-reuse BREAK bound (was 100).
BOSCH_RADAR_VREL_MAX = 30.0  # m/s; implied per-frame |jump speed| above this == swap artifact -> BREAK

# Emit-time vRel trust gate -- GRADUATED PERSISTENCE (replaces the old flat |vRel| cap, 2026-07-01).
# A flat magnitude cap (formerly PLAUSIBLE=20/30) is the wrong tool: it cannot tell a REAL fast closer from
# a phantom. A stopped car at highway speed closes at |vRel| up to ~30, so a low cap BLINDS us to distant
# stopped traffic (car doesn't slow), while a high cap lets phantoms through (phantom braking). Instead:
# the HIGHER the claimed |vRel|, the LONGER the track must have been cleanly tracked (settle cycles) before
# we trust it. A real fast closer persists as you approach and EARNS the trust; a short-lived phantom never
# accumulates it. (KF range-rate variance p11 was tested as the discriminator and REJECTED -- it converges
# to ~0.92 for every track regardless of quality; persistence is what actually separates real from phantom.)
# A hard physical ceiling still drops decode garbage outright.
# Validated on drive 00000007 highway seg 6/13/14/22 (n=5492): residual |vRel|>15 drops 101->~10, >20 -> 0,
# lead-retention preserved (~62%), and ZERO persistent (settle>=20) high-vRel tracks dropped -> a real
# stopped car is KEPT, unlike the flat cap. High-|vRel| detection is delayed by the settle requirement
# (~0.5-0.9 s) -- an accepted tradeoff; the PRIMARY distant-stopped-traffic fix is the azimuth/yRel
# calibration (far tracks are currently mis-placed laterally -> not fused by radard), see CAPTURE_SPEC.
BOSCH_RADAR_VREL_HARD_MAX = 45.0   # m/s; above this is not a real closing speed for this car -> always drop
BOSCH_RADAR_VREL_SOFT = 15.0       # m/s; |vRel| <= this is trusted at the base SETTLE_CYCLES
BOSCH_RADAR_VREL_MID = 25.0        # m/s; (SOFT, MID] must survive SETTLE_MID clean cycles
BOSCH_RADAR_SETTLE_MID = 10        # clean cycles required to trust |vRel| in (SOFT, MID]
BOSCH_RADAR_SETTLE_HIGH = 18       # clean cycles required to trust |vRel| in (MID, HARD_MAX]

# Settle gate: a slot must produce this many CONSECUTIVE clean KF updates (no birth, no reseed, no BREAK,
# and no innovation-adaptive/maneuver step) before its vRel is trusted enough to emit a point. Jumpy /
# churning tracks -- the source of the swinging +5/-23 m/s phantom closings -- never accumulate a clean
# run, so they are suppressed (radard uses vision); a real, smoothly-tracked lead settles in ~0.15 s and
# emits continuously. SETTLE_CYCLES > KF_CONV_UPDATES so vRel is always converged by the time it emits.
BOSCH_RADAR_SETTLE_CYCLES = 3
# A track with at least this many consecutive clean cycles behind it is MATURE: an innovation-adaptive
# (maneuver) step decays its settle run to SETTLE_CYCLES instead of zeroing it, so a real lead that
# starts braking keeps emitting (soft-|vRel| band) instead of blanking for 3 sweeps at maneuver onset.
# Young/churny tracks still zero -- the validated phantom protection is unchanged for them, and the
# graduated high-|vRel| bands (SETTLE_MID/HIGH) still demand a fresh clean run either way.
BOSCH_RADAR_SETTLE_MATURE = 20

# --- SAFE parity hardening constants (PARITY-MATRIX §3/§4; RX-only, keep-AEB preserved) ----------
# S1 -- trackId no-reuse (capnp car.capnp:314 "no trackId reuse"). trackId is no longer the bare slot
# index; it is slot*1000 + incarnation, where incarnation is bumped every time a slot is (re)born after
# being vacated (sentinel/absent/wrong-tag) OR on a detected slot-reuse discontinuity. This way a slot
# that hands off from object A to object B presents radard a DIFFERENT trackId, so radard's Kalman
# tracker sees a clean birth instead of one continuous object teleporting. Still UInt64; still
# slot-decodable as trackId // BOSCH_RADAR_TRACKID_STRIDE; never reused for a distinct physical object.
BOSCH_RADAR_TRACKID_STRIDE = 1000  # trackId = slot * STRIDE + incarnation

# S2 -- birth/persist hysteresis (Toyota valid_cnt pattern, toyota/radar_interface.py:66-77). A per-slot
# confidence counter: +1 on a valid range-carrier frame (capped), -1 (floored at 0) on absent/sentinel/
# wrong-tag. A point is only EMITTED once the counter reaches BORN_CYCLES (debounces a 1-frame glitch
# into a phantom), and only DROPPED once the counter floors at 0 (tolerates a single missed cycle).
# This governs per-slot birth/death WITHIN a live trigger stream only; the global STALE_S clear in
# update() and the whole-bus-silent path are UNCHANGED and still win (a whole-bus silence wipes all).
BOSCH_RADAR_BORN_CYCLES = 2  # consecutive valid cycles required before a slot emits a point
BOSCH_RADAR_VALID_CAP = 5    # max value the per-slot confidence counter saturates at

# S7 -- cross-slot identity stitch (2026-07-01, drive 4b775e9a/00000005 + 00000007 seg14 diagnosis).
# The radar re-sorts objects between fine-table slots (priority churn): in traffic the FOLLOWED LEAD hops
# slots every ~1-2 s. Without stitching every hop is a fresh incarnation -- BORN+SETTLE withholding (a
# ~3-sweep emit hole) plus a NEW trackId (radard KF reset + re-association penalty) -- so the fused lead
# steps to vision-only values and back (4-6 m) about once a second: the residual "phantom brake /
# follow-too-far / jumping chevron" driver AFTER the vRel gates. Measured on seg14 (steady highway
# follow): 34 of 54 lead-track dropouts were exactly the 3-sweep settle hole and the one physical lead
# wore 72 trackIds in 45 s. Stitch: when a slot (re)births, search recently-deceased born tracks for one
# whose PREDICTED range (last KF range + range_rate * gap) matches the new occupant inside a tight gate;
# on a hit the new occupant INHERITS the dead track's trackId, KF (the learned range-rate), confidence
# and settle run -> no emit hole, no id change; radard sees one continuous object. The gate is tight
# (range-continuity over <= ~4 sweeps) so distinct objects don't stitch; a worst-case mis-stitch of two
# near-coincident same-range objects costs a few KF cycles of adaptation, far less than the guaranteed
# churn harm. trackId no-reuse (S1) is preserved: an inherited id IS the same physical object continuing.
BOSCH_RADAR_STITCH_MAX_AGE_S = 0.25   # s; how long a deceased track stays stitchable (~4 sweeps)
BOSCH_RADAR_STITCH_RANGE_GATE = 2.0   # m; |new range - predicted deceased range| must be under this
# S7b -- AZIMUTH awareness (drive 00000007 seg14, multi-object same-range scene): range alone cannot
# tell two objects in DIFFERENT LANES at the SAME range apart. Two consequences and their fixes:
# (a) occupant SWAPS between same-range slots are invisible to the range-only BREAK test, so identities
#     silently cross objects (in-path track inherits the adjacent lane's kinematics -> under-reported
#     closing on the followed car + the "teleporting chevron"). A sweep-to-sweep LATERAL jump far above
#     physical lateral motion (~0.1 m/sweep) is therefore treated exactly like a range BREAK. The gate
#     scales with range because azimuth noise grows with range.
# (b) the stitch gate gains the same lateral-continuity requirement so a rebirth can only inherit an
#     identity that matches in BOTH range and azimuth.
BOSCH_RADAR_Y_BREAK_BASE = 2.0        # m; lateral jump gate at zero range
BOSCH_RADAR_Y_BREAK_SCALE = 0.06      # m of extra gate per meter of range
BOSCH_RADAR_STITCH_Y_GATE_BASE = 1.5  # m; lateral continuity gate for stitching
BOSCH_RADAR_STITCH_Y_GATE_SCALE = 0.05

# S8 -- HARDWARE per-object identity from the fine-track SUB2 sub-frame OBJ_LIFE (B0:B1 of header+2:
# 0x282/0x286/0x28A/0x28E/0x2D2/0x2D6/0x2DA/0x2DE). Mined + validated 2026-07-06 (tmp_radar/id_perobject.py,
# id_predicate.py on trip_fusion.pkl, 6 highway/traffic segments): OBJ_LIFE is the radar's OWN per-object
# lifetime accumulator -- it ticks +33 per sweep for a continuously-tracked object (deterministic internal
# sub-counter steps of +17 ~6% / +1 ~2%, NEVER a same-object decrease) on top of a near-unique per-object
# seed, so two SIMULTANEOUS objects collide only 0.2% of the time (spread median ~8448 over live slots).
# It is the radar's internal track id, which the range/azimuth stitch (S7/S7b) only APPROXIMATES.
# Used here as a stitch corroborator / VETO + missed-stitch recovery ON TOP of the geometric gates (NOT a
# standalone id: 2.56% of nearest-other-object counter gaps fall inside the <=6-sweep continuity reach, so
# range/azimuth still gate). Measured vs the parser's replay-validated identities: 95.6% of S7 stitches are
# counter-corroborated, 90.9% of BREAKs counter-confirmed, and 245/442 fresh trackIds are actually the same
# physical object the geometry MISSED (counter-continuous + range-plausible) -> recoverable churn.
# RX-only: read via an ISOLATED parser (rcp_sub) so a missing SUB2 frame can NEVER affect can_valid / fault
# logic; when OBJ_LIFE is unavailable the stitch falls back to the exact S7/S7b geometric behavior.
#
# Continuity predicate (_bosch_obj_life_continues): over a graveyard gap of age_s seconds the SAME object's
# OBJ_LIFE advances by delta=(now-old) mod 2^16 in [1, STEP_MAX*n + MARGIN], where n bounds the sweeps
# elapsed (age_s / fastest-sweep-dt). A different object is thousands away (or wraps to a huge delta) ->
# rejected. On an EMPTY/sentinel slot OBJ_LIFE is a high rail (~0xFFF0-0xFFFF), so it is only read for slots
# with a live range-carrier (never gated on the raw value -- a real counter can sit there just before wrap).
BOSCH_RADAR_SUB2_MSGS = [h + 2 for h in BOSCH_RADAR_HDR_MSGS]  # 0x282,0x286,...,0x2DE (SUB2 = header+2)
BOSCH_RADAR_OBJ_LIFE_STEP_MAX = 33     # max legit per-sweep OBJ_LIFE increment (observed max; 92% are +33)
BOSCH_RADAR_OBJ_LIFE_MARGIN = 6        # slack (parse/timing jitter) added to the continuity upper bound
BOSCH_RADAR_SWEEP_DT_MIN_S = 0.045     # fastest plausible sweep cadence -> generous sweep-count bound
# Range residual (after KF motion-compensation) allowed for a stitch when OBJ_LIFE CONFIRMS the identity
# (recovery of a missed stitch): looser than the geometry-only gate but still bounded (the close-counter
# tail can only ever align a genuinely range-plausible object). Geometry-only stitches keep the tight gate.
BOSCH_RADAR_STITCH_RANGE_GATE_LIFE = 5.0  # m

# S3 -- plausibility / self-consistency fault annotations (RX-only; error bits on RadarData, NOT
# authority changes; NO new frame decoded -- this is the SAFE subset of matrix #18). (a) a decoded dRel
# outside the physical band [RANGE_MIN, RANGE_MAX] for the declared scale is a decode/scale inconsistency
# -> wrongConfig + skip the point. (b) if can_valid but the trigger slot's CNTR has not advanced for
# CNTR_STALL_CYCLES cycles, the source is frozen-but-present -> radarFault.
BOSCH_RADAR_RANGE_MIN = -3.0   # m; DBC offset floor (raw 0 -> -3.0). Below this == decode inconsistency.
BOSCH_RADAR_RANGE_MAX = 230.0  # m; saturation rail ceiling. Above this == decode inconsistency.
BOSCH_RADAR_CNTR_STALL_CYCLES = 3  # frozen-CNTR cycles (while can_valid) before radarFault

# S6 -- vRel derivation hardening. Reject a non-positive dt (already guarded) AND clamp the dt upper
# bound: after a long gap the tiny-denominator-free path is fine but a stale baseline across a long gap
# would derive a spurious vRel from two far-apart-in-time samples -> re-seed (drop the derivative this
# cycle) when dt exceeds this.
BOSCH_RADAR_VREL_DT_MAX_S = 0.5  # s; baseline older than this -> re-seed, do not derive a vRel

# D1 (nrdrbranchdebug-86t.1) -- tag-demux frame assembler. CANParser.vl is last-write-wins per signal;
# when a range-carrier (0x74/0x94) and a metadata sub-frame share a header ID in one emit window, the
# old vl read saw only the LAST frame and spuriously decayed a live track. Frames are harvested from
# vl_all per rcp.update() batch (vl_all is cleared on every update call, while updated_messages
# accumulates until the 0x2DC trigger) and demuxed by TRACK_TAG at emit time.
BOSCH_RADAR_PENDING_CAP = 8  # max harvested frames retained per slot between trigger emits

# R1 (nrdrbranchdebug-86t.4) -- per-slot constant-velocity [range, range_rate] Kalman filter on the raw
# DBC-scaled RANGE, replacing the d(dRel)/dt + alpha=0.5 EMA derivation (~50-75 ms lag, LSB quantization
# chatter, and the S6 re-seed EMA-halving bug nrdrbranchdebug-6u8, which dies with the EMA).
BOSCH_RADAR_KF_R = 0.012          # m^2; range measurement variance (0.00357 m/LSB quantization + jitter)
BOSCH_RADAR_KF_Q_R = 0.05         # m^2/s; range process noise density
# range-rate process noise density (m/s)^2/s -- err RESPONSIVE so a hard-braking lead is never modeled
# optimistic (R1 ship gate). Sim-tuned 2026-06-10: at -6 m/s^2 lead braking, worst optimism 0.88 m/s
# (0.8 gave 1.77); realistic-noise vRel std 0.35 m/s vs the old d/dt+EMA's 1.00 -- still ~3x quieter
# while 2x more responsive.
BOSCH_RADAR_KF_Q_V = 4.0
# (m/s)^2; (re)seed range-rate variance. Large on purpose: the second sample then reproduces the raw
# derivative (old-behavior parity), smoothing only engages from the third sample on.
BOSCH_RADAR_KF_P0_V = 1.0e4
# 2-sigma normalized innovation; above this Q_v is inflated this step (noise-floor NIS is ~1e-3 at the
# quantization level -- huge margin)
BOSCH_RADAR_KF_NIS_ADAPT = 4.0
BOSCH_RADAR_KF_NIS_INFLATE = 10.0 # Q_v inflation factor on an adaptive step (maneuver onset)
# measurements absorbed before range_rate is published (S5 parity: the old path also had a derived vRel
# on the 2nd sighted cycle)
BOSCH_RADAR_KF_CONV_UPDATES = 2
BOSCH_RADAR_ACCEL_EMA_ALPHA = 0.25  # smoothing on the packed aRel (consumer is K5, radard-side, later)

_KF_OK, _KF_BREAK, _KF_RESEED = 0, 1, 2


@dataclass
class BoschTrackRecord:
  """D1: one slot's sub-frames for one emit window, demuxed by TRACK_TAG (stateless per window)."""
  slot: int
  range_frame: dict[str, float] | None = None             # latest TRACK_TAG in {0x74,0x94} frame (kinematics)
  meta_frames: dict[int, dict[str, float]] = field(default_factory=dict)  # latest frame per other tag
  # recovered_clobber: a range-carrier (0x74/0x94) frame was present but a meta frame arrived after it
  # (the exact window the old last-write-wins read would have mis-cleared)
  recovered_clobber: bool = False


class _SlotRangeKF:
  """R1: scalar 2-state CV Kalman filter, full P propagation (sweep dt jitters ~50-70 ms).

  Owns the S6 contracts: dt<=0 -> skip (no double-absorb), dt>VREL_DT_MAX -> in-place reseed,
  implied jump speed > VREL_MAX -> caller-visible BREAK (S1 incarnation bump). range_rate is
  published only after CONV_UPDATES measurements (S5: estimate vs measurement honesty).
  """
  __slots__ = ("r", "v", "a", "p00", "p01", "p11", "t", "n", "adapted")

  def __init__(self, r0: float, t_nanos: int):
    self._seed(r0, t_nanos)

  def _seed(self, r0: float, t_nanos: int):
    self.r = r0
    self.v = 0.0
    self.a = float('nan')
    self.p00 = BOSCH_RADAR_KF_R
    self.p01 = 0.0
    self.p11 = BOSCH_RADAR_KF_P0_V
    self.t = t_nanos
    self.n = 1
    # True when the LAST update() took an innovation-adaptive (maneuver/jump) step. The emit-time settle
    # gate treats such a step as instability and withholds the point until the track runs clean again.
    self.adapted = False

  @property
  def converged(self) -> bool:
    return self.n >= BOSCH_RADAR_KF_CONV_UPDATES

  def restitch(self, z: float, t_nanos: int):
    # S7: re-anchor the range at the successor slot's measurement (a re-slotted return often shifts the
    # reflection point slightly) while KEEPING the learned range-rate -- inheriting v is the entire point
    # of the stitch. Covariances restart at measurement level with a modest (not seed-huge) rate variance
    # so the following cycles refine v rather than re-learn it; `adapted` is cleared so the settle run
    # continues uninterrupted. n is kept: the filter stays converged across the stitch.
    self.r = z
    self.p00 = BOSCH_RADAR_KF_R
    self.p01 = 0.0
    self.p11 = max(self.p11, 4.0 * BOSCH_RADAR_KF_Q_V)  # rate uncertainty grew over the unobserved gap
    self.t = t_nanos
    self.adapted = False

  def update(self, z: float, t_nanos: int) -> int:
    dt = (t_nanos - self.t) * 1e-9
    if dt <= 0:
      return _KF_OK  # non-advancing clock: keep the posterior, never absorb the same instant twice
    if dt > BOSCH_RADAR_VREL_DT_MAX_S:
      self._seed(z, t_nanos)  # long gap: a stale state would alias into a spurious rate
      return _KF_RESEED
    if abs((z - self.r) / dt) > BOSCH_RADAR_VREL_MAX:
      return _KF_BREAK  # slot-reuse discontinuity; caller bumps incarnation and reseeds

    # predict
    self.adapted = False
    r_pred = self.r + self.v * dt
    q_v = BOSCH_RADAR_KF_Q_V * dt
    p00 = self.p00 + 2.0 * dt * self.p01 + dt * dt * self.p11 + BOSCH_RADAR_KF_Q_R * dt
    p01 = self.p01 + dt * self.p11
    p11 = self.p11 + q_v
    y = z - r_pred
    s = p00 + BOSCH_RADAR_KF_R
    if y * y / s > BOSCH_RADAR_KF_NIS_ADAPT:
      # innovation-adaptive Q: maneuver onset (e.g. lead brakes hard) -> trust the model less so the
      # rate snaps to the data instead of lagging optimistic
      self.adapted = True
      extra = BOSCH_RADAR_KF_Q_V * (BOSCH_RADAR_KF_NIS_INFLATE - 1.0) * dt
      p11 += extra
      p01 += extra * dt
      p00 += extra * dt * dt
      s = p00 + BOSCH_RADAR_KF_R

    k0 = p00 / s
    k1 = p01 / s
    v_prev = self.v
    self.r = r_pred + k0 * y
    self.v = self.v + k1 * y
    self.p00 = (1.0 - k0) * p00
    self.p01 = (1.0 - k0) * p01
    self.p11 = p11 - k1 * p01

    # packed aRel: EMA-smoothed posterior rate delta once converged (NaN before). Payoff needs the
    # radard-side consumer (K5); packed now so logs carry it.
    if self.n >= BOSCH_RADAR_KF_CONV_UPDATES:
      a_inst = (self.v - v_prev) / dt
      self.a = a_inst if math.isnan(self.a) else (1.0 - BOSCH_RADAR_ACCEL_EMA_ALPHA) * self.a + BOSCH_RADAR_ACCEL_EMA_ALPHA * a_inst
    self.t = t_nanos
    self.n += 1
    return _KF_OK


def _bosch_lat(dRel, cpt):
  # yRel = lateral projection of the polar (range, azimuth) measurement; see the LAT_SCALE block for the
  # field identity/scale/SIGN provenance (positive sign = radard's -lead.y convention; fixed 2026-07-06).
  # LAT_RAW is already offset-binary-centered per the DBC.
  az_deg = cpt['LAT_RAW'] * BOSCH_RADAR_LAT_SCALE_DEG_PER_LSB
  return dRel * sin(az_deg * pi / 180.0)


def _create_bosch_can_parser(CP):
  if Bus.radar not in DBC[CP.carFingerprint]:
    return None
  messages = [(m, 20) for m in BOSCH_RADAR_HDR_MSGS]
  return CANParser(DBC[CP.carFingerprint][Bus.radar], messages, CanBus(CP).camera)


def _create_bosch_selected_parser(CP):
  # SEPARATE parser for the SELECTED-lead coarse frame 0x2C8 (native Doppler telemetry). Kept isolated
  # from the fine-track parser so this RX-only telemetry NEVER affects the radar's can_valid / fault
  # logic: if 0x2C8 ever goes missing, only vRelNative degrades (to NaN), not the core radar health.
  if Bus.radar not in DBC[CP.carFingerprint]:
    return None
  return CANParser(DBC[CP.carFingerprint][Bus.radar], [(BOSCH_RADAR_SELECTED_MSG, 20)], CanBus(CP).camera)


def _create_bosch_sub_parser(CP):
  # S8: ISOLATED parser for the SUB2 sub-frames (OBJ_LIFE per-object identity counter). Kept separate from
  # the fine-track parser (exactly like _create_bosch_selected_parser) so this RX-only identity telemetry
  # can NEVER affect the radar's can_valid / fault logic: a missing SUB2 frame only makes OBJ_LIFE
  # unavailable for that slot (the stitch falls back to pure S7/S7b geometry), it never degrades health.
  if Bus.radar not in DBC[CP.carFingerprint]:
    return None
  return CANParser(DBC[CP.carFingerprint][Bus.radar], [(m, 20) for m in BOSCH_RADAR_SUB2_MSGS], CanBus(CP).camera)


class RadarInterface(RadarInterfaceBase):
  def __init__(self, CP, CP_SP):
    super().__init__(CP, CP_SP)
    self.track_id = 0
    self.radar_fault = False
    self.radar_wrong_config = False
    self.radar_off_can = CP.radarUnavailable

    # Bosch fine 0x280 track-table vs the legacy Nidec path. Keyed by fingerprint (the global Bosch "A"
    # set: Bosch minus radarless minus CAN FD) so this holds even when a bare CarParams is constructed
    # (e.g. unit tests that only set carFingerprint).
    self.bosch_radar = CP.carFingerprint in HONDA_BOSCH_A and (Bus.radar in DBC[CP.carFingerprint])

    # R1: per-SLOT [range, range_rate] KF (replaces the (last_dRel, nanos) derivative baseline).
    # NOTE: keyed by SLOT (0..5), not trackId. trackId now carries an incarnation (S1) so it changes on
    # every (re)birth; the kinematic state must persist across that change, hence the stable slot key.
    self._kf: dict[int, _SlotRangeKF] = {}
    # Phantom-brake fix: per-slot count of CONSECUTIVE clean KF updates (no birth/reseed/break/adapt).
    # The emit gate requires >= BOSCH_RADAR_SETTLE_CYCLES before a point's vRel is trusted; jumpy tracks
    # never settle and are suppressed (radard falls back to vision for that slot).
    self._settle: dict[int, int] = {}
    # D1: frames harvested from vl_all per rcp.update() batch (vl_all is wiped each call while
    # updated_messages accumulates until the trigger), demuxed by TRACK_TAG at emit time.
    self._pending: dict[int, list[dict[str, float]]] = {}
    self._clobber_recovered = 0  # emit windows where a meta frame would have mis-cleared a live track
    # S2 birth/persist hysteresis: slot index -> confidence counter (Toyota valid_cnt pattern).
    self._valid_cnt: dict[int, int] = {}
    # S1 trackId no-reuse: slot index -> current incarnation (bumped on (re)birth / slot-reuse break).
    self._incarnation: dict[int, int] = {}
    # S7: slot index -> the trackId the slot currently publishes under. Assigned at (re)birth: either a
    # fresh slot*STRIDE+incarnation id, or INHERITED from a stitched predecessor (same physical object
    # re-slotted, possibly from a DIFFERENT slot -- so the id is no longer derivable from (slot, inc)).
    self._tid: dict[int, int] = {}
    # S7: recently-deceased born tracks, stitchable by a re-slotted successor for STITCH_MAX_AGE_S.
    # Entries: {'tid','slot','kf','settle','valid_cnt','y'}; age is measured from kf.t (last measurement).
    self._graveyard: list[dict] = []
    # S7b: per-slot lateral position of the last valid frame (occupant-swap detection + stitch gating).
    self._last_y: dict[int, float] = {}
    # S8: per-slot OBJ_LIFE (the radar's per-object identity counter) of the slot's CURRENT tracked
    # occupant. Updated each cycle a slot is live (mirrors _last_y); read by the graveyard stitch to
    # corroborate / veto / recover identities. Only ever populated for slots with a live range-carrier.
    self._acc: dict[int, int] = {}
    # S3 CNTR-stall fault: last seen trigger-slot CNTR and how many cycles it has been frozen.
    self._last_cntr: int | None = None
    self._cntr_stall = 0
    # Parser-clock nanos of the last cycle the trigger header (sweep terminator 0x2DC) was emitted on;
    # -1 = never. Used by the staleness gate (compared against the parser's last-update clock). Tracked
    # here rather than reading rcp.ts_nanos so a frame at absolute t=0 (synthetic/replay start) isn't
    # mistaken for "never".
    self._last_trigger_nanos = -1

    if self.radar_off_can:
      self.rcp = None
      self.rcp_sel = None
      self.rcp_sub = None
      self.trigger_msg = 0x445
    elif self.bosch_radar:
      self.rcp = _create_bosch_can_parser(CP)
      # RX-only native-Doppler telemetry parser (0x2C8), isolated from self.rcp so it can never affect
      # the radar's can_valid / fault logic. See _create_bosch_selected_parser / vRelNative.
      self.rcp_sel = _create_bosch_selected_parser(CP)
      # S8 RX-only per-object identity parser (SUB2 OBJ_LIFE), likewise isolated from self.rcp so a
      # missing SUB2 frame never affects radar health -- it only makes the counter unavailable for that
      # slot (the stitch falls back to pure S7/S7b geometry). See _create_bosch_sub_parser.
      self.rcp_sub = _create_bosch_sub_parser(CP)
      # S4 sweep-coherent trigger: the radar emits a 6-slot sweep as a short burst on consecutive header
      # IDs, HEAD-first (0x280 leads, 0x2DC terminates -- confirmed across the bfcar capture: 234 sweeps,
      # 0x280->0x2DC intra-sweep span mean 8.4 ms / max 20.2 ms, well under the ~60 ms inter-sweep
      # cadence and the 150 ms STALE_S). Triggering on the HEAD (0x280) would emit a snapshot in which
      # slot 0 is from sweep N but slots 1..5 are still from sweep N-1 (a 1-sweep time skew, demonstrated
      # with a multi-slot replay). Trigger on the sweep TERMINATOR (0x2DC) instead -- like Toyota
      # (RADAR_B_MSGS[-1]) and Hyundai (0x51F) -- so the emit fires only after the whole sweep has
      # accumulated, giving a time-coherent snapshot. 0x2DC is as reliably present as 0x280 (also 234/234
      # bursts; the trigger keys on FRAME ARRIVAL, not payload validity, so it fires even when 0x2DC's
      # payload is a sentinel). The staleness gate (update()) and per-slot logic are otherwise unchanged.
      self.trigger_msg = 0x2DC
    else:
      self.rcp = _create_nidec_can_parser(CP.carFingerprint)
      self.rcp_sel = None
      self.rcp_sub = None
      self.trigger_msg = 0x445
    self.updated_messages = set()

  def update(self, can_strings):
    if self.radar_off_can or self.rcp is None:
      return super().update(None)

    vls = self.rcp.update(can_strings)
    self.updated_messages.update(vls)
    if self.bosch_radar:
      # D1: harvest NOW -- vl_all is cleared on the next rcp.update() call, but the emit window
      # (trigger-gated) can span several update batches.
      self._bosch_harvest_frames(vls)
      # RX-only: advance the isolated native-Doppler parser so vl[0x2C8] is fresh at emit time. Its
      # validity does NOT gate anything (a missing 0x2C8 only leaves vRelNative NaN).
      if self.rcp_sel is not None:
        self.rcp_sel.update(can_strings)
      # S8 RX-only: advance the isolated SUB2 parser so vl[OBJ_LIFE] is fresh at emit time. Its validity
      # does NOT gate anything (a missing SUB2 frame only makes the per-object counter unavailable, and
      # the stitch falls back to pure geometry).
      if self.rcp_sub is not None:
        self.rcp_sub.update(can_strings)

    if self.trigger_msg not in self.updated_messages:
      # Staleness fallback (Bosch fine only): the trigger header (sweep terminator 0x2DC) drives the
      # normal 20 Hz emit, but if it goes quiet while the parser keeps running we must still publish an
      # EMPTY RadarData so radard drops the stale lead (no frozen phantom). Compare the parser's
      # last-update clock to the last cycle the trigger was emitted -- both from the (replay-safe) clock.
      if self.bosch_radar and self.pts and self._last_trigger_nanos >= 0:
        now = self.rcp._last_update_nanos
        if (now - self._last_trigger_nanos) * 1e-9 > BOSCH_RADAR_STALE_S:
          return self._bosch_stale_radardata()
      return None

    rr = self._update(self.updated_messages)
    self.updated_messages.clear()
    return rr

  def _bosch_stale_radardata(self):
    # Clear all tracks + vRel history and return an EMPTY RadarData (NOT None) so liveTracks keeps
    # publishing at 20 Hz with zero points -> radard drops the lead within a cycle. Reset the trigger
    # clock so we emit the empty data exactly once until the trigger (0x2DC) returns.
    # S7: bury the live tracks first -- if the trigger returns inside the stitch window (a short bus
    # hiccup), the same physical objects resume under their prior identities instead of churning.
    for slot in list(self.pts):
      self._bosch_bury(slot)
    self.pts.clear()
    self._kf.clear()
    self._settle.clear()
    self._pending.clear()
    self._valid_cnt.clear()
    self._last_y.clear()
    self._acc.clear()
    # Do NOT reset _incarnation here: trackId no-reuse (S1) must hold across a staleness clear too, so a
    # slot that revives after going stale gets a fresh trackId rather than reusing the pre-stale one.
    self._last_trigger_nanos = -1
    self._last_cntr = None
    self._cntr_stall = 0
    stale = structs.RadarData()
    if not self.rcp.can_valid:
      stale.errors.canError = True
    stale.errors.radarUnavailableTemporary = True
    return stale

  def _bosch_trackid(self, slot):
    # S1 trackId no-reuse: slot index -> stable-but-unique id (slot*STRIDE + incarnation). The
    # incarnation is bumped on every (re)birth / slot-reuse break, so a slot that hands off from object A
    # to object B presents radard a DIFFERENT trackId (capnp car.capnp:314 "no trackId reuse").
    return slot * BOSCH_RADAR_TRACKID_STRIDE + self._incarnation.get(slot, 0)

  def _bosch_fresh_tid(self, slot):
    # S1: mint a brand-new trackId for a fresh occupant of this slot (no stitchable predecessor).
    self._incarnation[slot] = self._incarnation.get(slot, 0) + 1
    return self._bosch_trackid(slot)

  def _bosch_obj_life(self, slot):
    # S8: the slot's current SUB2 OBJ_LIFE (per-object identity counter) from the isolated parser, or 0
    # when unavailable (no SUB2 parser / unheard default). Callers only invoke this for slots with a live
    # range-carrier this cycle -- on an empty/sentinel slot OBJ_LIFE is a high rail, not a real id.
    if self.rcp_sub is None:
      return 0
    return int(self.rcp_sub.vl[BOSCH_RADAR_SUB2_MSGS[slot]]['OBJ_LIFE'])

  @staticmethod
  def _bosch_obj_life_continues(acc_old, acc_new, age_s):
    # S8: does OBJ_LIFE evolve from acc_old to acc_new like the SAME physical object over age_s seconds?
    # Returns True (continues), False (contradicts -> a DIFFERENT object), or None (either value
    # unavailable -> caller falls back to geometry). The counter is monotone (mod 2^16) and steps at most
    # STEP_MAX per sweep, so a same-object gap of n sweeps advances by delta in [1, STEP_MAX*n + MARGIN];
    # n is bounded above using the FASTEST plausible sweep cadence so a real continuation is never missed.
    # A different object's seed is thousands away (or the delta wraps to a huge value) -> rejected.
    # 0 is the isolated parser's unheard default -> unavailable (falsy guard).
    if not acc_old or not acc_new:
      return None
    n = max(1, int(math.ceil(age_s / BOSCH_RADAR_SWEEP_DT_MIN_S)))
    delta = (int(acc_new) - int(acc_old)) & 0xFFFF
    return 1 <= delta <= BOSCH_RADAR_OBJ_LIFE_STEP_MAX * n + BOSCH_RADAR_OBJ_LIFE_MARGIN

  def _bosch_bury(self, slot):
    # S7: copy a BORN track's identity + kinematics into the graveyard so a re-slotted successor can
    # inherit them. Non-destructive (the caller owns the slot's live state) and idempotent per tid.
    # Only born, converged tracks are worth stitching: an unborn sighting has no published identity or
    # trusted range-rate to preserve.
    kf = self._kf.get(slot)
    tid = self._tid.get(slot)
    if kf is None or tid is None or not kf.converged or self._valid_cnt.get(slot, 0) < BOSCH_RADAR_BORN_CYCLES:
      return
    if any(g['tid'] == tid for g in self._graveyard):
      return
    self._graveyard.append({'tid': tid, 'slot': slot, 'kf': kf,
                            'settle': self._settle.get(slot, 0),
                            'valid_cnt': self._valid_cnt.get(slot, 0),
                            'y': self._last_y.get(slot, float('nan')),
                            'acc': self._acc.get(slot)})  # S8: the departing occupant's OBJ_LIFE

  def _bosch_is_swap(self, slot, kf, dRel, y, now):
    # S7/S7b occupant-swap test (side-effect-free): the slot's new frame is a DIFFERENT object than its
    # current occupant if the implied range rate is unphysical (the classic BREAK) OR the lateral
    # position jumped far beyond physical sweep-to-sweep motion (same-range, different-lane swap that
    # range alone cannot see). Gates scale with range (azimuth noise grows with range).
    dt = (now - kf.t) * 1e-9
    if not (0.0 < dt <= BOSCH_RADAR_VREL_DT_MAX_S):
      return False
    if abs((dRel - kf.r) / dt) > BOSCH_RADAR_VREL_MAX:
      return True
    y_prev = self._last_y.get(slot)
    return (y_prev is not None and not math.isnan(y_prev)
            and abs(y - y_prev) > BOSCH_RADAR_Y_BREAK_BASE + BOSCH_RADAR_Y_BREAK_SCALE * dRel)

  def _bosch_stitch_pop(self, slot, dRel, now, exclude_tid=None, y=None, acc=None):
    # S7: find (and consume) the recently-deceased track whose PREDICTED range best matches the new
    # occupant of `slot`. Kills the donor slot's decaying leftover state on a cross-slot hit so the
    # object cannot double-emit from both its old and new slot.
    #
    # S8: the hardware per-object counter OBJ_LIFE (`acc`) is the PRIMARY identity key when available:
    #  - CONFIRMS a candidate whose counter continues (same object) and then RECOVERS it under a looser
    #    range gate -- a re-slotted object often shifts range/azimuth past the tight geometric gate while
    #    its counter continues exactly, so pure geometry would mint a churny fresh id.
    #  - VETOES a candidate whose counter CONTRADICTS (a different object) even if range/azimuth match.
    #  - falls back to the exact S7/S7b geometry (tight range + lateral) when the counter is unavailable.
    # Counter-confirmed candidates outrank geometry-only ones; ties break on range residual.
    y_gate = BOSCH_RADAR_STITCH_Y_GATE_BASE + BOSCH_RADAR_STITCH_Y_GATE_SCALE * dRel
    best = None
    best_score = None  # (rank, range_residual); rank 0 = counter-confirmed, 1 = geometry-only
    for g in self._graveyard:
      kf = g['kf']
      age_s = (now - kf.t) * 1e-9
      if not (0.0 <= age_s <= BOSCH_RADAR_STITCH_MAX_AGE_S) or g['tid'] == exclude_tid:
        continue
      res = abs(dRel - (kf.r + kf.v * age_s))
      life = self._bosch_obj_life_continues(g.get('acc'), acc, age_s)
      if life is False:
        continue  # S8 VETO: the counter says a DIFFERENT object -> never stitch, whatever the geometry
      if life is True:
        # S8 counter CONFIRMS: recover even past the tight geometry gate (looser range; lateral continuity
        # not required -- the counter is a stronger identity than azimuth), still bounded in range.
        if res > BOSCH_RADAR_STITCH_RANGE_GATE_LIFE:
          continue
        rank = 0
      else:
        # counter UNAVAILABLE -> unchanged S7/S7b geometry: tight range gate + lateral continuity.
        gy = g.get('y')
        if y is not None and gy is not None and not math.isnan(gy) and abs(y - gy) > y_gate:
          continue
        if res > BOSCH_RADAR_STITCH_RANGE_GATE:
          continue
        rank = 1
      score = (rank, res)
      if best_score is None or score < best_score:
        best, best_score = g, score
    if best is not None:
      self._graveyard.remove(best)
      donor = best['slot']
      if donor != slot and self._tid.get(donor) == best['tid']:
        # the S2 hysteresis keeps a decaying copy alive in the donor slot for a few cycles -- clear it
        self.pts.pop(donor, None)
        self._kf.pop(donor, None)
        self._settle.pop(donor, None)
        self._last_y.pop(donor, None)
        self._acc.pop(donor, None)
        self._valid_cnt[donor] = 0
    return best

  def _bosch_clear_slot(self, slot):
    # S2 persist hysteresis on an absent/sentinel/wrong-tag/out-of-band cycle: decay the per-slot
    # confidence counter by 1 (floored at 0). The point + vRel history are RETAINED while the counter is
    # still above 0 (tolerates a single missed cycle without dropping a real lead); they are only dropped
    # once the counter floors at 0 (two clean missed cycles from a born point). The incarnation is NOT
    # touched here; it is bumped at (re)birth so the NEXT object to occupy this slot gets a fresh trackId.
    # pts/_hist are keyed by SLOT internally; the wire trackId lives on the point object's .trackId field.
    self._bosch_bury(slot)  # S7: first absent/sentinel cycle copies a born track to the graveyard
    cnt = max(self._valid_cnt.get(slot, 0) - 1, 0)
    self._valid_cnt[slot] = cnt
    if cnt == 0:
      self.pts.pop(slot, None)
      self._kf.pop(slot, None)
      self._settle.pop(slot, None)
      self._last_y.pop(slot, None)
      self._acc.pop(slot, None)

  def _bosch_harvest_frames(self, updated_addrs):
    # D1: explode this batch's vl_all (per-signal aligned lists, one entry per parsed frame) into
    # per-slot frame dicts, in arrival order. Stateless per emit window: drained by _update_bosch.
    for ii in updated_addrs:
      if ii not in BOSCH_RADAR_HDR_MSGS:
        continue
      vl_all = self.rcp.vl_all[ii]
      names = list(vl_all)
      if not names or not vl_all[names[0]]:
        continue
      bucket = self._pending.setdefault(BOSCH_RADAR_HDR_MSGS.index(ii), [])
      for f in range(len(vl_all[names[0]])):
        bucket.append({name: vl_all[name][f] for name in names})
      del bucket[:-BOSCH_RADAR_PENDING_CAP]

  def _bosch_assemble_record(self, slot) -> BoschTrackRecord:
    # D1: demux the window's harvested frames by TRACK_TAG. The LAST frame in BOSCH_RADAR_HDR_TAG_SET
    # (0x74 moving OR 0x94 stationary) carries the freshest kinematics; both use the SAME byte layout.
    # Non-range-carrier frames are retained as metadata (sub-frame decode is D2's RE campaign).
    # 73z fix: 0x94 (stationary motion class) is now classified as a range_frame, NOT a meta_frame,
    # so a stopped/decelerating lead's range carrier is no longer dropped during stops.
    rec = BoschTrackRecord(slot)
    for fr in self._pending.get(slot, ()):
      if int(fr['TRACK_TAG']) in BOSCH_RADAR_HDR_TAG_SET:
        rec.range_frame = fr
        rec.recovered_clobber = False
      else:
        rec.meta_frames[int(fr['TRACK_TAG'])] = fr
        if rec.range_frame is not None:
          rec.recovered_clobber = True  # old last-write-wins read would have seen only this meta frame
    return rec

  def _update_bosch(self, updated_messages):
    # FINE per-track object table (0x280 block). Fixed slot map (0x280->slot0, 0x284->slot1, 0x288->slot2,
    # 0x28C->slot3, 0x2D0->slot4, 0x2D4->slot5, 0x2D8->slot6, 0x2DC->slot7); see BOSCH_RADAR_HDR_MSGS.
    # RX-parse only; never takes 0x1DF / longitudinal authority, so factory AEB/CMBS stays fully live.
    # Up to 8 RadarPoints are emitted; radard selects leadOne/leadTwo (we do NOT select in advance).
    #
    # trackId is slot*STRIDE + incarnation (S1, no-reuse). vRel is NOT published on these frames (rlog-
    # confirmed b4:b5 is azimuth, not range-rate), so it is DERIVED per-SLOT as d(dRel)/dt across cycles
    # (per-slot history below). yRel is the trig projection of (dRel, azimuth) -- b4:b5 = azimuth, scale
    # rlog-regressed to ~0.001 deg/LSB (MEDIUM on the exact value, HIGH on the identity; absolute
    # boresight zero still unpinned). Range scale/offset live in the DBC.
    ret = structs.RadarData()
    if not self.rcp.can_valid:
      ret.errors.canError = True

    # Clock from the CANParser frame timestamps (replay-safe: advances with rlog/replay time, not wall
    # clock). Used for the per-track vRel dt. The hard staleness gate (trigger 0x2DC stops arriving) lives
    # in update() above; here we only handle per-slot presence/sentinel within an emit cycle.
    now = self.rcp._last_update_nanos
    # This method only runs when the trigger header (sweep terminator 0x2DC) was present this cycle -> mark
    # it seen so the staleness fallback in update() can detect when the trigger later goes quiet.
    self._last_trigger_nanos = now

    # S7: expire graveyard entries past the stitch window (age measured from the last real measurement).
    self._graveyard = [g for g in self._graveyard if (now - g['kf'].t) * 1e-9 <= BOSCH_RADAR_STITCH_MAX_AGE_S]

    # S3(b) CNTR-stall plausibility: track the trigger slot's CNTR. If it freezes while can_valid the
    # source is present-but-frozen -> radarFault. The trigger (0x2DC) is guaranteed present this cycle (it
    # is what gated us into _update_bosch), and every header carries the same 8-bit CNTR (DBC bit 63).
    trig_cpt = self.rcp.vl[self.trigger_msg]
    cur_cntr = int(trig_cpt['CNTR'])
    if self._last_cntr is not None and cur_cntr == self._last_cntr:
      self._cntr_stall += 1
    else:
      self._cntr_stall = 0
    self._last_cntr = cur_cntr
    if self.rcp.can_valid and self._cntr_stall >= BOSCH_RADAR_CNTR_STALL_CYCLES:
      ret.errors.radarFault = True

    # ---- S7 pass A: classify every slot and bury displaced/vanished occupants TABLE-WIDE first. ----
    # The radar keeps the fine table ~sorted by range (nearest object = slot 0), so a single object
    # appearing/disappearing near the front shifts EVERY track a slot in the SAME sweep. A stitch lookup
    # in ascending slot order would then always run before its donor slot's burial (the donor sits one
    # slot HIGHER); burials must therefore complete for the whole table before any stitch is attempted.
    live_frames: dict[int, dict[str, float]] = {}
    for ii in BOSCH_RADAR_HDR_MSGS:
      slot = BOSCH_RADAR_HDR_MSGS.index(ii)

      # Stale-track aging: a header absent this trigger cycle is not a live track -> decay confidence and
      # drop the point/history so a long-absent slot cannot linger as a frozen point (S2 tolerates a
      # single missed cycle: the point is only fully dropped once the counter floors at 0).
      if ii not in updated_messages:
        self._bosch_clear_slot(slot)
        continue

      # D1: tag-demux over ALL frames this window (vl is last-write-wins; a metadata sub-frame landing
      # after a range-carrier (0x74/0x94) used to mis-clear a LIVE track here). Only a window with NO
      # range-carrier at all is a genuine miss.
      rec = self._bosch_assemble_record(slot)
      if rec.recovered_clobber:
        self._clobber_recovered += 1
      cpt = rec.range_frame
      if cpt is None:
        self._bosch_clear_slot(slot)
        continue

      # Sentinel skip (broadened): idle strength, unset range, or saturation rail -> not an active track.
      range_raw = int(cpt['RANGE_RAW'])
      if (int(cpt['STRENGTH']) == BOSCH_RADAR_STRENGTH_IDLE
          or range_raw == BOSCH_RADAR_RAW_UNSET
          or range_raw >= BOSCH_RADAR_RAW_SAT):
        self._bosch_clear_slot(slot)
        continue

      dRel = cpt['RANGE']  # meters, DBC-scaled (0.00357*raw - 3.0). Calibrated cross-car.

      # S3(a) plausibility: a tag-passing, non-sentinel frame whose decoded dRel lands outside the
      # physical band is a decode/scale inconsistency, not a real object -> flag wrongConfig and skip the
      # point (do NOT emit a bad lead). RX-only error annotation; no authority change.
      if not (BOSCH_RADAR_RANGE_MIN <= dRel <= BOSCH_RADAR_RANGE_MAX):
        ret.errors.wrongConfig = True
        self._bosch_clear_slot(slot)
        continue

      # S7 pre-burial: this slot's occupant is about to be displaced by a DIFFERENT object -- the same
      # range-discontinuity test the KF's BREAK uses, OR an occupant swap visible only in azimuth (S7b).
      # Side-effect-free here -> bury it now so ANY slot's stitch in pass B can find it, regardless of
      # slot order.
      kf = self._kf.get(slot)
      if kf is not None and self._bosch_is_swap(slot, kf, dRel, _bosch_lat(dRel, cpt), now):
        self._bosch_bury(slot)
      live_frames[slot] = cpt

    # ---- pass B: birth/stitch/KF-update/emit per live slot ----------------------------------------
    for slot, cpt in live_frames.items():
      dRel = cpt['RANGE']
      # S7b: this frame's lateral position, computed up front for swap detection + stitch gating (it is
      # also the yRel published at emission below).
      yRel = _bosch_lat(dRel, cpt)
      # S8: this live frame's OBJ_LIFE (the radar's per-object identity counter). Threaded into the
      # graveyard stitch (corroborate/veto/recover) and stored as this slot's occupant id below.
      new_acc = self._bosch_obj_life(slot)

      # S1 (re)birth detection: a slot whose confidence counter was floored at 0 BEFORE this cycle is a
      # fresh occupant -> bump its incarnation so the trackId it will be published under does not reuse
      # the prior occupant's, and clear its vRel baseline so the first derived sample is clean. Detect
      # rebirth on the 0->1 confidence transition (first SIGHTING), NOT on point absence -- with S2 a slot
      # is sighted for BORN_CYCLES-1 cycles before it is ever published, so point-absence would mis-fire.
      was_vacant = self._valid_cnt.get(slot, 0) == 0
      if was_vacant:
        st = self._bosch_stitch_pop(slot, dRel, now, y=yRel, acc=new_acc)
        if st is not None:
          # S7 stitch: same physical object re-slotted -- inherit its trackId, KF (learned range-rate),
          # confidence and settle run, so it keeps emitting under the same identity with no born/settle
          # hole and radard's tracker never resets.
          self._tid[slot] = st['tid']
          kf_in = st['kf']
          kf_in.restitch(dRel, now)
          self._kf[slot] = kf_in
          self._settle[slot] = st['settle']
          self._valid_cnt[slot] = st['valid_cnt']
        else:
          self._tid[slot] = self._bosch_fresh_tid(slot)
          self._kf.pop(slot, None)
      elif self._graveyard:
        # S7: the slot's own object is still live (S2 flicker tolerance) -- invalidate any graveyard copy
        # made on an absent cycle so it cannot be stitched onto a different slot while alive here.
        tid = self._tid.get(slot)
        self._graveyard = [g for g in self._graveyard if g['tid'] != tid]

      # S2 birth/persist hysteresis: this is a valid range-carrier frame -> +1 (saturating). A point is
      # only emitted once the counter reaches BORN_CYCLES (debounces a 1-frame glitch into a phantom).
      self._valid_cnt[slot] = min(self._valid_cnt.get(slot, 0) + 1, BOSCH_RADAR_VALID_CAP)

      # R1: per-slot [range, range_rate] KF on the raw range (replaces d(dRel)/dt + EMA). The filter
      # owns the S6 contracts (dt<=0 skip, long-gap reseed); the BREAK return keeps the S1 slot-reuse
      # semantics: bump the incarnation so radard sees a NEW trackId, drop the stale point so it is
      # re-created under that id this cycle, and reseed the filter at the new object's range.
      # S7b: an occupant swap that only shows in AZIMUTH (same-range, different lane) must be treated
      # exactly like a range BREAK -- and must NOT be absorbed by the old occupant's KF.
      kf = self._kf.get(slot)
      if kf is None:
        kf = self._kf[slot] = _SlotRangeKF(dRel, now)
        self._settle[slot] = 0  # fresh filter: re-accumulate clean cycles before vRel is trusted
      else:
        status = _KF_BREAK if self._bosch_is_swap(slot, kf, dRel, yRel, now) else kf.update(dRel, now)
        if status == _KF_BREAK:
          # S7: the displaced occupant may re-slot elsewhere -> bury it (before dropping its point).
          # The NEW occupant may itself be a stitchable refugee from another slot -- but never from the
          # occupant it just displaced (exclude_tid), which is a different object by definition of BREAK.
          self._bosch_bury(slot)
          old_tid = self._tid.get(slot)
          self.pts.pop(slot, None)
          st = self._bosch_stitch_pop(slot, dRel, now, exclude_tid=old_tid, y=yRel, acc=new_acc)
          if st is not None:
            self._tid[slot] = st['tid']
            kf = st['kf']
            kf.restitch(dRel, now)
            self._kf[slot] = kf
            self._settle[slot] = st['settle']
            self._valid_cnt[slot] = min(st['valid_cnt'] + 1, BOSCH_RADAR_VALID_CAP)
          else:
            self._tid[slot] = self._bosch_fresh_tid(slot)
            kf = self._kf[slot] = _SlotRangeKF(dRel, now)
            self._settle[slot] = 0  # slot-reuse discontinuity: restart the settle run
        elif status == _KF_RESEED:
          self._settle[slot] = 0  # long-gap reseed: stale -> fresh, vRel not yet trustworthy
        elif kf.adapted:
          # Innovation/maneuver step. For a YOUNG track this is churn -> withhold until it runs clean
          # (settle=0, the validated phantom protection). For a MATURE track (a long clean run behind it)
          # a single adaptive step is a real maneuver (e.g. the lead starts braking) -- zeroing would
          # blank the point for SETTLE_CYCLES sweeps exactly when the planner most needs it (and re-blank
          # it on every subsequent adaptive step of the same braking event). Decay to SETTLE_CYCLES
          # instead: the base (soft-|vRel|) band keeps emitting, while the graduated high-|vRel| bands
          # (SETTLE_MID/HIGH) still see a fresh run and keep their protection.
          mature = self._settle.get(slot, 0) >= BOSCH_RADAR_SETTLE_MATURE
          self._settle[slot] = BOSCH_RADAR_SETTLE_CYCLES if mature else 0
        else:
          self._settle[slot] = self._settle.get(slot, 0) + 1
      # S5: range_rate is an estimate until the filter has absorbed enough measurements -> NaN before
      vRel = kf.v if kf.converged else float('nan')

      # S7b: record this frame's lateral position for next cycle's swap test + burial (also when the
      # point is withheld below -- the slot's occupant was still SEEN here).
      self._last_y[slot] = yRel
      # S8: record this frame's OBJ_LIFE as this slot's current-occupant id (mirrors _last_y). Read by a
      # later cycle's graveyard stitch to match this object if it re-slots / drops out and returns.
      self._acc[slot] = new_acc

      # S2 gate: do not emit until the slot is confidently born.
      if self._valid_cnt[slot] < BOSCH_RADAR_BORN_CYCLES:
        # Not yet confident enough to publish; keep accumulating. Drop any stale point (there should be
        # none pre-birth) but retain the counter + baseline so the next valid cycle can promote it.
        self.pts.pop(slot, None)
        continue

      # Phantom-brake fix (lean-on-vision): only publish a point whose vRel is trustworthy. Require the KF
      # converged, |vRel| below the hard physical ceiling, and GRADUATED PERSISTENCE -- the higher the claimed
      # closing speed, the more consecutive clean cycles (no birth/reseed/break/maneuver) the slot must have
      # run before we trust it. A real fast closer (a stopped car you're approaching) persists and earns it; a
      # short-lived phantom never does. Otherwise DROP the point this cycle so radard falls back to the VISION
      # lead -- replay of route 0543acc22b traced the phantom braking to exactly these untrusted samples.
      absv = abs(vRel)
      if absv <= BOSCH_RADAR_VREL_SOFT:
        settle_req = BOSCH_RADAR_SETTLE_CYCLES
      elif absv <= BOSCH_RADAR_VREL_MID:
        settle_req = BOSCH_RADAR_SETTLE_MID
      else:
        settle_req = BOSCH_RADAR_SETTLE_HIGH
      vrel_ok = kf.converged and absv <= BOSCH_RADAR_VREL_HARD_MAX
      if self._settle.get(slot, 0) < settle_req or not vrel_ok:
        self.pts.pop(slot, None)
        continue

      if slot not in self.pts:
        self.pts[slot] = structs.RadarData.RadarPoint()
        # S7: publish under the slot's ASSIGNED id (inherited on a stitch, fresh otherwise) -- no longer
        # always derivable from (slot, incarnation).
        self.pts[slot].trackId = self._tid.get(slot, self._bosch_trackid(slot))
        self.pts[slot].yvRel = float('nan')
        self.pts[slot].vRelNative = float('nan')  # set on slot 0 below when a native Doppler is available

      self.pts[slot].dRel = dRel
      # yRel = lateral projection of the polar (range, azimuth) measurement (precomputed above via
      # _bosch_lat). b4:b5 is AZIMUTH ANGLE (offset-binary, center 0x8000), settled by the 2026-06-08
      # three-source rlog regression (see the LAT_SCALE block above); LAT_RAW is already (b4b5 - 0x8000)
      # per the DBC offset. left-positive: right-of-center (LAT_RAW > 0) -> negative yRel (rlog-confirmed
      # sign). Scale MEDIUM confidence; field identity HIGH.
      self.pts[slot].yRel = yRel
      self.pts[slot].vRel = vRel
      # R1: pack the KF's smoothed range-accel into aRel (NaN until the filter is converged AND has a
      # rate history). RX-only telemetry; the radard-side consumer is K5 (deferred).
      self.pts[slot].aRel = kf.a
      # S5 honest measured flag: vRel is a DERIVED estimate, so flag the point as an estimate (measured=
      # False) whenever vRel is not yet a valid derived value (first-sight/re-seed NaN). dRel/yRel are
      # real measurements, but the capnp measured bit is about point-as-measurement-vs-estimate, and our
      # headline kinematic (vRel) is derived -- True only once a stable derived vRel exists.
      self.pts[slot].measured = not math.isnan(vRel)

    # Native Doppler exposure (RX-only telemetry; does NOT change vRel/control). Attach the radar's
    # SELECTED-lead published REL_SPEED (a REAL Doppler) to slot 0's point (the selected lead ~ slot 0,
    # r=0.84; see the BOSCH_RADAR_SELECTED_MSG block). Gated by a calibration-free velocity-agreement
    # check so a differently-selected object is not mislabeled. Consumers (radard) fuse it with vision.
    self._bosch_attach_native_doppler()

    # D1: the emit window is consumed; the next window's frames are harvested fresh from vl_all.
    self._pending.clear()
    ret.points = list(self.pts.values())
    return ret

  def _bosch_attach_native_doppler(self):
    # Set slot 0's vRelNative from 0x2C8 REL_SPEED (the radar's native selected-lead Doppler). RX-only:
    # never touches vRel/dRel/yRel, so control is unchanged until a consumer opts in. NaN stays on the
    # point (set at creation) when there is no valid, associated selected lead this cycle.
    p0 = self.pts.get(0)
    if p0 is None or self.rcp_sel is None:
      return
    sel = self.rcp_sel.vl[BOSCH_RADAR_SELECTED_MSG]  # subscribed -> always present (defaults if unheard)
    sel_raw = int(sel['SEL_RANGE'])
    if (int(sel['SEL_STRENGTH']) in BOSCH_RADAR_SEL_STRENGTH_IDLE
        or sel_raw == BOSCH_RADAR_SEL_RANGE_UNSET or sel_raw >= BOSCH_RADAR_SEL_RANGE_SAT):
      return  # no selected lead this cycle
    rel_speed = sel['REL_SPEED']  # native Doppler, m/s (DBC-scaled; zero near raw 124, coarse scale)
    # Calibration-free association: the native Doppler must agree with slot 0's DERIVED vRel (same
    # object). Rejects the case where the radar selected a DIFFERENT object than slot 0 (and the
    # pre-convergence NaN vRel). The small (1-4 m/s) disagreements that matter for false-closing pass.
    if math.isnan(p0.vRel) or abs(rel_speed - p0.vRel) > BOSCH_RADAR_SEL_VREL_AGREE:
      return
    p0.vRelNative = rel_speed

  def _update(self, updated_messages):
    # Bosch fine 0x280 track-table radars use the dedicated parser path; dispatch here so the single
    # entry point (and the generic radar test that calls _update(trigger_msg)) works for both radars.
    if self.bosch_radar:
      return self._update_bosch(updated_messages)

    ret = structs.RadarData()

    for ii in sorted(updated_messages):
      cpt = self.rcp.vl[ii]
      if ii == 0x400:
        # check for radar faults
        self.radar_fault = cpt['RADAR_STATE'] != 0x79
        self.radar_wrong_config = cpt['RADAR_STATE'] == 0x69
      elif cpt['LONG_DIST'] < 255:
        if ii not in self.pts or cpt['NEW_TRACK']:
          self.pts[ii] = structs.RadarData.RadarPoint()
          self.pts[ii].trackId = self.track_id
          self.track_id += 1
        self.pts[ii].dRel = cpt['LONG_DIST']  # from front of car
        self.pts[ii].yRel = -cpt['LAT_DIST']  # in car frame's y axis, left is positive
        self.pts[ii].vRel = cpt['REL_SPEED']
        self.pts[ii].aRel = float('nan')
        self.pts[ii].yvRel = float('nan')
        self.pts[ii].measured = True
      else:
        if ii in self.pts:
          del self.pts[ii]

    if not self.rcp.can_valid:
      ret.errors.canError = True
    if self.radar_fault:
      ret.errors.radarFault = True
    if self.radar_wrong_config:
      ret.errors.wrongConfig = True

    ret.points = list(self.pts.values())

    return ret
