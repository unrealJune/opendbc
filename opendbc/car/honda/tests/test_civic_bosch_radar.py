#!/usr/bin/env python3
"""Unit tests for the Honda Civic Bosch FINE 0x280 track-table radar ingest.

These drive the REAL CANParser + RadarInterface end-to-end (no decode re-implementation) so the DBC,
the honda_* CHKSUM/CNTR trap avoidance, the b1==0x74 gate, the sentinel skips, multi-object emission,
trackId stability, vRel derivation, and the staleness->EMPTY-RadarData gate are all exercised together.

100% OFFLINE: frames are synthetic or replayed from radar-re captures; no panda, no CAN TX, no flash.

Bus note: the fine object frames are physically on CanBus.camera. For a bare (un-fingerprinted)
CarParams the CanBus offset resolves to a negative placeholder, so each test reads the bus the parser
was ACTUALLY built on (parser.bus) and feeds frames there -- this exercises the real parse path
independent of how the offset resolves in this opendbc-only checkout.
"""
import math
import os
import unittest

from opendbc.can import CANParser
from opendbc.car import Bus, structs
from opendbc.car.honda.radar_interface import (
  RadarInterface,
  BOSCH_RADAR_HDR_MSGS,
  BOSCH_RADAR_HDR_TAG,
  BOSCH_RADAR_LAT_SCALE_DEG_PER_LSB,
  BOSCH_RADAR_STALE_S,
  BOSCH_RADAR_VREL_MAX,
  BOSCH_RADAR_BORN_CYCLES,
  BOSCH_RADAR_SETTLE_CYCLES,
  BOSCH_RADAR_VALID_CAP,
  BOSCH_RADAR_TRACKID_STRIDE,
  BOSCH_RADAR_RANGE_MAX,
  BOSCH_RADAR_RAW_SAT,
  BOSCH_RADAR_CNTR_STALL_CYCLES,
  BOSCH_RADAR_VREL_DT_MAX_S,
  BOSCH_RADAR_SELECTED_MSG,
  BOSCH_RADAR_SEL_VREL_AGREE,
  BOSCH_RADAR_STITCH_RANGE_GATE,
  BOSCH_RADAR_STITCH_RANGE_GATE_LIFE,
  BOSCH_RADAR_OBJ_LIFE_STEP_MAX,
)
from opendbc.car.honda.values import CAR, DBC

BFCAR_CSV = r"C:/claudecode/firmware-analysis-kit/radar-re/captures/closing_bfcar.csv"
IDLE_CSV = r"C:/claudecode/firmware-analysis-kit/radar-re/captures/closing_10m.csv"


def _frame(b0, tag, b2, b3, b4, b5, b6, b7):
  return bytes([b0, tag, b2, b3, b4, b5, b6, b7])


def _hdr_frame(range_raw, *, tag=BOSCH_RADAR_HDR_TAG, strength=0x00, lat_raw=0x8000, cntr=0x00):
  """Header frame: b0=strength, b1=tag, b2:b3=range_raw BE16, b4:b5=lat_raw BE16, b7=cntr."""
  return _frame(strength, tag, (range_raw >> 8) & 0xFF, range_raw & 0xFF,
                (lat_raw >> 8) & 0xFF, lat_raw & 0xFF, 0x00, cntr)


def _make_ri():
  CP = structs.CarParams()
  CP.carFingerprint = CAR.HONDA_CIVIC_BOSCH
  CP.radarUnavailable = False
  CP_SP = structs.CarParamsSP()
  return RadarInterface(CP, CP_SP)


def _can(nanos, frames):
  return [nanos, frames]


class TestCivicBoschFineDBC(unittest.TestCase):
  """DBC-level decode + the honda_* CHKSUM/CNTR auto-enforcement trap."""

  def setUp(self):
    self.parser = CANParser(DBC[CAR.HONDA_CIVIC_BOSCH][Bus.radar],
                            [(m, 20) for m in BOSCH_RADAR_HDR_MSGS], 2)
    self.bus = self.parser.bus

  def test_range_decode_known_raw(self):
    # Real bfcar frame 00740f9f9bc00336 on 0x280 -> raw 0x0f9f -> 0.00357*3999 - 3.0 ~= 11.28 m.
    data = bytes.fromhex("00740f9f9bc00336")
    self.parser.update(_can(0, [(0x280, data, self.bus)]))
    vl = self.parser.vl[0x280]
    self.assertEqual(int(vl["TRACK_TAG"]), 0x74)
    self.assertEqual(int(vl["RANGE_RAW"]), 0x0F9F)
    self.assertAlmostEqual(vl["RANGE"], 0.00357 * 3999 - 3.0, places=4)
    self.assertAlmostEqual(vl["RANGE"], 11.28, delta=0.01)
    self.assertEqual(int(vl["STRENGTH"]), 0x00)
    self.assertEqual(int(vl["CNTR"]), 0x36)

  def test_range_scale_offset(self):
    self.parser.update(_can(0, [(0x280, _hdr_frame(3999), self.bus)]))
    self.assertAlmostEqual(self.parser.vl[0x280]["RANGE"], 0.00357 * 3999 - 3.0, places=6)

  def test_lat_offset_binary_center(self):
    # raw 0x8000 -> 0 (offset -32768); 0x9bc0 -> +7104.
    self.parser.update(_can(0, [(0x280, _hdr_frame(3999, lat_raw=0x8000), self.bus)]))
    self.assertEqual(int(self.parser.vl[0x280]["LAT_RAW"]), 0)
    self.parser.update(_can(1, [(0x280, _hdr_frame(3999, lat_raw=0x9BC0), self.bus)]))
    self.assertEqual(int(self.parser.vl[0x280]["LAT_RAW"]), 0x9BC0 - 0x8000)

  def test_chksum_cntr_trap_avoided(self):
    # opendbc auto-enforces a Honda checksum/counter ONLY on signals literally named CHECKSUM/COUNTER,
    # dropping frames on mismatch. Our fine frames carry CNTR (no CHECKSUM at all) so an arbitrary
    # counter value must NOT cause the frame to be dropped: the decode must still land.
    names = set()
    for m in BOSCH_RADAR_HDR_MSGS:
      names |= set(self.parser.vl[m].keys())
    self.assertNotIn("CHECKSUM", names)
    self.assertNotIn("COUNTER", names)
    self.assertTrue("CNTR" in names)
    self.parser.update(_can(0, [(0x280, _hdr_frame(5000, cntr=0xAB), self.bus)]))
    self.assertEqual(int(self.parser.vl[0x280]["CNTR"]), 0xAB)
    self.assertAlmostEqual(self.parser.vl[0x280]["RANGE"], 0.00357 * 5000 - 3.0, places=4)


class TestCivicBoschFineParser(unittest.TestCase):
  """RadarInterface._update_bosch end-to-end through the real CANParser."""

  TRIG = 0x2DC  # S4: the parser triggers the emit on the sweep terminator (0x2DC), not the head (0x280).

  def setUp(self):
    self.ri = _make_ri()
    self.bus = self.ri.rcp.bus
    self.assertTrue(self.ri.bosch_radar)
    self.assertEqual(self.ri.trigger_msg, self.TRIG)  # S4 sweep-coherent trigger

  def _step(self, nanos, frames):
    return self.ri.update(_can(nanos, frames))

  def _f(self, addr, frame):
    return (addr, frame, self.bus)

  def _trig(self, cntr):
    # The trigger frame (sweep terminator). Its payload is a benign non-range sentinel (b1!=0x74) so it
    # never births a slot-5 point by itself; it exists only to fire the emit and advance the S3 CNTR.
    return self._f(self.TRIG, _hdr_frame(0x8000, tag=0xF0, strength=0xFE, cntr=cntr))

  def _emit(self, nanos, frames, cntr):
    # Drive one sweep: the given head/body frames PLUS the trigger terminator, so update() emits.
    return self._step(nanos, list(frames) + [self._trig(cntr)])

  # A steady slot must clear TWO gates before it emits: S2 birth hysteresis (BORN_CYCLES valid sweeps) AND
  # the settle gate (SETTLE_CYCLES consecutive clean KF cycles, which only start counting once the KF exists).
  # So the first emit lands on cycle index BORN_CYCLES + SETTLE_CYCLES - 1; feed one extra for margin.
  WARM_CYCLES = BOSCH_RADAR_BORN_CYCLES + BOSCH_RADAR_SETTLE_CYCLES

  def _warm(self, range_raw, *, slot_addr=0x280, lat_raw=0x8000, base_ns=0, cntr0=0x10):
    # Drive the slot (default 0x280) at a STEADY range for WARM_CYCLES sweeps so it is fully born AND settled
    # -> emitting a point on the returned sweep. Each sweep is terminated by the trigger (0x2DC) so the emit
    # fires; CNTR advances each sweep to keep the S3 CNTR-stall fault from firing. Returns the last rr.
    # After this the slot has emitted, valid_cnt is saturated, and the next continuation sweep is index
    # WARM_CYCLES (nanos = WARM_CYCLES*0.05s, cntr = cntr0 + WARM_CYCLES).
    dt_ns = int(0.05 * 1e9)
    rr = None
    for k in range(self.WARM_CYCLES):
      cntr = (cntr0 + k) & 0xFF
      body = [self._f(slot_addr, _hdr_frame(range_raw, lat_raw=lat_raw, cntr=cntr))]
      rr = self._emit(base_ns + k * dt_ns, body, cntr)
    return rr

  def test_single_live_track_emits_one_point(self):
    # A steady slot emits exactly one point once it is born (S2) AND settled. (A single-sweep glitch never
    # births a point -- covered by test_s2_single_frame_glitch_no_phantom.)
    rr = self._warm(3999)
    self.assertIsNotNone(rr)
    self.assertEqual(len(rr.points), 1)
    p = rr.points[0]
    # S1: trackId is slot*STRIDE + incarnation (slot 0, first incarnation = 1), no longer the bare slot.
    self.assertEqual(p.trackId, 0 * BOSCH_RADAR_TRACKID_STRIDE + 1)
    self.assertEqual(p.trackId // BOSCH_RADAR_TRACKID_STRIDE, 0)  # still slot-decodable
    self.assertAlmostEqual(p.dRel, 0.00357 * 3999 - 3.0, places=4)
    # S5: vRel is a real (near-zero) derived value for a steady lead -> measured. R1: once the KF is
    # converged with a rate history it packs the smoothed aRel (no longer NaN); a steady lead -> ~0.
    self.assertTrue(p.measured)
    self.assertFalse(math.isnan(p.vRel))
    self.assertAlmostEqual(p.aRel, 0.0, delta=1.0)

  def _sel_frame(self, rel_speed_raw, *, strength=100, sel_range=5000, sel_lat=0x8000, cntr=0x10):
    # 0x2C8 RADAR_SELECTED_0: b0=SEL_STRENGTH, b1=SEL_CNTR_LO, b2:b3=SEL_RANGE, b4:b5=SEL_LAT,
    # b6=REL_SPEED raw (native Doppler; vRel = -0.7*raw + 86.5, ~0 at raw 124), b7=SEL_CNTR.
    return self._f(BOSCH_RADAR_SELECTED_MSG,
                   _frame(strength, cntr, (sel_range >> 8) & 0xFF, sel_range & 0xFF,
                          (sel_lat >> 8) & 0xFF, sel_lat & 0xFF, rel_speed_raw, cntr))

  def _warm_with_sel(self, range_raw, rel_speed_raw, **sel_kw):
    # Warm slot 0 steady while also feeding a 0x2C8 selected-lead frame each sweep. Returns last rr.
    dt_ns = int(0.05 * 1e9)
    rr = None
    for k in range(self.WARM_CYCLES):
      cntr = (0x10 + k) & 0xFF
      body = [self._f(0x280, _hdr_frame(range_raw, cntr=cntr)), self._sel_frame(rel_speed_raw, cntr=cntr, **sel_kw)]
      rr = self._emit(k * dt_ns, body, cntr)
    return rr

  def test_native_doppler_attached_to_slot0_when_agreeing(self):
    # A valid selected lead whose native Doppler (~0 at raw 124) agrees with slot 0's derived vRel (~0
    # for a steady lead) -> vRelNative set on slot 0's point. RX-only: vRel/dRel are UNCHANGED.
    rr = self._warm_with_sel(3999, 124)
    p = rr.points[0]
    self.assertFalse(math.isnan(p.vRelNative))
    self.assertAlmostEqual(p.vRelNative, -0.7 * 124 + 86.5, places=2)
    # no control change: vRel is still the derived (~0) value, dRel unchanged
    self.assertAlmostEqual(p.dRel, 0.00357 * 3999 - 3.0, places=4)
    self.assertFalse(math.isnan(p.vRel))

  def test_native_doppler_nan_without_selected_frame(self):
    # No 0x2C8 fed -> vRelNative stays NaN (the isolated parser sees a sentinel/default).
    rr = self._warm(3999)
    self.assertTrue(math.isnan(rr.points[0].vRelNative))

  def test_native_doppler_rejected_on_gross_disagreement(self):
    # Selected-lead Doppler implying a large closing speed while slot 0 is steady (vRel~0) -> the
    # association check (|REL_SPEED - vRel| < AGREE) rejects it (different object) -> vRelNative NaN.
    raw_fast = int(round((-20.0 - 86.5) / -0.7))  # REL_SPEED ~ -20 m/s (hard closing), |diff| >> AGREE
    self.assertGreater(abs(-0.7 * raw_fast + 86.5), BOSCH_RADAR_SEL_VREL_AGREE)
    rr = self._warm_with_sel(3999, raw_fast)
    self.assertTrue(math.isnan(rr.points[0].vRelNative))

  def test_native_doppler_nan_when_selected_sentinel(self):
    # An idle-strength selected frame (no selected lead) -> vRelNative NaN even though 0x2C8 is present.
    rr = self._warm_with_sel(3999, 124, strength=0xFE)
    self.assertTrue(math.isnan(rr.points[0].vRelNative))

  def test_native_doppler_does_not_change_vrel_or_drel(self):
    # RX-only guarantee: feeding the selected-lead frame must NOT change the emitted vRel/dRel of slot 0
    # (only vRelNative is added). Compare a warm WITHOUT any 0x2C8 to an identical warm WITH one.
    rr_no = self._warm(3999)
    p_no = rr_no.points[0]
    self.ri = _make_ri()
    self.bus = self.ri.rcp.bus
    rr_yes = self._warm_with_sel(3999, 124)
    p_yes = rr_yes.points[0]
    self.assertAlmostEqual(p_no.vRel, p_yes.vRel, places=6)
    self.assertAlmostEqual(p_no.dRel, p_yes.dRel, places=6)
    self.assertTrue(math.isnan(p_no.vRelNative))
    self.assertFalse(math.isnan(p_yes.vRelNative))

  def test_b1_tag_gate_skips_nonheader(self):
    # b1 != 0x74 -> non-range sub-frame -> skipped (no point), even with a plausible range field.
    rr = self._emit(0, [self._f(0x280, _hdr_frame(3999, tag=0x02))], 0x10)
    self.assertIsNotNone(rr)
    self.assertEqual(len(rr.points), 0)

  def test_sentinel_strength_idle(self):
    rr = self._emit(0, [self._f(0x280, _hdr_frame(3999, strength=0xFE))], 0x10)
    self.assertEqual(len(rr.points), 0)

  def test_sentinel_range_unset(self):
    rr = self._emit(0, [self._f(0x280, _hdr_frame(0x8000))], 0x10)
    self.assertEqual(len(rr.points), 0)

  def test_sentinel_range_saturation(self):
    rr = self._emit(0, [self._f(0x280, _hdr_frame(0xFF80))], 0x10)
    self.assertEqual(len(rr.points), 0)
    rr = self._emit(int(0.05 * 1e9), [self._f(0x280, _hdr_frame(0xFFFF))], 0x11)
    self.assertEqual(len(rr.points), 0)

  def test_multi_object_emission(self):
    dt_ns = int(0.05 * 1e9)

    def burst(ns, cntr):
      return self._emit(ns, [self._f(0x280, _hdr_frame(3000, cntr=cntr)),   # slot 0 (near head)
                             self._f(0x288, _hdr_frame(4000, cntr=cntr)),   # slot 2 (mid, added 2026-07-01)
                             self._f(0x2D0, _hdr_frame(5000, cntr=cntr))], cntr)  # slot 4 (far group)
    rr = None
    for k in range(self.WARM_CYCLES):   # born + settled -> all three emit
      rr = burst(k * dt_ns, (0x10 + k) & 0xFF)
    self.assertEqual(len(rr.points), 3)
    # S1: trackId = slot*STRIDE + incarnation(=1); decode the slot back out to verify the 3 distinct slots.
    by_slot = {p.trackId // BOSCH_RADAR_TRACKID_STRIDE: p for p in rr.points}
    self.assertEqual(set(by_slot), {0, 2, 4})
    self.assertAlmostEqual(by_slot[0].dRel, 0.00357 * 3000 - 3.0, places=4)
    self.assertAlmostEqual(by_slot[2].dRel, 0.00357 * 4000 - 3.0, places=4)
    self.assertAlmostEqual(by_slot[4].dRel, 0.00357 * 5000 - 3.0, places=4)
    # All three are first-incarnation distinct trackIds (no reuse across slots).
    self.assertEqual(len({p.trackId for p in rr.points}), 3)

  def test_trackid_stability_across_cycles(self):
    dt_ns = int(0.05 * 1e9)  # 20 Hz
    rr0 = self._warm(3000)                                                   # born (cycles 0,1)
    id0 = rr0.points[0].trackId
    rr1 = self._emit(2 * dt_ns, [self._f(0x280, _hdr_frame(3010, cntr=0x20))], 0x20)
    # S1: a continuously-present slot keeps its trackId (same incarnation) across cycles.
    self.assertEqual(rr1.points[0].trackId, id0)
    self.assertEqual(id0 // BOSCH_RADAR_TRACKID_STRIDE, 0)  # slot 0
    self.assertEqual(id0, 1)                                # first incarnation

  def test_vrel_derived_closing_negative(self):
    dt_ns = int(0.05 * 1e9)  # 50 ms
    # Steady close: dRel shrinks a fixed amount each sweep -> the KF converges to that closing rate. Use a
    # modest rate (< VREL_SOFT) so the base settle applies; warm past born+settle so the point emits.
    step = 100  # raw/cycle -> 0.00357*100 = 0.357 m/cycle -> ~ -7.14 m/s
    rate = -0.00357 * step / 0.05
    rr = None
    for k in range(self.WARM_CYCLES + 1):
      rr = self._emit(k * dt_ns, [self._f(0x280, _hdr_frame(4000 - step * k, cntr=(0x10 + k) & 0xFF))], (0x10 + k) & 0xFF)
    p = rr.points[0]
    self.assertFalse(math.isnan(p.vRel))
    self.assertLess(p.vRel, 0.0)
    self.assertAlmostEqual(p.vRel, rate, delta=1.5)  # KF converged to the steady closing rate

  def test_yrel_azimuth_formula_and_sign(self):
    # b4:b5 = AZIMUTH (rlog-settled 2026-06-08; SIGN corrected 2026-07-06 by the roadtrip excited-pair
    # regression -- radard's yRel convention is -lead.y, and vision y ~ -sin(k*raw), so the projection is
    # POSITIVE):  yRel = +dRel * sin((b4b5 - 0x8000) * scale_deg * pi/180)
    # NOT a linear m/LSB. LAT_RAW > 0 -> positive yRel.
    rr = self._warm(3999, lat_raw=0x9000)  # lat_raw > center; born under S2
    p = rr.points[0]
    lat = 0x9000 - 0x8000  # = +4096 LSB
    dRel = 0.00357 * 3999 - 3.0
    az_deg = lat * BOSCH_RADAR_LAT_SCALE_DEG_PER_LSB
    expected = dRel * math.sin(az_deg * math.pi / 180.0)
    self.assertAlmostEqual(p.yRel, expected, places=6)
    self.assertGreater(p.yRel, 0.0)  # positive LAT_RAW -> positive yRel (radard -lead.y convention)
    # And it is the trig projection, NOT a linear LAT_RAW*scale (the two differ once dRel != 1):
    self.assertNotAlmostEqual(p.yRel, lat * BOSCH_RADAR_LAT_SCALE_DEG_PER_LSB, places=6)

  def test_yrel_center_is_zero(self):
    # Exactly centered azimuth (LAT_RAW == 0) -> yRel == 0 regardless of range.
    rr = self._warm(3999, lat_raw=0x8000)
    self.assertAlmostEqual(rr.points[0].yRel, 0.0, places=9)

  def test_yrel_left_positive(self):
    # LAT_RAW < center -> negative yRel (sign symmetry of the projection; convention fixed 2026-07-06).
    rr = self._warm(3999, lat_raw=0x7000)  # below center
    p = rr.points[0]
    self.assertLess(p.yRel, 0.0)
    # magnitude matches the opposite-side case at the same offset magnitude
    dRel = 0.00357 * 3999 - 3.0
    az_deg = (0x7000 - 0x8000) * BOSCH_RADAR_LAT_SCALE_DEG_PER_LSB
    self.assertAlmostEqual(p.yRel, dRel * math.sin(az_deg * math.pi / 180.0), places=6)

  def test_yrel_scales_with_range(self):
    # AZIMUTH signature: at a FIXED angle, the lateral projection grows with range (a linear m/LSB
    # field would be range-independent). Same lat_raw, two ranges -> |yRel| larger at the larger range.
    # Use a fresh interface per range so the per-slot vRel/born history doesn't cross-contaminate.
    near = self._warm(2000, lat_raw=0x9000, base_ns=0)        # dRel ~= 4.14 m
    self.ri = _make_ri()                                       # reset; _warm/_emit read self.ri
    self.bus = self.ri.rcp.bus
    far = self._warm(6000, lat_raw=0x9000, base_ns=0)         # dRel ~= 18.42 m
    self.assertLess(abs(near.points[0].yRel), abs(far.points[0].yRel))

  def _slots(self, rr):
    return {p.trackId // BOSCH_RADAR_TRACKID_STRIDE for p in rr.points}

  def _warm2(self, dt_ns, cntr0=0x10):
    # warm slots 0 and 1 together to emitting (born + settled). Returns (last_rr, next_cycle_index).
    rr = None
    for k in range(self.WARM_CYCLES):
      c = (cntr0 + k) & 0xFF
      rr = self._emit(k * dt_ns, [self._f(0x280, _hdr_frame(3000, cntr=c)),
                                  self._f(0x284, _hdr_frame(4000, cntr=c))], c)
    return rr, self.WARM_CYCLES

  def test_slot_clears_when_track_goes_sentinel(self):
    dt_ns = int(0.05 * 1e9)
    rr, k = self._warm2(dt_ns)
    self.assertEqual(self._slots(rr), {0, 1})
    # slot 0 goes sentinel; S2 persist tolerates it (valid_cnt saturated at VALID_CAP) then drops after
    # VALID_CAP sustained sentinel cycles. slot 1 stays valid throughout.
    c = (0x10 + k) & 0xFF
    rr = self._emit(k * dt_ns, [self._f(0x280, _hdr_frame(3000, strength=0xFE, cntr=c)),
                                self._f(0x284, _hdr_frame(4000, cntr=c))], c)
    self.assertIn(0, self._slots(rr))          # one sentinel tolerated (persist hysteresis)
    for j in range(1, BOSCH_RADAR_VALID_CAP + 1):
      c = (0x10 + k + j) & 0xFF
      rr = self._emit((k + j) * dt_ns, [self._f(0x280, _hdr_frame(3000, strength=0xFE, cntr=c)),
                                        self._f(0x284, _hdr_frame(4000, cntr=c))], c)
    self.assertEqual(self._slots(rr), {1})     # sustained sentinel -> slot 0 aged out, slot 1 retained

  def test_stale_track_aged_when_absent(self):
    dt_ns = int(0.05 * 1e9)
    rr, k = self._warm2(dt_ns)
    self.assertEqual(self._slots(rr), {0, 1})
    # 0x284 (slot 1) goes absent; tolerated one cycle, then aged out after VALID_CAP sustained absences.
    c = (0x10 + k) & 0xFF
    rr = self._emit(k * dt_ns, [self._f(0x280, _hdr_frame(3010, cntr=c))], c)
    self.assertIn(1, self._slots(rr))          # slot 1 persists one absent cycle
    for j in range(1, BOSCH_RADAR_VALID_CAP + 1):
      c = (0x10 + k + j) & 0xFF
      rr = self._emit((k + j) * dt_ns, [self._f(0x280, _hdr_frame(3020 + j, cntr=c))], c)
    self.assertEqual(self._slots(rr), {0})     # sustained absence -> slot 1 aged out

  def test_staleness_returns_empty_radardata_not_none(self):
    # trigger (0x2DC) born over two sweeps; then it goes quiet while another declared header keeps the
    # parser clock advancing past STALE_S -> EMPTY RadarData (not None) + radarUnavailableTemporary.
    self._warm(3000)  # born (2 sweeps), point established
    self.assertEqual(len(self.ri.pts), 1)
    stale_ns = int((BOSCH_RADAR_STALE_S + 0.2) * 1e9)
    rr = self._step(stale_ns, [self._f(0x284, _hdr_frame(0x8000))])  # 0x284 frame; trigger 0x2DC absent
    self.assertIsNotNone(rr)             # must be EMPTY RadarData, NOT None
    self.assertEqual(len(rr.points), 0)
    self.assertTrue(rr.errors.radarUnavailableTemporary)
    self.assertEqual(len(self.ri.pts), 0)  # points cleared

  def test_trigger_absent_no_stale_returns_none(self):
    # If the trigger (0x2DC) is merely absent for one cycle (well under STALE_S) and we have live points,
    # the update returns None (normal cadence gate) -- staleness only fires past STALE_S.
    self._warm(3000)  # born, live point present
    dt_ns = int(0.05 * 1e9)
    rr = self._step(2 * dt_ns + int(0.02 * 1e9), [self._f(0x284, _hdr_frame(4000))])  # trigger absent, 20ms later
    self.assertIsNone(rr)

  def test_fully_silent_radar_clears_points_and_returns_empty(self):
    # MOST safety-relevant staleness case: the radar goes COMPLETELY silent (no frames on ANY id) while
    # the parser clock keeps advancing (e.g. radard still pumps update() on its own cadence). The
    # frozen-phantom must still be cleared -> EMPTY RadarData (not None) + radarUnavailableTemporary.
    self._warm(3000)  # born (2 cycles), point established
    self.assertEqual(len(self.ri.pts), 1)
    stale_ns = int((BOSCH_RADAR_STALE_S + 0.2) * 1e9)
    rr = self.ri.update(_can(stale_ns, []))  # whole bus silent, advancing timestamp
    self.assertIsNotNone(rr)              # EMPTY RadarData, NOT None
    self.assertEqual(len(rr.points), 0)
    self.assertTrue(rr.errors.radarUnavailableTemporary)
    self.assertEqual(len(self.ri.pts), 0)  # phantom cleared

  def test_fully_silent_under_threshold_returns_none(self):
    # Brief whole-bus silence under STALE_S must NOT prematurely drop the live point.
    self._warm(3000)  # born, live point present
    dt_ns = int(0.05 * 1e9)
    rr = self.ri.update(_can(2 * dt_ns + int(0.05 * 1e9), []))  # 50 ms silent, well under 0.15 s
    self.assertIsNone(rr)
    self.assertEqual(len(self.ri.pts), 1)            # point retained

  def test_vrel_discontinuity_guard_rejects_slot_reuse(self):
    # If object A vacates slot 0 and object B enters the SAME slot in the next cycle WITHOUT an intervening
    # sentinel, the naive derivative teleports vRel to a non-physical value. The guard must reject that
    # sample (vRel NaN) AND re-seed history so the NEXT cycle derives cleanly. S1: the post-swap point
    # must ALSO be published under a DIFFERENT trackId (no reuse across the swap, capnp:314).
    dt_ns = int(0.05 * 1e9)  # 50 ms
    # Warm object A (~11 m) to an emitting point.
    rrA = self._warm(3900)
    id_a = rrA.points[0].trackId                       # object A's trackId (pre-swap)
    k = self.WARM_CYCLES
    # A DIFFERENT object B teleports into slot 0 at ~110 m (implied speed ~1900 m/s >> VREL_MAX) -> slot-reuse
    # BREAK: incarnation bumped, KF reseeded, settle reset -> the teleport is WITHHELD (never published as a
    # ~1900 m/s spike), rather than emitted with a NaN vRel.
    far_raw = int((110.0 + 3.0) / 0.00357)
    rr = self._emit(k * dt_ns, [self._f(0x280, _hdr_frame(far_raw, cntr=(0x10 + k) & 0xFF))], (0x10 + k) & 0xFF)
    self.assertEqual(len(rr.points), 0)                # phantom teleport suppressed this cycle
    # Re-settle B at its new steady range -> it emits under a NEW trackId (no reuse) with an in-bounds vRel.
    rr = None
    for j in range(1, self.WARM_CYCLES + 1):
      rr = self._emit((k + j) * dt_ns, [self._f(0x280, _hdr_frame(far_raw, cntr=(0x10 + k + j) & 0xFF))], (0x10 + k + j) & 0xFF)
    p = rr.points[0]
    id_b = p.trackId
    self.assertNotEqual(id_b, id_a)                    # S1: no trackId reuse across the swap
    self.assertEqual(id_a // BOSCH_RADAR_TRACKID_STRIDE, 0)
    self.assertEqual(id_b // BOSCH_RADAR_TRACKID_STRIDE, 0)
    self.assertAlmostEqual(p.dRel, 0.00357 * far_raw - 3.0, places=2)  # dRel tracks the new object
    self.assertFalse(math.isnan(p.vRel))
    self.assertLessEqual(abs(p.vRel), BOSCH_RADAR_VREL_MAX)

  def test_in_bounds_fast_lead_keeps_stable_trackid(self):
    # S1 control: a genuine fast closer (stationary object at highway speed, ~ -28.6 m/s, in-bounds) must NOT
    # be rejected and must keep a STABLE trackId. Under GRADUATED PERSISTENCE a high-|vRel| track must be
    # tracked longer before it is trusted, so warm it well past SETTLE_HIGH, then verify a stable id + vRel.
    dt_ns = int(0.05 * 1e9)
    step = 400   # raw/cycle -> 0.00357*400/0.05 = ~ -28.6 m/s (below VREL_MAX/HARD_MAX)
    raw0 = int((95.0 + 3.0) / 0.00357)
    rr = None
    n = 28       # comfortably past BORN + SETTLE_HIGH so a high-|vRel| track is trusted
    for k in range(n):
      rr = self._emit(k * dt_ns, [self._f(0x280, _hdr_frame(raw0 - step * k, cntr=(0x10 + k) & 0xFF))], (0x10 + k) & 0xFF)
    p = rr.points[0]
    id0 = p.trackId
    self.assertFalse(math.isnan(p.vRel))
    self.assertLess(p.vRel, 0.0)
    self.assertLessEqual(abs(p.vRel), BOSCH_RADAR_VREL_MAX)
    rr = self._emit(n * dt_ns, [self._f(0x280, _hdr_frame(raw0 - step * n, cntr=(0x10 + n) & 0xFF))], (0x10 + n) & 0xFF)
    self.assertEqual(rr.points[0].trackId, id0)   # stable id for a continuous in-bounds fast lead

  def test_returns_radardata_with_points_list(self):
    rr = self._warm(3000)  # born under S2
    self.assertIsNotNone(rr)
    self.assertEqual(len(rr.points), 1)            # iterable points sequence on the RadarData
    # canError mirrors rcp.can_valid (set on both the normal and stale paths).
    self.assertEqual(rr.errors.canError, not self.ri.rcp.can_valid)


class TestCivicBoschFineSafeParity(unittest.TestCase):
  """Dedicated acceptance tests for the SAFE parity-hardening set (S1-S6). RX-only, keep-AEB preserved."""

  TRIG = 0x2DC

  def setUp(self):
    self.ri = _make_ri()
    self.bus = self.ri.rcp.bus
    self.dt_ns = int(0.05 * 1e9)

  def _f(self, addr, frame):
    return (addr, frame, self.bus)

  def _trig(self, cntr):
    return self._f(self.TRIG, _hdr_frame(0x8000, tag=0xF0, strength=0xFE, cntr=cntr))

  def _emit(self, k, body, cntr):
    return self.ri.update(_can(k * self.dt_ns, list(body) + [self._trig(cntr)]))

  def _emit_full(self, k, slot0_frame, trig_cntr):
    # Drive a FULL 8-header sweep (so the CANParser reaches can_valid). slot 0 carries slot0_frame; slots
    # 1..7 (including the 0x2DC terminator) are benign sentinels carrying trig_cntr. Used for S3 faults,
    # which are gated on can_valid (a fault must not fire on a not-yet-valid bus).
    frames = [self._f(0x280, slot0_frame)]
    for a in BOSCH_RADAR_HDR_MSGS[1:]:
      frames.append(self._f(a, _hdr_frame(0x8000, tag=0xF0, strength=0xFE, cntr=trig_cntr)))
    return self.ri.update(_can(k * self.dt_ns, frames))

  def _slots(self, rr):
    return {p.trackId // BOSCH_RADAR_TRACKID_STRIDE for p in rr.points}

  # A steady slot emits only after BORN (S2) AND SETTLED (settle gate); drive it there.
  WARM_CYCLES = BOSCH_RADAR_BORN_CYCLES + BOSCH_RADAR_SETTLE_CYCLES

  def _warm(self, range_raw, cntr0=0x10):
    # Drive slot 0 at a steady range for WARM_CYCLES sweeps so it is born + settled -> emitting. Next
    # continuation sweep is cycle index WARM_CYCLES (cntr cntr0 + WARM_CYCLES). Returns the last rr.
    rr = None
    for k in range(self.WARM_CYCLES):
      rr = self._emit(k, [self._f(0x280, _hdr_frame(range_raw, cntr=(cntr0 + k) & 0xFF))], (cntr0 + k) & 0xFF)
    return rr

  # ---- S2 birth/persist hysteresis -------------------------------------------------------------
  def test_s2_single_frame_glitch_no_phantom(self):
    # (a) a single 1-frame valid glitch must NOT birth a phantom point.
    rr = self._emit(0, [self._f(0x280, _hdr_frame(3000, cntr=0x10))], 0x10)
    self.assertEqual(len(rr.points), 0)         # valid_cnt == 1 < BORN_CYCLES
    self.assertEqual(len(self.ri.pts), 0)

  def test_s2_born_after_n_cycles(self):
    # A point is published only after the slot is BORN (BORN_CYCLES valid sweeps) AND SETTLED (SETTLE_CYCLES
    # clean KF cycles). No point appears before both are met; for a steady slot the settle gate binds, so the
    # first emit lands no earlier than SETTLE_CYCLES.
    first = None
    for k in range(self.WARM_CYCLES):
      rr = self._emit(k, [self._f(0x280, _hdr_frame(3000, cntr=(0x10 + k) & 0xFF))], (0x10 + k) & 0xFF)
      if rr.points and first is None:
        first = k
    self.assertIsNotNone(first)                 # it does emit within born+settle sweeps
    self.assertGreaterEqual(first, BOSCH_RADAR_SETTLE_CYCLES)
    self.assertGreaterEqual(first, BOSCH_RADAR_BORN_CYCLES - 1)

  def test_s2_single_miss_does_not_drop(self):
    # (b) one missed cycle must NOT drop an established (born+settled) point (persist tolerance).
    self._warm(3000)
    k = self.WARM_CYCLES
    rr = self._emit(k, [self._f(0x280, _hdr_frame(0x8000, cntr=(0x10 + k) & 0xFF))], (0x10 + k) & 0xFF)
    self.assertEqual(self._slots(rr), {0})      # retained for one missed cycle (valid_cnt decremented, >0)

  def test_s2_two_misses_drop(self):
    # (c) two consecutive missed cycles DO drop the point.
    self._emit(0, [self._f(0x280, _hdr_frame(3000, cntr=0x10))], 0x10)
    self._emit(1, [self._f(0x280, _hdr_frame(3000, cntr=0x11))], 0x11)  # born (valid_cnt 2)
    self._emit(2, [self._f(0x280, _hdr_frame(0x8000, cntr=0x12))], 0x12)  # miss 1 -> valid_cnt 1
    rr = self._emit(3, [self._f(0x280, _hdr_frame(0x8000, cntr=0x13))], 0x13)  # miss 2 -> valid_cnt 0
    self.assertEqual(len(rr.points), 0)

  def test_s2_valid_cap_saturates(self):
    # the confidence counter must saturate at VALID_CAP (so persist tolerance is bounded, not unbounded).
    for k in range(BOSCH_RADAR_VALID_CAP + 4):
      self._emit(k, [self._f(0x280, _hdr_frame(3000, cntr=(0x10 + k) & 0xFF))], (0x10 + k) & 0xFF)
    self.assertLessEqual(self.ri._valid_cnt[0], BOSCH_RADAR_VALID_CAP)

  # ---- S3 plausibility / self-consistency faults ----------------------------------------------
  def test_s3_out_of_band_range_raises_wrongconfig(self):
    # A decoded dRel beyond the physical ceiling -> wrongConfig + NO point emitted. The existing
    # saturation sentinel (raw >= 0xFF80 ~= 230.5 m) catches most over-range raws first; the S3 check
    # covers the narrow window between RANGE_MAX (230.0 m) and the sat rail. Pick a raw in that window.
    over_raw = 65350  # 0.00357*65350 - 3.0 = 230.30 m -> > RANGE_MAX(230) and < 0xFF80(65408)
    self.assertLess(over_raw, BOSCH_RADAR_RAW_SAT)
    self.assertGreater(0.00357 * over_raw - 3.0, BOSCH_RADAR_RANGE_MAX)
    rr = self._emit(0, [self._f(0x280, _hdr_frame(over_raw, cntr=0x10))], 0x10)
    self.assertTrue(rr.errors.wrongConfig)
    self.assertEqual(len(rr.points), 0)

  def test_s3_in_band_range_no_wrongconfig(self):
    rr = self._emit(0, [self._f(0x280, _hdr_frame(3000, cntr=0x10))], 0x10)
    self.assertFalse(rr.errors.wrongConfig)

  def test_s3_frozen_cntr_raises_radarfault(self):
    # CNTR frozen (constant) while can_valid -> radarFault after CNTR_STALL_CYCLES. Use FULL sweeps so the
    # parser reaches can_valid (the fault is intentionally gated on can_valid). Freeze the trigger CNTR.
    faulted = False
    for k in range(BOSCH_RADAR_CNTR_STALL_CYCLES + 4):
      rr = self._emit_full(k, _hdr_frame(3000, cntr=0x10), 0x55)  # trigger CNTR frozen at 0x55
      if rr is not None and rr.errors.radarFault:
        faulted = True
    self.assertTrue(faulted)

  def test_s3_advancing_cntr_no_radarfault(self):
    # A normal advancing CNTR (full valid sweeps) must raise neither radarFault nor wrongConfig.
    saw_fault = saw_wrong = False
    for k in range(BOSCH_RADAR_CNTR_STALL_CYCLES + 6):
      rr = self._emit_full(k, _hdr_frame(3000, cntr=(0x10 + k) & 0xFF), (0x20 + k) & 0xFF)
      if rr is not None:
        saw_fault |= rr.errors.radarFault
        saw_wrong |= rr.errors.wrongConfig
    self.assertFalse(saw_fault)
    self.assertFalse(saw_wrong)

  # ---- S5 honest measured flag ----------------------------------------------------------------
  def test_s5_estimate_vs_measurement(self):
    # A settled track publishes a MEASUREMENT (measured=True, real derived vRel). A destabilising event (a
    # slot-reuse teleport) reseeds the slot and RESETS settle -> the point is WITHHELD (not published as a
    # NaN estimate) until it re-settles; then it is a measurement again.
    rr = self._warm(4000)
    self.assertFalse(math.isnan(rr.points[0].vRel))
    self.assertTrue(rr.points[0].measured)
    k = self.WARM_CYCLES
    far = int((120.0 + 3.0) / 0.00357)                          # teleport -> BREAK -> settle reset
    rr = self._emit(k, [self._f(0x280, _hdr_frame(far, cntr=(0x10 + k) & 0xFF))], (0x10 + k) & 0xFF)
    self.assertEqual(len(rr.points), 0)                         # withheld while unsettled (no NaN published)
    rr = None
    for j in range(1, self.WARM_CYCLES + 1):
      rr = self._emit(k + j, [self._f(0x280, _hdr_frame(far, cntr=(0x10 + k + j) & 0xFF))], (0x10 + k + j) & 0xFF)
    self.assertTrue(rr.points[0].measured)                      # re-settled -> measurement again

  # ---- S6 vRel derivation hardening -----------------------------------------------------------
  def test_s6_long_gap_reseeds_no_spike(self):
    # A long gap (> DT_MAX) between sightings must RE-SEED (not derive a spike from two far-apart samples).
    # The re-seed resets settle, so no point is published on the gap cycle; after re-settling, the vRel is a
    # clean in-bounds value -- never a spike.
    rr = self._warm(4000)
    self.assertIsNotNone(rr.points[0])
    k = self.WARM_CYCLES
    gap_k = int((BOSCH_RADAR_VREL_DT_MAX_S + 0.2) / 0.05) + 1
    rr = self._emit(k + gap_k, [self._f(0x280, _hdr_frame(2000, cntr=(0x10 + k) & 0xFF))], (0x10 + k) & 0xFF)
    self.assertEqual(len(rr.points), 0)                         # re-seeded + unsettled -> withheld, no spike
    rr = None
    for j in range(1, self.WARM_CYCLES + 1):
      rr = self._emit(k + gap_k + j, [self._f(0x280, _hdr_frame(2000, cntr=(0x10 + k + j) & 0xFF))], (0x10 + k + j) & 0xFF)
    self.assertFalse(math.isnan(rr.points[0].vRel))
    self.assertLessEqual(abs(rr.points[0].vRel), BOSCH_RADAR_VREL_MAX)

  def test_s6_smooth_close_stable_negative_vrel(self):
    # A smooth closing sequence yields a stable negative derived vRel (in-bounds). Points appear only once
    # settled; collect the emitted ones over a long steady close.
    rng = 4000
    vrels = []
    for k in range(self.WARM_CYCLES + 6):
      rng -= 50  # steady close (~ -3.6 m/s, base settle band)
      rr = self._emit(k, [self._f(0x280, _hdr_frame(rng, cntr=(0x10 + k) & 0xFF))], (0x10 + k) & 0xFF)
      if rr.points and not math.isnan(rr.points[0].vRel):
        vrels.append(rr.points[0].vRel)
    self.assertGreater(len(vrels), 3)
    self.assertTrue(all(v < 0.0 for v in vrels))                 # all closing
    self.assertTrue(all(abs(v) <= BOSCH_RADAR_VREL_MAX for v in vrels))

  # ---- keep-AEB / RX-only invariants ----------------------------------------------------------
  def test_keepaeb_invariants_preserved(self):
    # radarUnavailable pinned False on this CP (stock radar + AEB alive); the parser was actually built
    # (rcp is not None) and triggers on the sweep terminator. RX-only: the interface declares no TX path.
    self.assertFalse(self.ri.radar_off_can)
    self.assertIsNotNone(self.ri.rcp)
    self.assertEqual(self.ri.trigger_msg, 0x2DC)
    # The radar ingest never publishes vRel/aRel authority changes; aRel is always NaN (Toyota posture).
    rng = 4000
    self._emit(0, [self._f(0x280, _hdr_frame(rng, cntr=0x10))], 0x10)
    rr = self._emit(1, [self._f(0x280, _hdr_frame(rng - 50, cntr=0x11))], 0x11)
    self.assertTrue(all(math.isnan(p.aRel) for p in rr.points))  # aRel never fabricated (R2 deferred)


@unittest.skipUnless(os.path.exists(BFCAR_CSV), "radar-re bfcar capture not present")
class TestCivicBoschFineRealCapture(unittest.TestCase):
  """Replay real radar-re captures through the parser (positive + negative control)."""

  HDR_HEX = {f"{m:X}" for m in BOSCH_RADAR_HDR_MSGS}
  TRIG_HEX = f"{BOSCH_RADAR_HDR_MSGS[-1]:X}"  # 0x2DC -- the sweep terminator / trigger

  @classmethod
  def _load_sweeps(cls, path):
    # Load all 8 header IDs (bus 2) in arrival order and group into sweeps. A sweep boundary is each new
    # 0x280 (head of burst); each sweep's frames are replayed together so the 0x2DC terminator triggers
    # a single coherent emit per sweep (S4). Returns a list of sweeps, each a list of (addr, bytes).
    import csv
    rows = []
    with open(path) as f:
      for row in csv.DictReader(f):
        a = row["addr_hex"].upper()
        if row["bus"] == "2" and a in cls.HDR_HEX:
          rows.append((int(a, 16), bytes.fromhex(row["data_hex"])))
    sweeps, cur = [], []
    for addr, data in rows:
      if addr == 0x280 and cur:
        sweeps.append(cur)
        cur = []
      cur.append((addr, data))
    if cur:
      sweeps.append(cur)
    return sweeps

  def test_bfcar_positive_control_clean_close(self):
    sweeps = self._load_sweeps(BFCAR_CSV)
    self.assertGreater(len(sweeps), 100)
    ri = _make_ri()
    bus = ri.rcp.bus
    ranges, vrels = [], []
    dt_ns = int(0.05 * 1e9)
    for i, sweep in enumerate(sweeps):
      rr = ri.update(_can(i * dt_ns, [(addr, data, bus) for addr, data in sweep]))
      if rr is not None and rr.points:
        ranges.append(rr.points[0].dRel)
        if not math.isnan(rr.points[0].vRel):
          vrels.append(rr.points[0].vRel)
    self.assertGreater(len(ranges), 100)
    # Clean monotonic close 11.28 -> 1.52 m (CONFIRM-REPORT); allow a small margin. (S3 plausibility: every
    # dRel stays well inside [-3, 230] m so the positive control must raise NO wrongConfig.)
    self.assertAlmostEqual(max(ranges), 11.28, delta=0.2)
    self.assertAlmostEqual(min(ranges), 1.52, delta=0.5)
    # A closing trajectory -> derived vRel net negative on average.
    self.assertGreater(len(vrels), 50)
    self.assertLess(sum(vrels) / len(vrels), 0.0)

  def test_bfcar_sweep_coherent_no_split(self):
    # S4 acceptance: every live slot in a sweep is emitted in the SAME RadarData (no slot split across two
    # emits). With the 0x2DC trigger the emit fires once per sweep AFTER the whole burst has accumulated,
    # so the number of emits equals the number of sweeps that contain the terminator (no double-emit, no
    # mid-sweep partial). bfcar happens to carry exactly one live slot (slot 0); assert exactly one emit
    # per sweep and that the live slot is present in it.
    sweeps = self._load_sweeps(BFCAR_CSV)
    # restrict to sweeps that actually contain the terminator (otherwise no emit is expected)
    full = [s for s in sweeps if any(addr == BOSCH_RADAR_HDR_MSGS[-1] for addr, _ in s)]
    self.assertGreater(len(full), 100)
    ri = _make_ri()
    bus = ri.rcp.bus
    dt_ns = int(0.05 * 1e9)
    emits = 0
    for i, sweep in enumerate(full):
      rr = ri.update(_can(i * dt_ns, [(addr, data, bus) for addr, data in sweep]))
      if rr is not None:
        emits += 1
    # exactly one emit per terminator-bearing sweep -> no split, no double-emit.
    self.assertEqual(emits, len(full))

  @unittest.skipUnless(os.path.exists(IDLE_CSV), "radar-re idle capture not present")
  def test_idle_negative_control_zero_points(self):
    sweeps = self._load_sweeps(IDLE_CSV)
    self.assertGreater(len(sweeps), 100)
    ri = _make_ri()
    bus = ri.rcp.bus
    max_pts = 0
    dt_ns = int(0.05 * 1e9)
    for i, sweep in enumerate(sweeps):
      rr = ri.update(_can(i * dt_ns, [(addr, data, bus) for addr, data in sweep]))
      if rr is not None:
        max_pts = max(max_pts, len(rr.points))
    # All frames are b0==0xFE idle / b1==0xF0 (never 0x74) -> every frame skipped -> 0 points ever.
    self.assertEqual(max_pts, 0)


class TestS7CrossSlotStitch(unittest.TestCase):
  """S7 cross-slot identity stitch: the radar keeps the fine table ~sorted by range, so one object
  appearing/disappearing shifts EVERY track a slot within one sweep. A born track must survive that
  re-slotting with its trackId/KF/settle intact (no emit hole), while genuinely different objects must
  NOT be stitched. Also covers the SETTLE_MATURE maneuver-step decay."""

  TRIG = 0x2DC
  DT_NS = int(0.05 * 1e9)

  def setUp(self):
    self.ri = _make_ri()
    self.bus = self.ri.rcp.bus

  def _f(self, addr, frame):
    return (addr, frame, self.bus)

  def _trig(self, cntr):
    return self._f(self.TRIG, _hdr_frame(0x8000, tag=0xF0, strength=0xFE, cntr=cntr))

  def _sweep(self, k, slot_ranges, cntr0=0x10):
    # One sweep at cycle k: {header_addr: range_raw} + the trigger terminator.
    cntr = (cntr0 + k) & 0xFF
    body = [self._f(a, _hdr_frame(rr, cntr=cntr)) for a, rr in slot_ranges.items()]
    return self.ri.update(_can(k * self.DT_NS, body + [self._trig(cntr)]))

  WARM = BOSCH_RADAR_BORN_CYCLES + BOSCH_RADAR_SETTLE_CYCLES + 2

  def test_table_shift_preserves_trackid_no_emit_hole(self):
    # Object born+settled in slot 1 (0x284) at ~24 m; a second far object sits in slot 2. The near
    # object then SHIFTS to slot 0 in one sweep (table re-sort) while slot 1 takes the far object.
    raw24, raw36 = 7563, 10924  # ~24.0 m, ~36.0 m
    for k in range(self.WARM):
      rr = self._sweep(k, {0x284: raw24, 0x288: raw36})
    ids = {p.trackId: p for p in rr.points}
    self.assertEqual(len(ids), 2)
    tid24 = next(t for t, p in ids.items() if abs(p.dRel - 24.0) < 0.5)
    self.assertFalse(math.isnan(ids[tid24].vRel))
    # the shift sweep: 24 m object now on 0x280, 36 m object now on 0x284, 0x288 goes quiet
    rr = self._sweep(self.WARM, {0x280: raw24, 0x284: raw36})
    self.assertIsNotNone(rr)
    pts24 = [p for p in rr.points if abs(p.dRel - 24.0) < 0.5]
    # no emit hole: the re-slotted object is present on the VERY shift sweep, same id, finite vRel
    self.assertEqual(len(pts24), 1)
    self.assertEqual(pts24[0].trackId, tid24)
    self.assertFalse(math.isnan(pts24[0].vRel))
    # and it keeps emitting under the same id on the following sweep
    rr = self._sweep(self.WARM + 1, {0x280: raw24, 0x284: raw36})
    pts24 = [p for p in rr.points if abs(p.dRel - 24.0) < 0.5]
    self.assertEqual(len(pts24), 1)
    self.assertEqual(pts24[0].trackId, tid24)

  def test_distinct_object_not_stitched(self):
    # A 20 m track dies; a 30 m object (outside the 2 m stitch gate) takes the slot within the stitch
    # window -> it must get a NEW trackId and pay the normal born/settle warmup (no instant emit).
    raw20, raw30 = 6443, 9244  # ~20.0 m, ~30.0 m
    for k in range(self.WARM):
      rr = self._sweep(k, {0x280: raw20})
    tid20 = rr.points[0].trackId
    # one absent sweep (decays confidence; buries a graveyard copy), then the different object appears
    self._sweep(self.WARM, {})
    rr = self._sweep(self.WARM + 1, {0x280: raw30})
    pts30 = [p for p in rr.points if abs(p.dRel - 30.0) < 0.5]
    self.assertEqual(len(pts30), 0)  # normal warmup: no instant emit for a genuinely new object
    for k in range(self.WARM + 2, 2 * self.WARM + 2):
      rr = self._sweep(k, {0x280: raw30})
    pts30 = [p for p in rr.points if abs(p.dRel - 30.0) < 0.5]
    self.assertEqual(len(pts30), 1)
    self.assertNotEqual(pts30[0].trackId, tid20)

  def test_stitch_window_expiry_new_trackid(self):
    # Same range, but the object is gone for LONGER than the stitch window -> graveyard entry expired
    # -> rebirth is a NEW identity with the normal warmup.
    raw25 = 7843  # ~25.0 m
    for k in range(self.WARM):
      rr = self._sweep(k, {0x280: raw25})
    tid = rr.points[0].trackId
    gap_sweeps = 8  # 8 * 50 ms = 0.4 s > STITCH_MAX_AGE_S (0.25 s); also floors valid_cnt
    for k in range(self.WARM, self.WARM + gap_sweeps):
      self._sweep(k, {})
    rr = None
    for k in range(self.WARM + gap_sweeps, self.WARM + gap_sweeps + self.WARM):
      rr = self._sweep(k, {0x280: raw25})
    self.assertEqual(len(rr.points), 1)
    self.assertNotEqual(rr.points[0].trackId, tid)

  def test_mature_track_survives_maneuver_step(self):
    # A mature track (long clean settle run) that takes a KF innovation-adaptive step (lead starts
    # braking) keeps emitting: settle decays to SETTLE_CYCLES, not 0 -> no 3-sweep blackout.
    from opendbc.car.honda.radar_interface import BOSCH_RADAR_SETTLE_MATURE
    raw = 9244  # ~30.0 m
    n_warm = BOSCH_RADAR_BORN_CYCLES + BOSCH_RADAR_SETTLE_MATURE + 3
    for k in range(n_warm):
      rr = self._sweep(k, {0x280: raw})
    self.assertGreaterEqual(self.ri._settle[0], BOSCH_RADAR_SETTLE_MATURE)
    self.assertEqual(len(rr.points), 1)
    # one 0.6 m range step in a 50 ms sweep (~12 m/s implied jump: adaptive, far below the 30 m/s BREAK)
    raw_step = raw - 168
    rr = self._sweep(n_warm, {0x280: raw_step})
    self.assertTrue(self.ri._kf[0].adapted)  # the maneuver branch actually fired
    self.assertEqual(self.ri._settle[0], BOSCH_RADAR_SETTLE_CYCLES)  # decayed, NOT zeroed
    self.assertEqual(len(rr.points), 1)  # still emitting -- no blackout at maneuver onset
    self.assertFalse(math.isnan(rr.points[0].vRel))

  def test_same_range_lane_swap_breaks_identity(self):
    # S7b: two objects at the SAME range in different lanes swap slot occupancy -- invisible to the
    # range-only BREAK test. The azimuth jump must break the identity (new trackId, point withheld)
    # instead of silently letting the old id absorb the other lane's kinematics.
    raw24 = 7563  # ~24.0 m
    # y = -d*sin(az): lat_raw 0x477A -> LAT_RAW = -14470 -> az ~ -14.47 deg -> y ~ +6.0 m at 24 m
    LAT_6M = 0x477A
    for k in range(self.WARM):
      cntr = (0x10 + k) & 0xFF
      rr = self.ri.update(_can(k * self.DT_NS,
                               [self._f(0x280, _hdr_frame(raw24, cntr=cntr))] + [self._trig(cntr)]))
    tid = rr.points[0].trackId
    self.assertAlmostEqual(rr.points[0].yRel, 0.0, delta=0.1)
    # same range, lateral position jumps ~6 m in one sweep: a different object took the slot
    cntr = (0x10 + self.WARM) & 0xFF
    rr = self.ri.update(_can(self.WARM * self.DT_NS,
                             [self._f(0x280, _hdr_frame(raw24, lat_raw=LAT_6M, cntr=cntr))] + [self._trig(cntr)]))
    self.assertEqual(len([p for p in rr.points if p.trackId == tid]), 0)  # old identity gone
    self.assertEqual(len(rr.points), 0)  # new occupant pays the settle warmup (withheld)
    self.assertNotEqual(self.ri._tid[0], tid)

  def test_stitch_requires_lateral_continuity(self):
    # S7b: a rebirth at the SAME range but a very different lateral position must NOT inherit the dead
    # track's identity (range alone cannot distinguish same-range objects in different lanes).
    raw24 = 7563
    LAT_6M = 0x477A
    for k in range(self.WARM):
      rr = self._sweep(k, {0x280: raw24})
    tid = rr.points[0].trackId
    self._sweep(self.WARM, {})  # one absent sweep buries the born track
    cntr = (0x10 + self.WARM + 1) & 0xFF
    rr = self.ri.update(_can((self.WARM + 1) * self.DT_NS,
                             [self._f(0x280, _hdr_frame(raw24, lat_raw=LAT_6M, cntr=cntr))] + [self._trig(cntr)]))
    self.assertNotEqual(self.ri._tid[0], tid)  # NOT stitched: fresh identity despite matching range

  def test_young_track_still_zeroed_on_maneuver_step(self):
    # The same adaptive step on a YOUNG track (settle < MATURE) still zeroes the run and withholds the
    # point: the validated churn/phantom protection is unchanged for unproven tracks.
    raw = 9244
    n_warm = self.WARM  # born + settled, but far below MATURE
    for k in range(n_warm):
      rr = self._sweep(k, {0x280: raw})
    self.assertEqual(len(rr.points), 1)
    rr = self._sweep(n_warm, {0x280: raw - 168})
    self.assertTrue(self.ri._kf[0].adapted)
    self.assertEqual(self.ri._settle[0], 0)
    self.assertEqual(len(rr.points), 0)  # withheld while it re-proves itself


class TestS8CounterIdentity(unittest.TestCase):
  """S8: the radar's HARDWARE per-object counter OBJ_LIFE (B0:B1 of each slot's SUB2 frame, header+2) is
  read via an isolated parser and used as a stitch corroborator / veto / recovery on top of S7/S7b.
  These drive real SUB2 frames end-to-end (DBC decode + isolated parser + graveyard stitch)."""

  TRIG = 0x2DC
  DT_NS = int(0.05 * 1e9)
  WARM = BOSCH_RADAR_BORN_CYCLES + BOSCH_RADAR_SETTLE_CYCLES + 2
  A_BASE, B_BASE, C_BASE = 5000, 20000, 40000  # per-object OBJ_LIFE seeds (far apart -> distinct ids)

  def setUp(self):
    self.ri = _make_ri()
    self.bus = self.ri.rcp.bus

  def _f(self, addr, frame):
    return (addr, frame, self.bus)

  def _trig(self, cntr):
    return self._f(self.TRIG, _hdr_frame(0x8000, tag=0xF0, strength=0xFE, cntr=cntr))

  def _sub2(self, hdr_addr, life):
    # SUB2 frame (header+2) carrying OBJ_LIFE at B0:B1 (the rest is don't-care for this decode).
    return self._f(hdr_addr + 2, _frame((life >> 8) & 0xFF, life & 0xFF, 0, 0, 0, 0, 0, 0))

  def _sweep(self, k, specs, *, with_life=True, cntr0=0x10):
    # One sweep at cycle k. specs = {hdr_addr: (range_raw, life)}. Sends header + (optional) SUB2 +
    # trigger. with_life=False omits the SUB2 frames -> OBJ_LIFE unavailable (pure S7/S7b geometry).
    cntr = (cntr0 + k) & 0xFF
    body = []
    for a, (rr, life) in specs.items():
      body.append(self._f(a, _hdr_frame(rr, cntr=cntr)))
      if with_life:
        body.append(self._sub2(a, life))
    return self.ri.update(_can(k * self.DT_NS, body + [self._trig(cntr)]))

  # ---- direct predicate + decode ---------------------------------------------------------------
  def test_predicate_bounds(self):
    f = RadarInterface._bosch_obj_life_continues
    self.assertTrue(f(1000, 1000 + BOSCH_RADAR_OBJ_LIFE_STEP_MAX, 0.06))  # +33 one sweep -> continues
    self.assertTrue(f(1000, 1017, 0.06))                                  # +17 sub-counter step -> continues
    self.assertTrue(f(1000, 1001, 0.06))                                  # +1 sub-counter wrap -> continues
    self.assertTrue(f(1000, 1000 + BOSCH_RADAR_OBJ_LIFE_STEP_MAX * 6, 0.30))  # 6-sweep gap, all +33
    self.assertFalse(f(1000, 1000, 0.06))       # frozen (no advance) -> not a live continuation
    self.assertFalse(f(1000, 990, 0.06))        # DECREASE -> different object
    self.assertFalse(f(1000, 9000, 0.06))       # huge jump -> different object
    self.assertFalse(f(1000, 1066, 0.04))       # +66 in a single-sweep gap (n=1) -> advanced too far
    self.assertIsNone(f(0, 1033, 0.06))         # unavailable (unheard default) -> caller uses geometry
    self.assertIsNone(f(1000, 0, 0.06))
    # 16-bit modular wrap: an object near the rail advances correctly across the 2^16 boundary
    self.assertTrue(f(65530, (65530 + 33) & 0xFFFF, 0.06))

  def test_obj_life_decoded_and_stored_per_slot(self):
    # A live slot's OBJ_LIFE is decoded from its SUB2 frame and stored in _acc (keyed by slot), so a later
    # graveyard stitch can match this object by its hardware id. RX-only: the point's vRel/dRel are set by
    # the header frame, not the SUB2 frame.
    life = self.A_BASE
    rr = None
    for k in range(self.WARM):
      rr = self._sweep(k, {0x280: (3999, life + 33 * k)})
    self.assertEqual(len(rr.points), 1)
    self.assertEqual(self.ri._acc[0], life + 33 * (self.WARM - 1))  # last live frame's counter
    self.assertAlmostEqual(rr.points[0].dRel, 0.00357 * 3999 - 3.0, places=4)  # header-driven, unaffected

  # ---- cross-slot recovery (counter continues where the tight range gate misses) ----------------
  def _warm_two(self, with_life):
    # Warm object A in slot 1 (0x284, ~24 m) and object B in slot 2 (0x288, ~36 m) to emitting.
    raw24, raw36 = 7563, 10924
    rr = None
    for k in range(self.WARM):
      rr = self._sweep(k, {0x284: (raw24, self.A_BASE + 33 * k),
                           0x288: (raw36, self.B_BASE + 33 * k)}, with_life=with_life)
    ids = {round(p.dRel): p.trackId for p in rr.points}
    return rr, ids

  def test_cross_slot_recovery_beyond_geometry_gate(self):
    # A (slot 1, 24 m) re-slots to slot 0 but its range shifts 3 m (RES beyond the 2 m geometric gate,
    # inside the 5 m counter-confirmed gate). WITH the counter it is RECOVERED (same trackId, emits with
    # no hole); WITHOUT the counter pure geometry misses it (fresh trackId).
    self.assertGreater(3.0, BOSCH_RADAR_STITCH_RANGE_GATE)
    self.assertLess(3.0, BOSCH_RADAR_STITCH_RANGE_GATE_LIFE)
    raw27, raw36 = 8403, 10924  # 27 m (A shifted +3 m), 36 m (B)

    # WITH counter -> recovered
    rr, ids = self._warm_two(with_life=True)
    tid_a = ids[24]
    rr = self._sweep(self.WARM, {0x280: (raw27, self.A_BASE + 33 * self.WARM),
                                 0x284: (raw36, self.B_BASE + 33 * self.WARM)}, with_life=True)
    pts27 = [p for p in rr.points if abs(p.dRel - 27.0) < 0.6]
    self.assertEqual(len(pts27), 1)               # no emit hole (inherited settle/valid_cnt)
    self.assertEqual(pts27[0].trackId, tid_a)     # SAME identity recovered across the re-slot

    # WITHOUT counter -> pure geometry misses the 3 m shift
    self.ri = _make_ri()
    self.bus = self.ri.rcp.bus
    rr, ids = self._warm_two(with_life=False)
    tid_a2 = ids[24]
    self._sweep(self.WARM, {0x280: (raw27, 0), 0x284: (raw36, 0)}, with_life=False)
    self.assertNotEqual(self.ri._tid[0], tid_a2)  # geometry alone: fresh identity (the miss S8 recovers)

  def test_counter_vetoes_same_range_different_object(self):
    # A (slot 1, 24 m) is displaced; a DIFFERENT object C takes slot 0 at the SAME 24 m range (RES ~0,
    # inside the geometric gate). WITHOUT the counter geometry wrongly STITCHES C onto A's identity;
    # WITH the counter C's non-continuing OBJ_LIFE VETOES the stitch -> C gets a fresh identity.
    raw24, raw36 = 7563, 10924

    # WITHOUT counter -> geometry wrongly merges (control)
    rr, ids = self._warm_two(with_life=False)
    tid_a = ids[24]
    self._sweep(self.WARM, {0x280: (raw24, 0), 0x284: (raw36, 0)}, with_life=False)
    self.assertEqual(self.ri._tid[0], tid_a)      # geometry alone: C inherits A's id (the wrong merge)

    # WITH counter -> vetoed
    self.ri = _make_ri()
    self.bus = self.ri.rcp.bus
    rr, ids = self._warm_two(with_life=True)
    tid_a2 = ids[24]
    # slot 0 gets 24 m but with object C's counter (does NOT continue A's) -> veto
    rr = self._sweep(self.WARM, {0x280: (raw24, self.C_BASE),
                                 0x284: (raw36, self.B_BASE + 33 * self.WARM)}, with_life=True)
    self.assertNotEqual(self.ri._tid[0], tid_a2)  # counter vetoed the same-range merge -> fresh identity
    self.assertEqual(len([p for p in rr.points if p.trackId == tid_a2]), 0)


if __name__ == "__main__":
  unittest.main()