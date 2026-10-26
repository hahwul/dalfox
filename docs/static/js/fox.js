// The field — foxes running across a night meadow, drawn as a grid of
// monospace glyphs on a <canvas>. Loaded on the landing page only.
//
// How it works
//   world    : a handful of foxes trot along the ground plane (lower = nearer
//              = bigger), pick new lanes now and then, pause, turn at the
//              edges, steer clear of any element marked [data-fox-avoid],
//              and dash to a "lure" the visitor drops by clicking the field.
//   renderer : every frame each fox is rebuilt from a few dozen circles,
//              ellipses and capsules in fox-local coordinates, rasterised into
//              a cell grid with 2x2 sub-samples per cell, and each cell picks
//              a glyph from its coverage mask (edge cells get - | / \, full
//              cells get a dense glyph). Colours come from CSS custom
//              properties so the light/dark themes restyle the field for free.
//
// Respect for the reader: prefers-reduced-motion renders one still frame and
// never animates; the loop also stops while the canvas is scrolled out of
// view or the tab is hidden. No inline script, no network — CSP is
// `script-src 'self'`.
(function () {
  'use strict';

  var canvas = document.getElementById('field');
  if (!canvas || !canvas.getContext) return;
  var ctx = canvas.getContext('2d');
  if (!ctx) return;

  var TAU = Math.PI * 2;
  var DT = 1 / 60;
  var LURE_LIFE = 12;

  function clamp(v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; }
  function lerp(a, b, t) { return a + (b - a) * t; }
  function rand(lo, hi) { return lo + Math.random() * (hi - lo); }
  function smooth(t) { t = clamp(t, 0, 1); return t * t * (3 - 2 * t); }
  // Deterministic per-cell noise so ambient glyphs never flicker between frames.
  function hash(i, j, k) {
    var h = (Math.imul(i, 374761393) + Math.imul(j, 668265263) + Math.imul(k | 0, 2246822519)) | 0;
    h = Math.imul(h ^ (h >>> 13), 1274126177);
    return ((h ^ (h >>> 16)) >>> 0) / 4294967296;
  }

  // ---------------------------------------------------------------------------
  // Palette — read from the CSS tokens on the canvas, re-read on theme change.
  // ---------------------------------------------------------------------------
  var PART_BODY = 0, PART_TIP = 1, PART_SOCK = 2;
  var C_BODY = 0, C_TIP = 1, C_SOCK = 2, C_SHADOW = 3, C_GRASS = 4, C_GRASS2 = 5,
      C_STAR = 6, C_MOON = 7, C_LURE = 8, C_TRAIL = 9, C_EYE = 10,
      C_BODY2 = 11, C_TIP2 = 12, C_SOCK2 = 13, C_PREY = 14;
  var palette = [];
  function readPalette() {
    var cs = getComputedStyle(canvas);
    function v(name, fallback) {
      var val = cs.getPropertyValue(name).trim();
      return val || fallback;
    }
    palette = [
      v('--fox-body', '#d99a63'), v('--fox-tip', '#f3e9db'), v('--fox-sock', '#7a5a4a'),
      v('--fox-shadow', 'rgba(0,0,0,0.35)'), v('--field-grass', '#2a3352'), v('--field-grass-2', '#3a4470'),
      v('--field-star', '#7b86b8'), v('--field-moon', '#cfd6ee'), v('--field-lure', '#b1b8f5'),
      v('--field-trail', '#4a5480'), v('--bg', '#0b0d16'),
      v('--fox2-body', '#7f8ff0'), v('--fox2-tip', '#e3e7ff'), v('--fox2-sock', '#4651a0'),
      v('--field-prey', '#f07a7a')
    ];
  }

  // ---------------------------------------------------------------------------
  // World
  // ---------------------------------------------------------------------------
  function World() {
    this.w = 0; this.h = 0; this.time = 0;
    this.foxes = []; this.lures = []; this.trails = []; this.puffs = []; this.embers = [];
    this.avoid = [];
    this.pointer = { x: -1e9, y: -1e9, active: false, speed: 0 };
    this.luresDropped = 0;
  }

  World.prototype.resize = function (w, h) {
    this.w = w; this.h = h;
    var want = (w * h) < 350000 ? 2 : 3;
    while (this.foxes.length < want) this.spawn();
    while (this.foxes.length > want) this.foxes.pop();
    for (var i = 0; i < this.foxes.length; i++) {
      var f = this.foxes[i];
      f.y = clamp(f.y, this.groundMin(), this.groundMax());
      f.lane = clamp(f.lane, this.groundMin(), this.groundMax());
    }
  };
  World.prototype.groundMin = function () { return this.h * 0.3; };
  World.prototype.groundMax = function () { return this.h * 0.97; };

  World.prototype.spawn = function () {
    var i = this.foxes.length;
    var y = rand(i === 0 ? lerp(this.groundMin(), this.groundMax(), 0.45) : this.groundMin(), this.groundMax());
    this.foxes.push({
      id: i,
      seed: Math.random() * 1000,
      x: (i + 0.5) * (this.w / 3) + rand(-80, 80),
      y: y, lane: y,
      dir: Math.random() < 0.5 ? -1 : 1,
      big: i === 0,
      size: i === 0 ? 1.2 : 1,
      speed: 0, cruise: i === 0 ? rand(45, 80) : rand(55, 105),
      targetSpeed: 0,
      phase: Math.random() * TAU,
      state: 'trot', timer: rand(1, 5),
      nextLane: rand(3, 9),
      avoidUntil: 0,
      air: 0, pounceT: 0, pounceFrom: 0, pounceTo: 0, pounceY: 0,
      nod: 0, nodTarget: 0,
      lure: null,
      curiosity: rand(0.45, 1),
      L: 170,
      strideAcc: 0,
      startle: 0
    });
  };

  World.prototype.foxL = function (f, y) { return this.scaleFor(y) * f.size; };
  // The big one keeps to the near half of the field so its size reads.
  World.prototype.laneMin = function (f) { return f.big ? lerp(this.groundMin(), this.groundMax(), 0.45) : this.groundMin(); };
  World.prototype.scaleFor = function (y) {
    var depth = clamp((y - this.h * 0.25) / (this.h * 0.75), 0, 1);
    var base = this.w < 640 ? 0.78 : 1;
    return lerp(112, 225, depth) * base;
  };

  // A lane whose fox silhouette (here and a couple of seconds ahead) misses
  // every marked box; falls back to the current lane.
  World.prototype.laneClear = function (f, x, y) {
    var L = this.foxL(f, y);
    for (var k = 0; k < 2; k++) {
      var cx = x + f.dir * f.cruise * 2 * k;
      for (var b = 0; b < this.avoid.length; b++) {
        var r = this.avoid[b];
        if (cx + 0.95 * L > r.left - 10 && cx - 0.6 * L < r.right + 10 && y > r.top - 10 && y - 0.98 * L < r.bottom + 10) return false;
      }
    }
    return true;
  };
  World.prototype.pickLane = function (f) {
    for (var i = 0; i < 8; i++) {
      var y = rand(this.laneMin(f), this.groundMax());
      if (this.laneClear(f, f.x, y)) return y;
    }
    return f.lane;
  };

  World.prototype.feed = function (x, y) {
    if (this.lures.length >= 8) this.lures.shift();
    var lure = { x: x, y: clamp(y, this.groundMin() * 0.8, this.groundMax()), born: this.time, taken: false };
    this.lures.push(lure);
    this.luresDropped++;
    // The nearest fox always comes; the curious ones follow.
    var nearest = null, nd = Infinity;
    for (var i = 0; i < this.foxes.length; i++) {
      var f = this.foxes[i];
      if (f.state === 'pounce') continue;
      var d = Math.hypot(f.x - x, f.y - y);
      if (d < nd) { nd = d; nearest = f; }
      if (d < 900 && Math.random() < f.curiosity * 0.7) this.chase(f, lure);
    }
    if (nearest && nearest.state !== 'chase') this.chase(nearest, lure);
  };

  World.prototype.handOff = function (lure, except) {
    if (!lure || lure.taken) return;
    var best = null, bd = Infinity;
    for (var i = 0; i < this.foxes.length; i++) {
      var o = this.foxes[i];
      if (o === except || o.state === 'pounce' || o.state === 'chase') continue;
      var d = Math.hypot(o.x - lure.x, o.y - lure.y);
      if (d < bd) { bd = d; best = o; }
    }
    if (best) this.chase(best, lure);
  };

  World.prototype.chase = function (f, lure) {
    f.state = 'chase'; f.lure = lure; f.nodTarget = 0; f.timer = 12;
  };

  World.prototype.step = function (dt) {
    this.time += dt;
    var t = this.time;
    for (var i = 0; i < this.foxes.length; i++) this.stepFox(this.foxes[i], dt);
    // separation: two foxes sharing a lane drift apart, the trailing one eases off
    for (var a = 0; a < this.foxes.length; a++) {
      for (var b = a + 1; b < this.foxes.length; b++) {
        var fa = this.foxes[a], fb = this.foxes[b];
        var Lm = Math.max(fa.L, fb.L);
        var dx = fb.x - fa.x, dy = fb.y - fa.y;
        if (Math.abs(dx) < 1.5 * Lm && Math.abs(dy) < 0.45 * Lm) {
          var push = (dy >= 0 ? 1 : -1) * 0.4 * Lm;
          if (t > fa.avoidUntil) fa.lane = clamp(fa.y - push, this.groundMin(), this.groundMax());
          if (t > fb.avoidUntil) fb.lane = clamp(fb.y + push, this.groundMin(), this.groundMax());
          var trailing = (fa.dir === fb.dir) ? ((fa.dir > 0) === (fa.x < fb.x) ? fa : fb) : null;
          if (trailing && trailing.state === 'trot') trailing.speed *= 0.985;
        }
      }
    }
    for (var e = 0; e < this.embers.length; e++) {
      var em = this.embers[e];
      em.vy -= 14 * dt;
      em.x += (em.vx + Math.sin(t * 3 + em.seed) * 9) * dt;
      em.y += em.vy * dt;
    }
    this.embers = this.embers.filter(function (p) { return t - p.born < p.life; });
    this.trails = this.trails.filter(function (p) { return t - p.born < 2.6; });
    this.puffs = this.puffs.filter(function (p) { return t - p.born < 0.6; });
    this.lures = this.lures.filter(function (l) { return !l.taken && t - l.born < LURE_LIFE; });
    if (this.pointer.active) this.pointer.speed *= Math.pow(0.02, dt);
  };

  World.prototype.stepFox = function (f, dt) {
    var w = this.w, h = this.h, t = this.time;
    var L = this.foxL(f, f.y);
    f.timer -= dt;

    // --- state machine ----------------------------------------------------
    if (f.state === 'trot') {
      f.targetSpeed = f.cruise * (L / 170);
      f.nodTarget = 0;
      f.nextLane -= dt;
      if (f.nextLane <= 0 && t > f.avoidUntil) {
        f.lane = this.pickLane(f);
        f.nextLane = rand(4, 10);
      }
      if (f.timer <= 0) {
        f.state = 'idle'; f.timer = rand(1.4, 4);
      }
    } else if (f.state === 'idle') {
      f.targetSpeed = 0;
      f.nodTarget = Math.sin(t * 0.7 + f.seed) > 0.55 ? 0.5 : 0;
      if (f.timer <= 0) {
        f.state = 'trot'; f.timer = rand(7, 18);
        if (Math.random() < 0.4) f.dir = -f.dir;
      }
    } else if (f.state === 'chase') {
      var l = f.lure;
      if (!l || l.taken) { f.state = 'trot'; f.timer = rand(5, 12); f.lure = null; }
      else {
        var dx = l.x - f.x;
        if (Math.abs(dx) > 0.2 * L) f.dir = dx > 0 ? 1 : -1;
        f.targetSpeed = lerp(170, 260, f.curiosity) * (L / 170) * (f.big ? 0.8 : 1);
        f.lane = clamp(l.y, this.groundMin() * 0.8, this.groundMax());
        var closeX = Math.abs(dx) < 0.9 * L && (dx > 0) === (f.dir > 0);
        var closeY = Math.abs(l.y - f.y) < 0.18 * L;
        if (closeX && closeY) {
          f.state = 'pounce'; f.pounceT = 0; f.pounceFrom = f.x; f.pounceTo = l.x - f.dir * 0.25 * L;
          f.pounceY = f.y;
        }
        if (f.timer <= 0) { var give = f.lure; f.state = 'trot'; f.timer = rand(5, 12); f.lure = null; this.handOff(give, f); }
      }
    } else if (f.state === 'pounce') {
      var T = 0.62;
      f.pounceT += dt;
      var k = clamp(f.pounceT / T, 0, 1);
      f.x = lerp(f.pounceFrom, f.pounceTo, smooth(k));
      f.air = Math.sin(k * Math.PI) * 0.42 * L;
      f.targetSpeed = 0; f.speed = 0;
      if (k >= 1) {
        f.air = 0;
        if (f.lure) {
          f.lure.taken = true;
          for (var p = 0; p < 10; p++) {
            var a = (p / 10) * TAU + rand(-0.2, 0.2);
            this.puffs.push({ x: f.lure.x, y: f.lure.y - 4, a: a, born: t, r: rand(0.6, 1.1), g: '<>/"=()\'`;'.charAt(p % 10) });
          }
          f.lure = null;
        }
        f.state = 'sniff'; f.timer = rand(1.2, 2.4);
      }
    } else if (f.state === 'sniff') {
      f.targetSpeed = 0; f.nodTarget = 1;
      if (f.timer <= 0) { f.state = 'trot'; f.timer = rand(6, 14); f.nodTarget = 0; if (Math.random() < 0.5) f.dir = -f.dir; }
    }

    // --- pointer: slow down when it hovers close; bolt when it rushes in ----
    var ptr = this.pointer;
    if (ptr.active && f.state !== 'pounce') {
      var pd = Math.hypot(ptr.x - f.x, ptr.y - (f.y - 0.4 * L));
      if (pd < 1.1 * L) {
        if (ptr.speed > 1400 && f.startle <= 0) {
          f.startle = 1.1; f.dir = ptr.x < f.x ? 1 : -1;
          if (f.state === 'idle' || f.state === 'sniff') { f.state = 'trot'; f.timer = rand(6, 14); }
        } else if (f.state === 'trot') {
          f.targetSpeed *= 0.35;
          f.nodTarget = 0.3;
        }
      }
    }
    if (f.startle > 0) { f.startle -= dt; f.targetSpeed = Math.max(f.targetSpeed, 240 * (L / 170)); }

    // --- edges: turn before leaving the frame -----------------------------
    if (f.state !== 'pounce') {
      if (f.dir > 0 && f.x > w - 0.9 * L) f.dir = -1;
      if (f.dir < 0 && f.x < 0.9 * L) f.dir = 1;
      if (f.x < -0.3 * L) f.x = -0.3 * L;
      if (f.x > w + 0.3 * L) f.x = w + 0.3 * L;
    }

    // --- content avoidance: steer the lane around marked boxes ------------
    var ahead = f.x + f.dir * f.speed * 0.7;
    var left = Math.min(f.x, ahead) - 0.55 * L, right = Math.max(f.x, ahead) + 0.9 * L;
    var top = f.y - 0.95 * L, bottom = f.y + 0.04 * L;
    for (var b = 0; b < this.avoid.length; b++) {
      var r = this.avoid[b];
      if (right < r.left || left > r.right || bottom < r.top || top > r.bottom) continue;
      var below = r.bottom + 0.98 * L;
      var above = r.top - 0.08 * L;
      var canBelow = below <= this.groundMax();
      var canAbove = above >= this.groundMin() * 0.85;
      var target;
      if (canBelow && canAbove) target = (below - f.y) < (f.y - above) ? below : above;
      else if (canBelow) target = below;
      else if (canAbove) target = above;
      else { // nowhere to go in this column: turn back
        if (f.state !== 'pounce') f.dir = -f.dir;
        continue;
      }
      f.lane = target;
      f.avoidUntil = t + 2.5;
      // Already overlapping (resize, or a box that grew): hurry.
      var overlapping = f.x + 0.9 * L > r.left && f.x - 0.55 * L < r.right && bottom > r.top && top < r.bottom;
      if (overlapping) f.y += Math.sign(target - f.y) * 140 * dt;
      break;
    }

    // --- motion -----------------------------------------------------------
    var accel = f.targetSpeed > f.speed ? 220 : 320;
    f.speed += clamp(f.targetSpeed - f.speed, -accel * dt, accel * dt);
    if (f.state !== 'pounce') {
      f.x += f.dir * f.speed * dt;
      var dy = f.lane - f.y;
      var rate = (t < f.avoidUntil ? 70 : 26) + f.speed * 0.15;
      f.y += clamp(dy, -rate * dt, rate * dt);
    }
    f.nod += (f.nodTarget - f.nod) * Math.min(1, 4 * dt);

    // gait: stride length ~0.75 body lengths
    var cyc = f.speed / (0.75 * L);
    var prev = f.phase;
    f.phase += cyc * TAU * dt;
    if (f.speed > 40 && Math.floor(f.phase / Math.PI) !== Math.floor(prev / Math.PI)) {
      this.trails.push({ x: f.x - f.dir * rand(0.05, 0.3) * L, y: f.y, born: t, blue: f.big });
      if (this.trails.length > 120) this.trails.shift();
    }
    if (f.big) {
      var rate = f.speed > 15 ? 9 : 2.5;
      if (Math.random() < rate * dt) {
        this.embers.push({
          x: f.x - f.dir * rand(0.55, 0.85) * L + rand(-6, 6),
          y: f.y - f.air - rand(0.35, 0.6) * L,
          vx: -f.dir * rand(4, 18), vy: rand(-26, -10),
          born: t, life: rand(1.1, 2.1), seed: Math.random() * 10
        });
        if (this.embers.length > 60) this.embers.shift();
      }
    }
    if (f.phase > 1e4) f.phase -= 1e4;
  };

  // ---------------------------------------------------------------------------
  // Fox geometry — painted each frame onto a tiny offscreen canvas in
  // fox-local units (x forward, y up, 1 = body length, origin under the chest
  // on the ground), two pixels per cell on each axis. The renderer then reads
  // the pixels back as a coverage mask. Parts are encoded in the colour
  // channels: R = body, G = tail tip / chest, B = socks, black = eye.
  // ---------------------------------------------------------------------------
  var off = document.createElement('canvas');
  var octx = off.getContext('2d', { willReadFrequently: true });
  var COL_BODY = '#ff0000', COL_TIP = '#00ff00', COL_SOCK = '#0000ff', COL_EYE = '#000000';

  function paintFox(g, f, t) {
    var amp = clamp(f.speed / (120 * (f.L / 170)), 0, 1.3);
    var run = Math.min(1, amp);
    var phi = f.phase;
    var airborne = f.state === 'pounce';
    var pk = airborne ? clamp(f.pounceT / 0.62, 0, 1) : 0;
    var bob = 0.045 * amp * Math.max(0, Math.sin(phi));
    var pitch = airborne ? -0.3 * Math.sin(pk * Math.PI) : 0.1 * amp * Math.sin(phi - 0.5);
    var nod = f.nod;
    var by = 0.47 + bob;
    g.lineCap = 'round'; g.lineJoin = 'round';

    // --- tail: a bushy S-curve. At rest it drops from the rump and curls up
    // at the tip; at a run it streams back. Fluff circles along the curve give
    // it volume, the last third is the cream brush. -------------------------
    var rest = 1 - run;
    var sway = 0.08 * Math.sin(t * (f.speed < 10 ? 2.2 : 3.6) + f.seed) * (f.speed < 10 ? 1 : 0.5);
    var lift = airborne ? 0.3 : 0;
    var p0x = -0.27, p0y = by + 0.06;
    var c1x = -0.55, c1y = by - 0.2 * rest + 0.04 * run + sway + lift;
    var c2x = -0.9, c2y = by - 0.1 * rest + 0.12 * run + sway * 1.5 + lift;
    var p3x = -0.92 + 0.08 * rest, p3y = by + 0.3 * rest + 0.2 * run + sway * 2 + lift - pitch * 0.3;
    function cp(tt) {
      var u = 1 - tt, a = u * u * u, b = 3 * u * u * tt, c = 3 * u * tt * tt, d = tt * tt * tt;
      return [a * p0x + b * c1x + c * c2x + d * p3x, a * p0y + b * c1y + c * c2y + d * p3y];
    }
    g.strokeStyle = COL_BODY;
    g.lineWidth = 0.24; g.beginPath(); g.moveTo(p0x, p0y); g.bezierCurveTo(c1x, c1y, c2x, c2y, p3x, p3y); g.stroke();
    g.fillStyle = COL_BODY;
    var fluff = [[0.18, 0.14], [0.36, 0.165], [0.54, 0.165], [0.7, 0.15]];
    for (var fi = 0; fi < fluff.length; fi++) {
      var fp = cp(fluff[fi][0]);
      g.beginPath(); g.ellipse(fp[0], fp[1], fluff[fi][1], fluff[fi][1] * 0.9, 0, 0, TAU); g.fill();
    }
    g.strokeStyle = COL_TIP; g.lineWidth = 0.2;
    var n = cp(0.72), n2 = cp(0.86);
    g.beginPath(); g.moveTo(n[0], n[1]); g.quadraticCurveTo(n2[0], n2[1], p3x, p3y); g.stroke();
    g.fillStyle = COL_TIP; g.beginPath(); g.ellipse(n2[0], n2[1], 0.12, 0.11, 0, 0, TAU); g.fill();

    // --- legs: shoulder/hip -> knee -> paw ------------------------------------
    var A = 0.8 * amp, K = 1.15 * amp;
    function leg(px, py, ph, rear, tuck) {
      var up = tuck ? (rear ? 0.9 : -0.6) : A * Math.sin(ph);
      var bend = tuck ? 1.5 : K * Math.max(0, -Math.sin(ph + 0.3));
      var low = tuck ? up + (rear ? 1.3 : -1.6) : up - bend * (rear ? -0.9 : 1);
      var lu = 0.21, ll = 0.21;
      var kx = px + Math.sin(up) * lu, ky = py - Math.cos(up) * lu;
      var fx = kx + Math.sin(low) * ll, fy = ky - Math.cos(low) * ll;
      g.strokeStyle = COL_BODY; g.lineWidth = 0.12;
      g.beginPath(); g.moveTo(px, py); g.lineTo(kx, ky); g.stroke();
      g.strokeStyle = COL_SOCK; g.lineWidth = 0.085;
      g.beginPath(); g.moveTo(kx, ky); g.lineTo(fx, fy); g.stroke();
      g.fillStyle = COL_SOCK; g.beginPath(); g.ellipse(fx + 0.015, fy + 0.012, 0.055, 0.04, 0, 0, TAU); g.fill();
    }
    leg(-0.2, by - 0.04, phi + Math.PI, true, airborne);
    leg(0.22, by - 0.05, phi + 0.5, false, airborne);

    // --- body --------------------------------------------------------------
    g.fillStyle = COL_BODY;
    // spine arches over the middle, belly tucks up toward the hips (the waist)
    var arch = 0.1 + 0.05 * Math.max(0, Math.sin(phi + 0.6)) * amp;
    g.beginPath();
    g.moveTo(0.3, by + 0.13);
    g.quadraticCurveTo(0.0, by + 0.17 + arch, -0.3, by + 0.1);
    g.lineTo(-0.3, by - 0.02);
    g.quadraticCurveTo(-0.05, by - 0.13, 0.3, by - 0.15);
    g.closePath(); g.fill();
    g.beginPath(); g.ellipse(0.25, by - 0.01, 0.165, 0.16, 0, 0, TAU); g.fill();   // chest
    g.beginPath(); g.ellipse(-0.24, by + 0.03, 0.14, 0.135, 0, 0, TAU); g.fill();  // rump

    leg(-0.22, by - 0.03, phi + Math.PI + 0.45, true, airborne);
    leg(0.25, by - 0.04, phi, false, airborne);

    // chest bib
    g.fillStyle = COL_TIP; g.beginPath(); g.ellipse(0.31, by - 0.07, 0.075, 0.065, 0, 0, TAU); g.fill();

    // --- neck + head (nod lowers and extends the head) ----------------------
    var hx = 0.52 + 0.1 * nod, hy = by + 0.21 - 0.27 * nod;
    g.strokeStyle = COL_BODY; g.lineWidth = 0.21;
    g.beginPath(); g.moveTo(0.27, by + 0.05); g.lineTo(hx - 0.07, hy - 0.04); g.stroke();
    g.fillStyle = COL_BODY;
    g.beginPath(); g.ellipse(hx, hy, 0.145, 0.115, 0.15 + 0.5 * nod, 0, TAU); g.fill();
    g.fillStyle = COL_TIP; g.beginPath(); g.ellipse(hx - 0.02, hy - 0.08, 0.075, 0.05, 0.2, 0, TAU); g.fill(); // cheek ruff
    g.fillStyle = COL_BODY;
    // muzzle: tapering stroke
    g.lineWidth = 0.1; g.beginPath(); g.moveTo(hx + 0.06, hy - 0.01); g.lineTo(hx + 0.18, hy - 0.06 - 0.06 * nod); g.stroke();
    g.lineWidth = 0.055; g.beginPath(); g.moveTo(hx + 0.17, hy - 0.06 - 0.06 * nod); g.lineTo(hx + 0.25, hy - 0.085 - 0.08 * nod); g.stroke();
    // cream jaw
    g.strokeStyle = COL_TIP; g.lineWidth = 0.045;
    g.beginPath(); g.moveTo(hx + 0.08, hy - 0.07); g.lineTo(hx + 0.2, hy - 0.1 - 0.06 * nod); g.stroke();
    // ears: two triangles, the fox tell
    g.fillStyle = COL_BODY;
    var ea = -0.25 * nod;
    g.beginPath(); g.moveTo(hx - 0.12, hy + 0.05); g.lineTo(hx - 0.13 + ea, hy + 0.34); g.lineTo(hx + 0.0, hy + 0.09); g.closePath(); g.fill();
    g.beginPath(); g.moveTo(hx + 0.0, hy + 0.06); g.lineTo(hx + 0.03 + ea, hy + 0.35); g.lineTo(hx + 0.13, hy + 0.07); g.closePath(); g.fill();
    // eye
    g.fillStyle = COL_EYE; g.beginPath(); g.ellipse(hx + 0.05, hy + 0.03, 0.034, 0.034, 0, 0, TAU); g.fill();
  }

  // ---------------------------------------------------------------------------
  // Renderer — the glyph grid
  // ---------------------------------------------------------------------------
  var GLYPH = [];
  // coverage mask bits: TL=1 TR=2 BL=4 BR=8
  GLYPH[0] = ''; GLYPH[1] = "'"; GLYPH[2] = "'"; GLYPH[4] = '.'; GLYPH[8] = '.';
  GLYPH[3] = '-'; GLYPH[12] = '_'; GLYPH[5] = '|'; GLYPH[10] = '|'; GLYPH[6] = '/'; GLYPH[9] = '\\';
  GLYPH[7] = '%'; GLYPH[11] = '%'; GLYPH[13] = '&'; GLYPH[14] = '&'; GLYPH[15] = '@';
  var DENSE = ['@', '#', '@', '@', '#', '8', '@', '&'];
  var SAMPLES = [[-0.25, -0.25], [0.25, -0.25], [-0.25, 0.25], [0.25, 0.25]];

  function Renderer() {
    this.cw = 10; this.ch = 13; this.cols = 0; this.rows = 0; this.dpr = 1;
    this.glyph = null; this.color = null; this.alpha = null; this.dim = null;
    this.fontFamily = getComputedStyle(canvas).fontFamily || 'monospace';
  }

  Renderer.prototype.resize = function (w, h, dpr) {
    this.dpr = dpr;
    this.ch = clamp(Math.round(w / 110), 11, 15);
    this.cw = Math.round(this.ch * 0.6);
    this.cols = Math.ceil(w / this.cw);
    this.rows = Math.ceil(h / this.ch);
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    var n = this.cols * this.rows;
    this.glyph = new Uint16Array(n);
    this.color = new Uint8Array(n);
    this.alpha = new Float32Array(n);
    this.dim = new Float32Array(n).fill(1);
    this.dimKey = '';
  };

  Renderer.prototype.setDimBoxes = function (boxes) {
    var key = this.cols + 'x' + this.rows + ':' + boxes.map(function (o) {
      return Math.round(o.left) + ',' + Math.round(o.top) + ',' + Math.round(o.right) + ',' + Math.round(o.bottom);
    }).join(';');
    if (key === this.dimKey) return;
    this.dimKey = key;
    var cols = this.cols, rows = this.rows, cw = this.cw, ch = this.ch, dim = this.dim;
    dim.fill(1);
    var m = 3.5 * cw;
    for (var b = 0; b < boxes.length; b++) {
      var o = boxes[b];
      var c0 = Math.max(0, Math.floor((o.left - m) / cw)), c1 = Math.min(cols - 1, Math.floor((o.right + m) / cw));
      var r0 = Math.max(0, Math.floor((o.top - m) / ch)), r1 = Math.min(rows - 1, Math.floor((o.bottom + m) / ch));
      for (var r = r0; r <= r1; r++) {
        for (var c = c0; c <= c1; c++) {
          var x = c * cw + cw / 2, y = r * ch + ch / 2;
          var d = Math.hypot(Math.max(o.left - x, 0, x - o.right), Math.max(o.top - y, 0, y - o.bottom));
          var i = r * cols + c;
          dim[i] = Math.min(dim[i], 0.1 + 0.9 * smooth(d / m));
        }
      }
    }
  };

  Renderer.prototype.put = function (c, r, ch, color, a) {
    if (c < 0 || r < 0 || c >= this.cols || r >= this.rows) return;
    var i = r * this.cols + c;
    this.glyph[i] = ch.charCodeAt(0);
    this.color[i] = color;
    this.alpha[i] = a;
  };

  Renderer.prototype.render = function (world, t) {
    var cols = this.cols, rows = this.rows;
    if (!cols) return;
    this.glyph.fill(0);
    this.drawAmbient(world, t);
    this.drawTrails(world);
    this.drawLures(world);
    var foxes = world.foxes.slice().sort(function (a, b) { return a.y - b.y; });
    for (var i = 0; i < foxes.length; i++) this.drawShadow(world, foxes[i]);
    for (var j = 0; j < foxes.length; j++) this.drawFox(world, foxes[j]);
    this.drawPuffs(world);
    this.drawEmbers(world);

    var c = ctx, dpr = this.dpr, cw = this.cw, ch = this.ch;
    c.setTransform(1, 0, 0, 1, 0, 0);
    c.clearRect(0, 0, canvas.width, canvas.height);
    c.setTransform(dpr, 0, 0, dpr, 0, 0);
    c.font = '600 ' + (ch * 0.98).toFixed(1) + 'px ' + this.fontFamily;
    c.textAlign = 'center';
    c.textBaseline = 'middle';
    var lastColor = -1, lastAlpha = -1;
    var glyph = this.glyph, color = this.color, alpha = this.alpha, dim = this.dim;
    for (var r = 0; r < rows; r++) {
      var y = r * ch + ch / 2;
      for (var k = 0; k < cols; k++) {
        var idx = r * cols + k;
        var g = glyph[idx];
        if (!g) continue;
        var a = alpha[idx] * dim[idx];
        if (a < 0.02) continue;
        if (color[idx] !== lastColor) { lastColor = color[idx]; c.fillStyle = palette[lastColor]; }
        if (a !== lastAlpha) { lastAlpha = a; c.globalAlpha = a; }
        c.fillText(String.fromCharCode(g), k * cw + cw / 2, y);
      }
    }
    c.globalAlpha = 1;
  };

  Renderer.prototype.drawAmbient = function (world, t) {
    var cols = this.cols, rows = this.rows, cw = this.cw, ch = this.ch;
    var h = world.h, w = world.w;
    var horizon = h * 0.42;
    var starsOn = palette[C_STAR] !== 'transparent';
    var GR = [',', "'", '`', '.', '"'];
    for (var r = 0; r < rows; r++) {
      var y = r * ch + ch / 2;
      for (var c = 0; c < cols; c++) {
        var h1 = hash(c, r, 7);
        if (y > horizon) {
          var g = (y - horizon) / (h - horizon);
          var p = g * g * 0.26 + 0.006;
          if (h1 < p) {
            var h2 = hash(c, r, 11);
            var sway = Math.sin(t * 0.9 + c * 0.35 + h2 * 6) > 0.75;
            var ci = Math.floor(h2 * GR.length);
            if (sway) ci = (ci + 1) % GR.length;
            this.put(c, r, GR[ci], h2 < 0.5 ? C_GRASS : C_GRASS2, 0.55 + 0.45 * g);
          }
        } else if (starsOn) {
          var p2 = 0.014 * (1 - y / horizon);
          if (h1 < p2) {
            var h3 = hash(c, r, 13);
            var tw = 0.35 + 0.65 * Math.abs(Math.sin(t * 0.5 + h3 * 20));
            this.put(c, r, h3 < 0.12 ? '+' : '.', C_STAR, tw * 0.9);
          }
        }
      }
    }
    // Crescent moon, top-right, rasterised with the same mask ramp as the foxes.
    var R = 8.5 * ch, mx = w * 0.64, my = h * 0.2;
    if (w < 640) { R = 6 * ch; mx = w * 0.7; my = h * 0.13; }
    var c0 = Math.floor((mx - R) / cw), c1 = Math.ceil((mx + R) / cw);
    var r0 = Math.floor((my - R) / ch), r1 = Math.ceil((my + R) / ch);
    for (var rr = r0; rr <= r1; rr++) {
      for (var cc = c0; cc <= c1; cc++) {
        var mask = 0;
        for (var s = 0; s < 4; s++) {
          var sx = cc * cw + cw * (0.5 + SAMPLES[s][0]), sy = rr * ch + ch * (0.5 + SAMPLES[s][1]);
          var inA = Math.hypot(sx - mx, sy - my) <= R;
          var inB = Math.hypot(sx - (mx + 0.5 * R), sy - (my - 0.16 * R)) <= R * 0.93;
          if (inA && !inB) mask |= 1 << s;
        }
        if (mask) this.put(cc, rr, mask === 15 ? DENSE[Math.floor(hash(cc, rr, 3) * DENSE.length)] : GLYPH[mask], C_MOON, mask === 15 ? 0.9 : 0.7);
      }
    }
  };

  Renderer.prototype.drawTrails = function (world) {
    for (var i = 0; i < world.trails.length; i++) {
      var p = world.trails[i];
      var age = (world.time - p.born) / 2.6;
      this.put(Math.floor(p.x / this.cw), Math.floor(p.y / this.ch), age < 0.3 ? ':' : '.', p.blue ? C_BODY2 : C_TRAIL, (p.blue ? 0.6 : 0.8) * (1 - age));
    }
  };

  // The lure is the prey itself: "XSS" sitting in the grass, pulsing, with a
  // pair of angle brackets that blink around it like a half-typed tag.
  Renderer.prototype.drawLures = function (world) {
    for (var i = 0; i < world.lures.length; i++) {
      var l = world.lures[i];
      var age = world.time - l.born;
      var c = Math.floor(l.x / this.cw), r = Math.floor(l.y / this.ch);
      var fade = clamp((LURE_LIFE - age) / 3, 0, 1);
      var pulse = (0.7 + 0.3 * Math.sin(age * 5)) * fade;
      this.put(c - 1, r, 'X', C_PREY, pulse);
      this.put(c, r, 'S', C_PREY, pulse);
      this.put(c + 1, r, 'S', C_PREY, pulse);
      var blink = Math.floor(age * 2.5) % 2 === 0;
      this.put(c - 2, r, blink ? '<' : ' ', C_PREY, 0.45 * fade);
      this.put(c + 2, r, blink ? '>' : ' ', C_PREY, 0.45 * fade);
      this.put(c, r + 1, '~', C_SHADOW, 0.6 * fade);
    }
  };

  Renderer.prototype.drawEmbers = function (world) {
    for (var i = 0; i < world.embers.length; i++) {
      var p = world.embers[i];
      var age = (world.time - p.born) / p.life;
      var g = age < 0.25 ? '*' : age < 0.6 ? '+' : '.';
      this.put(Math.floor(p.x / this.cw), Math.floor(p.y / this.ch), g, age < 0.45 ? C_TIP2 : C_BODY2, 0.95 * (1 - age * age));
    }
  };

  Renderer.prototype.drawPuffs = function (world) {
    for (var i = 0; i < world.puffs.length; i++) {
      var p = world.puffs[i];
      var age = (world.time - p.born) / 0.6;
      var d = (0.5 + age * 2.2) * this.ch * p.r;
      var x = p.x + Math.cos(p.a) * d * 1.4, y = p.y + Math.sin(p.a) * d * 0.6;
      this.put(Math.floor(x / this.cw), Math.floor(y / this.ch), age < 0.7 ? p.g : '.', C_PREY, 1 - age);
    }
  };

  Renderer.prototype.drawShadow = function (world, f) {
    var L = world.foxL(f, f.y);
    var squash = 1 - clamp(f.air / (0.5 * L), 0, 0.7);
    var half = 0.42 * L * squash;
    var r = Math.floor(f.y / this.ch);
    var c0 = Math.floor((f.x - half) / this.cw), c1 = Math.floor((f.x + half) / this.cw);
    for (var c = c0; c <= c1; c++) {
      var k = Math.abs((c * this.cw + this.cw / 2 - f.x) / half);
      this.put(c, r, k > 0.8 ? '.' : '~', C_SHADOW, (0.75 - 0.4 * k) * squash);
    }
  };

  Renderer.prototype.drawFox = function (world, f) {
    var L = world.foxL(f, f.y);
    f.L = L;
    var cw = this.cw, ch = this.ch, cols = this.cols, rows = this.rows;
    var ox = f.x, oy = f.y - f.air, dir = f.dir;

    // fox bbox in cells (clamped to the grid)
    var c0 = Math.max(0, Math.floor((ox - 1.15 * L) / cw)), c1 = Math.min(cols - 1, Math.floor((ox + 1.15 * L) / cw));
    var r0 = Math.max(0, Math.floor((oy - 1.15 * L) / ch)), r1 = Math.min(rows - 1, Math.floor((oy + 0.08 * L) / ch));
    if (c1 < c0 || r1 < r0) return;
    var gw = c1 - c0 + 1, gh = r1 - r0 + 1;
    var pw = gw * 2, ph = gh * 2;
    if (off.width !== pw || off.height !== ph) { off.width = pw; off.height = ph; }
    octx.setTransform(1, 0, 0, 1, 0, 0);
    octx.clearRect(0, 0, pw, ph);
    // local units -> offscreen pixels (2 per cell); y flips
    octx.setTransform(dir * L * 2 / cw, 0, 0, -L * 2 / ch, (ox - c0 * cw) * 2 / cw, (oy - r0 * ch) * 2 / ch);
    paintFox(octx, f, world.time);
    var px = octx.getImageData(0, 0, pw, ph).data;

    var eyeIsBg = C_EYE;
    for (var r = 0; r < gh; r++) {
      for (var c = 0; c < gw; c++) {
        var mask = 0, cb = 0, ct = 0, cs = 0, ce = 0;
        for (var q = 0; q < 4; q++) {
          var sx = c * 2 + (q & 1), sy = r * 2 + (q >> 1);
          var i = (sy * pw + sx) * 4;
          if (px[i + 3] < 110) continue;
          mask |= 1 << q;
          var R = px[i], G = px[i + 1], B = px[i + 2];
          if (R >= G && R >= B && R > 60) cb++;
          else if (G >= B && G > 60) ct++;
          else if (B > 60) cs++;
          else ce++;
        }
        if (!mask) continue;
        var col = ct > cb && ct >= cs ? (f.big ? C_TIP2 : C_TIP) : cs > cb && cs > ct ? (f.big ? C_SOCK2 : C_SOCK) : (f.big ? C_BODY2 : C_BODY);
        var glyph;
        if (mask === 15) {
          var salt = f.big && hash(c + c0, r + r0, 99) < 0.3 ? Math.floor(world.time * 2.5) : f.id * 7 + 1;
          glyph = DENSE[Math.floor(hash(c + c0, r + r0, salt) * DENSE.length)];
        }
        else glyph = GLYPH[mask];
        if (ce >= 2) { glyph = 'o'; col = eyeIsBg; }
        this.put(c + c0, r + r0, glyph, col, 1);
      }
    }
  };

  // ---------------------------------------------------------------------------
  // Controller — sizing, loop, input, stats
  // ---------------------------------------------------------------------------
  var world = new World();
  var renderer = new Renderer();
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  var raf = 0, last = 0, acc = 0, frames = 0, visible = true, lastPointerT = 0;
  var statEl = document.querySelector('.field-stat');
  var fieldEl = canvas.parentElement;
  var rect = { left: 0, top: 0, width: 0, height: 0 };
  var countEl = document.getElementById('fox-count');

  function mergeBoxes(boxes) {
    var out = [];
    boxes.sort(function (a, b) { return a.top - b.top; });
    for (var i = 0; i < boxes.length; i++) {
      var b = boxes[i], hit = null;
      for (var j = 0; j < out.length; j++) {
        var o = out[j];
        if (b.top - o.bottom < 120 && b.left - o.right < 120 && o.left - b.right < 120) { hit = o; break; }
      }
      if (!hit) out.push({ left: b.left, top: b.top, right: b.right, bottom: b.bottom });
      else { hit.left = Math.min(hit.left, b.left); hit.right = Math.max(hit.right, b.right); hit.bottom = Math.max(hit.bottom, b.bottom); hit.top = Math.min(hit.top, b.top); }
    }
    return out;
  }

  function settle() {
    for (var i = 0; i < world.foxes.length; i++) {
      var f = world.foxes[i];
      var best = null, bestScore = -1;
      for (var tries = 0; tries < 24; tries++) {
        var y = tries === 0 ? f.y : rand(world.laneMin(f), world.groundMax());
        var L = world.foxL(f, y);
        var x = tries === 0 ? f.x : rand(0.4 * L, world.w - 0.4 * L);
        if (!world.laneClear(f, x, y)) continue;
        var score = Infinity;
        for (var j = 0; j < world.foxes.length; j++) {
          if (j === i) continue;
          var o = world.foxes[j];
          score = Math.min(score, Math.hypot((x - o.x) / 1.6, y - o.y) / L);
        }
        if (score > bestScore) { bestScore = score; best = { x: x, y: y }; }
        if (tries === 0 && score > 1.2) break;
      }
      if (best) { f.x = best.x; f.y = f.lane = best.y; }
    }
  }

  function measureContent() {
    var cr = rect = canvas.getBoundingClientRect();
    var boxes = Array.prototype.map.call(document.querySelectorAll('[data-fox-avoid]'), function (el) {
      var r = el.getBoundingClientRect();
      return { left: r.left - cr.left, top: r.top - cr.top, right: r.right - cr.left, bottom: r.bottom - cr.top };
    }).filter(function (b) { return b.right > b.left && b.bottom > b.top; });
    var merged = mergeBoxes(boxes);
    renderer.setDimBoxes(merged);
    world.avoid = merged;
  }

  function report() {
    if (countEl) countEl.textContent = String(world.foxes.length);
    if (statEl) statEl.setAttribute('data-lures', String(world.luresDropped));
  }

  function resize() {
    var r = canvas.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return;
    renderer.resize(r.width, r.height, Math.min(window.devicePixelRatio || 1, 2));
    world.resize(r.width, r.height);
    measureContent();
    settle();
    report();
    if (reduced.matches) drawStill();
  }

  function drawStill() {
    canvas.classList.add('is-still');
    if (world.time < 6) for (var i = 0; i < 420; i++) world.step(DT);
    measureContent();
    renderer.render(world, world.time);
  }

  function frame(now) {
    if (now - last < 28) { raf = requestAnimationFrame(frame); return; }
    var dt = Math.min(0.1, (now - last) / 1000);
    last = now;
    acc += dt;
    var steps = 0;
    while (acc >= DT && steps < 4) { world.step(DT); acc -= DT; steps++; }
    if (steps === 4) acc = 0;
    if (++frames % 30 === 0) measureContent();
    renderer.render(world, world.time);
    raf = requestAnimationFrame(frame);
  }

  function running() { return visible && !document.hidden && !(fieldEl && fieldEl.classList.contains('is-covered')); }

  function schedule() {
    cancelAnimationFrame(raf);
    raf = 0;
    if (!running()) return;
    if (reduced.matches) { drawStill(); return; }
    canvas.classList.remove('is-still');
    last = performance.now();
    raf = requestAnimationFrame(frame);
  }

  // Uses the rect cached by measureContent (refreshed every ~30 frames and on
  // resize), so pointer events never force a synchronous layout. The field is
  // sticky at the top of the viewport, so the rect barely moves.
  function toLocal(e) {
    var x = e.clientX - rect.left, y = e.clientY - rect.top;
    return { x: x, y: y, inside: x >= 0 && y >= 0 && x <= rect.width && y <= rect.height };
  }

  window.addEventListener('pointermove', function (e) {
    if (!raf) return;
    var p = toLocal(e), ptr = world.pointer;
    var dtp = Math.max(1, e.timeStamp - lastPointerT) / 1000;
    var sp = Math.hypot(p.x - ptr.x, p.y - ptr.y) / dtp;
    ptr.speed += (Math.min(sp, 5000) - ptr.speed) * 0.5;
    lastPointerT = e.timeStamp;
    ptr.x = p.x; ptr.y = p.y;
    ptr.active = p.inside && e.pointerType !== 'touch';
  }, { passive: true });
  function pointerLeave() { world.pointer.active = false; world.pointer.speed = 0; }
  document.documentElement.addEventListener('pointerleave', pointerLeave);
  window.addEventListener('blur', pointerLeave);

  window.addEventListener('click', function (e) {
    if (reduced.matches) return;
    var path = e.composedPath ? e.composedPath() : [];
    for (var i = 0; i < path.length; i++) {
      var el = path[i];
      if (el instanceof Element && el.matches('a, button, input, textarea, select, label, [role="button"], [data-fox-ignore], [data-fox-avoid]')) return;
    }
    if (!raf) return;
    var sel = window.getSelection && window.getSelection();
    if (sel && sel.toString()) return;
    measureContent();
    var p = toLocal(e);
    if (!p.inside) return;
    world.feed(p.x, p.y);
    if (statEl) statEl.classList.remove('show-hint');
    report();
  });

  if (statEl && !reduced.matches) {
    setTimeout(function () { if (world.luresDropped === 0) statEl.classList.add('show-hint'); }, 2600);
  }

  // theme changes re-colour the field
  new MutationObserver(function () { readPalette(); if (reduced.matches) drawStill(); })
    .observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

  if (fieldEl) new MutationObserver(function () { if (running() !== !!raf) schedule(); })
    .observe(fieldEl, { attributes: true, attributeFilter: ['class'] });
  new ResizeObserver(resize).observe(canvas);
  new IntersectionObserver(function (entries) { visible = entries[0].isIntersecting; schedule(); }).observe(canvas);
  document.addEventListener('visibilitychange', schedule);
  reduced.addEventListener('change', schedule);
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(function () { if (reduced.matches) drawStill(); });

  readPalette();
  resize();
  schedule();
})();
