// The field — foxes running across a night meadow, drawn as a grid of
// monospace glyphs on a <canvas>. Loaded on the landing page only.
//
// How it works
//   world    : a handful of foxes live on the ground plane (lower = nearer
//              = bigger). Between trots they idle, sit and watch the cursor,
//              curl up to sleep, stretch, hop, or crouch and pounce on a mouse
//              in the grass. They turn at the edges, steer clear of any
//              element marked [data-fox-avoid], and dash to the <XSS> the
//              visitor drops by clicking the field.
//   renderer : every frame each fox is painted from a blend of poses (stand,
//              sit, bow, dive, crouch, curl) onto a tiny offscreen canvas,
//              read back as a 2x2 coverage mask per cell, and each cell picks
//              a glyph from its mask (edge cells get - | / \, full cells get
//              a dense glyph). Colours come from CSS custom
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
  var HOP_REACH = 2.3;   // longest hop run: 4 hops x 0.55 body lengths, plus margin

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
    this.foxes = []; this.lures = []; this.trails = []; this.puffs = []; this.embers = []; this.zs = [];
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
      state: 'trot', timer: 0,
      nextLane: rand(3, 9),
      avoidUntil: 0,
      air: 0, pounceT: 0, pounceFrom: 0, pounceTo: 0, pounceY: 0,
      nod: 0, nodTarget: 0,
      lure: null,
      curiosity: rand(0.45, 1),
      L: 170,
      strideAcc: 0,
      startle: 0,
      flying: false, airK: 0,
      pw: { stand: 1, sit: 0, bow: 0, dive: 0, crouch: 0, curl: 0 },
      lastNap: -100, nextZ: 0, turnAt: 0, earTwitch: -10,
      hopsLeft: 0, hopT: 0, hopPause: 0,
      mPhase: '', leapT: 0, leapFrom: 0, leapTo: 0, leapAngle: 0
    });
    // Open on a mix of moods so even the still frame has character: the
    // alpha sits, the others trot, sit, or nap.
    var f = this.foxes[i];
    var r = Math.random();
    this.enter(f, i === 0 ? 'sit' : r < 0.45 ? 'trot' : r < 0.75 ? 'curl' : 'sit');
    if (f.state === 'trot') f.timer = rand(1, 5);
    for (var k in f.pw) f.pw[k] = 0;
    f.pw[poseFor(f)] = 1;
  };

  // Which pose a state draws with; paintFox blends toward it.
  function poseFor(f) {
    switch (f.state) {
      case 'sit': return 'sit';
      case 'curl': return 'curl';
      case 'bow': return 'bow';
      case 'mouse': return f.mPhase === 'crouch' ? 'crouch' : f.mPhase === 'dive' ? 'dive' : 'stand';
      default: return 'stand';
    }
  }

  World.prototype.enter = function (f, s) {
    var t = this.time;
    f.state = s; f.nodTarget = 0; f.air = 0; f.flying = false;
    if (s !== 'trot' && s !== 'chase') f.lane = f.y;
    if (s === 'trot') f.timer = rand(7, 16);
    else if (s === 'idle') f.timer = rand(1.4, 4);
    else if (s === 'sit') f.timer = rand(4, 9);
    else if (s === 'curl') { f.timer = rand(9, 18); f.lastNap = t; f.nextZ = t + 1.2; }
    else if (s === 'bow') f.timer = rand(1.1, 1.6);
    else if (s === 'sniff') f.timer = rand(1.2, 2.4);
    else if (s === 'hop') { f.hopsLeft = 2 + Math.floor(Math.random() * 3); f.hopT = 0; f.hopPause = 0.1; }
    else if (s === 'mouse') { f.mPhase = 'crouch'; f.timer = rand(0.9, 1.5); }
  };

  // Room to travel d px ahead (flips direction once if the way is blocked).
  World.prototype.roomFor = function (f, d) {
    var L = this.foxL(f, f.y);
    for (var k = 0; k < 2; k++) {
      var x = f.x + f.dir * d;
      if (x > 0.9 * L && x < this.w - 0.9 * L && this.laneClear(f, x, f.y)) return true;
      f.dir = -f.dir;
    }
    return false;
  };

  // What a fox does when a trot runs out. The alpha sits more; the small
  // ones hop more; naps need a while since the last one.
  World.prototype.nextBehavior = function (f) {
    var L = this.foxL(f, f.y);
    var opts = [['idle', 3], ['sit', f.big ? 3.2 : 2], ['bow', 0.7]];
    if (this.time - f.lastNap > 25) opts.push(['curl', 1.2]);
    if (this.roomFor(f, HOP_REACH * L)) opts.push(['hop', f.big ? 0.8 : 2.4]);
    if (this.roomFor(f, 1.0 * L)) opts.push(['mouse', 1.5]);
    var sum = 0, i;
    for (i = 0; i < opts.length; i++) sum += opts[i][1];
    var r = Math.random() * sum;
    for (i = 0; i < opts.length - 1; i++) { r -= opts[i][1]; if (r <= 0) break; }
    this.enter(f, opts[i][0]);
  };

  // Mid-air or mid-pounce: not interruptible by food or the cursor.
  World.prototype.busy = function (f) {
    return f.flying || f.state === 'pounce' || (f.state === 'mouse' && f.mPhase !== 'crouch');
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
      if (this.busy(f)) continue;
      var d = Math.hypot(f.x - x, f.y - y);
      if (d < nd) { nd = d; nearest = f; }
      if (d < 900 && Math.random() < f.curiosity * 0.7) this.chase(f, lure);
    }
    if (nearest && nearest.state !== 'chase' && !this.busy(nearest)) this.chase(nearest, lure);
  };

  // A lure is gone once eaten or once it has faded; foxes must not keep
  // chasing (or passing around) one that is no longer on screen.
  World.prototype.lureLive = function (l) {
    return !!l && !l.taken && this.time - l.born < LURE_LIFE;
  };

  World.prototype.handOff = function (lure, except) {
    if (!this.lureLive(lure)) return;
    var best = null, bd = Infinity;
    for (var i = 0; i < this.foxes.length; i++) {
      var o = this.foxes[i];
      if (o === except || this.busy(o) || o.state === 'chase') continue;
      var d = Math.hypot(o.x - lure.x, o.y - lure.y);
      if (d < bd) { bd = d; best = o; }
    }
    if (best) this.chase(best, lure);
  };

  World.prototype.chase = function (f, lure) {
    this.enter(f, 'chase'); f.lure = lure; f.timer = 12;
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
          if (t > fa.avoidUntil && fa.state === 'trot') fa.lane = clamp(fa.y - push, this.groundMin(), this.groundMax());
          if (t > fb.avoidUntil && fb.state === 'trot') fb.lane = clamp(fb.y + push, this.groundMin(), this.groundMax());
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
    for (var z = 0; z < this.zs.length; z++) {
      var zz = this.zs[z];
      zz.y -= 15 * dt;
      zz.x += (zz.vx + Math.sin(t * 2 + zz.seed) * 6) * dt;
    }
    this.zs = this.zs.filter(function (p) { return t - p.born < 2.6; });
    this.trails = this.trails.filter(function (p) { return t - p.born < 2.6; });
    this.puffs = this.puffs.filter(function (p) { return t - p.born < 0.6; });
    var self = this;
    this.lures = this.lures.filter(function (l) { return self.lureLive(l); });
    if (this.pointer.active) this.pointer.speed *= Math.pow(0.02, dt);
  };

  World.prototype.stepFox = function (f, dt) {
    var w = this.w, h = this.h, t = this.time;
    var L = this.foxL(f, f.y);
    f.timer -= dt;

    // --- state machine ----------------------------------------------------
    f.flying = false;
    if (f.state === 'trot') {
      f.targetSpeed = f.cruise * (L / 170);
      f.nodTarget = 0;
      f.nextLane -= dt;
      if (f.nextLane <= 0 && t > f.avoidUntil) {
        f.lane = this.pickLane(f);
        f.nextLane = rand(4, 10);
      }
      if (f.timer <= 0) this.nextBehavior(f);
    } else if (f.state === 'idle') {
      f.targetSpeed = 0;
      f.nodTarget = Math.sin(t * 0.7 + f.seed) > 0.55 ? 0.5 : 0;
      if (f.timer <= 0) {
        if (Math.random() < 0.4) this.enter(f, 'sit');
        else { this.enter(f, 'trot'); if (Math.random() < 0.4) f.dir = -f.dir; }
      }
    } else if (f.state === 'sit') {
      // sits tall, now and then dips its head to sniff the grass
      f.targetSpeed = 0;
      f.nodTarget = Math.sin(t * 0.45 + f.seed) > 0.82 ? 0.45 : 0;
      if (f.timer <= 0) {
        var rs = Math.random();
        if (rs < 0.35 && t - f.lastNap > 20) this.enter(f, 'curl');
        else if (rs < 0.55) this.enter(f, 'bow');
        else this.enter(f, 'trot');
      }
    } else if (f.state === 'curl') {
      // asleep: breathes (in paintFox) and lets out a z now and then
      f.targetSpeed = 0;
      if (f.pw.curl > 0.8 && t > f.nextZ) {
        this.zs.push({ x: f.x + f.dir * 0.42 * L, y: f.y - 0.32 * L, vx: f.dir * rand(4, 9), born: t, seed: Math.random() * 10 });
        if (this.zs.length > 12) this.zs.shift();
        f.nextZ = t + rand(1.4, 2.2);
      }
      if (f.timer <= 0) this.enter(f, 'bow');   // wake with a stretch
    } else if (f.state === 'bow') {
      f.targetSpeed = 0;
      if (f.timer <= 0) {
        if (Math.random() < 0.35 && this.roomFor(f, HOP_REACH * L)) this.enter(f, 'hop');
        else this.enter(f, 'trot');
      }
    } else if (f.state === 'hop') {
      // a run of springy hops, each one a little arc forward
      f.targetSpeed = 0; f.speed = 0;
      if (f.hopPause > 0) f.hopPause -= dt;
      else {
        var HT = 0.44;
        f.hopT += dt;
        var kh = clamp(f.hopT / HT, 0, 1);
        f.flying = true; f.airK = kh;
        f.air = Math.sin(kh * Math.PI) * 0.26 * L;
        f.x += f.dir * (0.55 * L / HT) * dt;
        if (kh >= 1) {
          f.air = 0; f.hopT = 0; f.hopPause = 0.12; f.flying = false;
          if (--f.hopsLeft <= 0) this.enter(f, 'trot');
        }
      }
    } else if (f.state === 'mouse') {
      // the fox "mousing" pounce: crouch and wiggle, leap high, dive nose-first
      f.targetSpeed = 0; f.speed = 0;
      if (f.mPhase === 'crouch') {
        if (f.timer <= 0) {
          f.mPhase = 'leap'; f.leapT = 0; f.leapFrom = f.x; f.leapTo = f.x + f.dir * 0.85 * L;
        }
      } else if (f.mPhase === 'leap') {
        var LT = 0.78;
        f.leapT += dt;
        var kl = clamp(f.leapT / LT, 0, 1);
        f.flying = true; f.airK = kl;
        f.x = lerp(f.leapFrom, f.leapTo, kl);
        f.air = Math.sin(kl * Math.PI) * 0.7 * L;
        f.leapAngle = lerp(0.55, -0.8, smooth(kl));
        if (kl >= 1) {
          f.air = 0; f.flying = false; f.mPhase = 'dive'; f.timer = 0.65;
          var hx = f.x + f.dir * 0.55 * L;
          for (var gp = 0; gp < 8; gp++) {
            this.puffs.push({ x: hx, y: f.y - 4, a: Math.PI + (gp / 7) * Math.PI + rand(-0.15, 0.15), born: t, r: rand(0.6, 1.1), g: ",'`\"".charAt(gp % 4), col: C_GRASS2 });
          }
        }
      } else if (f.timer <= 0) {
        this.enter(f, 'sniff');
      }
    } else if (f.state === 'chase') {
      var l = f.lure;
      if (!this.lureLive(l)) { this.enter(f, 'trot'); f.timer = rand(5, 12); f.lure = null; }
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
        if (f.state === 'chase' && f.timer <= 0) { var give = f.lure; this.enter(f, 'trot'); f.timer = rand(5, 12); f.lure = null; this.handOff(give, f); }
      }
    } else if (f.state === 'pounce') {
      var T = 0.62;
      f.pounceT += dt;
      var k = clamp(f.pounceT / T, 0, 1);
      f.flying = true; f.airK = k;
      f.x = lerp(f.pounceFrom, f.pounceTo, smooth(k));
      f.air = Math.sin(k * Math.PI) * 0.42 * L;
      f.targetSpeed = 0; f.speed = 0;
      if (k >= 1) {
        f.air = 0; f.flying = false;
        if (f.lure) {
          f.lure.taken = true;
          for (var p = 0; p < 10; p++) {
            var a = (p / 10) * TAU + rand(-0.2, 0.2);
            this.puffs.push({ x: f.lure.x, y: f.lure.y - 4, a: a, born: t, r: rand(0.6, 1.1), g: '<>/"=()\'`;'.charAt(p % 10) });
          }
          f.lure = null;
        }
        this.enter(f, 'sniff');
      }
    } else if (f.state === 'sniff') {
      f.targetSpeed = 0; f.nodTarget = 1;
      if (f.timer <= 0) { this.enter(f, 'trot'); f.timer = rand(6, 14); if (Math.random() < 0.5) f.dir = -f.dir; }
    }

    // --- pointer: a rush startles anyone awake (or asleep) into a bolt; a
    // slow hover makes trotters ease off; sitting foxes turn to watch it;
    // a sleeper only twitches an ear. ------------------------------------
    var ptr = this.pointer;
    if (ptr.active && !this.busy(f)) {
      var pd = Math.hypot(ptr.x - f.x, ptr.y - (f.y - 0.4 * L));
      if (pd < 1.1 * L && ptr.speed > 1400 && f.startle <= 0 && f.state !== 'chase') {
        this.enter(f, 'trot');
        f.startle = 1.1; f.dir = ptr.x < f.x ? 1 : -1;
      } else if (pd < 1.1 * L && f.state === 'trot') {
        f.targetSpeed *= 0.35;
        f.nodTarget = 0.3;
      } else if ((f.state === 'sit' || f.state === 'idle' || f.state === 'sniff') && pd < 2.4 * L && t > f.turnAt) {
        var want = ptr.x > f.x ? 1 : -1;
        if (want !== f.dir) { f.dir = want; f.turnAt = t + 0.8; }
      } else if (f.state === 'curl' && pd < 1.3 * L && t - f.earTwitch > 1.2) {
        f.earTwitch = t;
      }
    }
    if (f.startle > 0) { f.startle -= dt; f.targetSpeed = Math.max(f.targetSpeed, 240 * (L / 170)); }

    // --- edges: turn before leaving the frame -----------------------------
    if (!f.flying && f.state !== 'pounce') {
      if (f.dir > 0 && f.x > w - 0.9 * L) f.dir = -1;
      if (f.dir < 0 && f.x < 0.9 * L) f.dir = 1;
      if (f.x < -0.3 * L) f.x = -0.3 * L;
      if (f.x > w + 0.3 * L) f.x = w + 0.3 * L;
    }

    // --- content avoidance: steer the lane around marked boxes ------------
    // (only foxes on the move; a fox at rest stays put)
    var moving = f.state === 'trot' || f.state === 'chase';
    var ahead = f.x + f.dir * f.speed * 0.7;
    var left = Math.min(f.x, ahead) - 0.55 * L, right = Math.max(f.x, ahead) + 0.9 * L;
    var top = f.y - 0.95 * L, bottom = f.y + 0.04 * L;
    for (var b = 0; moving && b < this.avoid.length; b++) {
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
    if (!f.flying && f.state !== 'pounce') {
      f.x += f.dir * f.speed * dt;
      var dy = f.lane - f.y;
      var rate = (t < f.avoidUntil ? 70 : 26) + f.speed * 0.15;
      f.y += clamp(dy, -rate * dt, rate * dt);
    }
    f.nod += (f.nodTarget - f.nod) * Math.min(1, 4 * dt);

    // pose weights glide toward the state's pose (lying down is slower)
    var want = poseFor(f), rate = (want === 'curl' || f.pw.curl > 0.05) ? 3 : 7, sum = 0;
    for (var pk in f.pw) { f.pw[pk] += ((pk === want ? 1 : 0) - f.pw[pk]) * Math.min(1, rate * dt); sum += f.pw[pk]; }
    for (pk in f.pw) f.pw[pk] /= sum;

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

  // Pose library. Every pose yields the same set of numbers so any mix of
  // them can be blended: body (centre, angle with + = nose up, x/y scale,
  // back arch), head (position, tilt with + = nose down, ear lean, eye open),
  // tail (control-point offsets from the rump), feet (near/far fore, near/far
  // hind) and knee hints (which side each joint bends toward).
  var POSE_KEYS = ['bx', 'by', 'ba', 'bsx', 'bsy', 'arch', 'hx', 'hy', 'ht', 'eb', 'eye',
    't1x', 't1y', 't2x', 't2y', 't3x', 't3y', 'tw',
    'f0x', 'f0y', 'f1x', 'f1y', 'f2x', 'f2y', 'f3x', 'f3y',
    'k0x', 'k0y', 'k1x', 'k1y', 'k2x', 'k2y', 'k3x', 'k3y'];
  // pivots in the body frame: near fore, far fore, near hind, far hind
  var PIVOTS = [[0.25, -0.04], [0.22, -0.05], [-0.22, -0.03], [-0.2, -0.04]];
  var LU = 0.21, LL = 0.21;
  var FX = ['f0x', 'f1x', 'f2x', 'f3x'], FY = ['f0y', 'f1y', 'f2y', 'f3y'];
  var KX = ['k0x', 'k1x', 'k2x', 'k3x'], KY = ['k0y', 'k1y', 'k2y', 'k3y'];

  function bodyPt(P, u, v) {
    var c = Math.cos(P.ba), s = Math.sin(P.ba);
    u *= P.bsx; v *= P.bsy;
    return [P.bx + u * c - v * s, P.by + u * s + v * c];
  }

  // Two-bone IK: knee for a leg from pivot to foot, on the side of hint.
  function ik(px, py, fx, fy, hx, hy) {
    var dx = fx - px, dy = fy - py, d = Math.hypot(dx, dy) || 1e-4, max = LU + LL - 1e-4;
    if (d > max) { fx = px + dx / d * max; fy = py + dy / d * max; dx = fx - px; dy = fy - py; d = max; }
    var a = (LU * LU - LL * LL + d * d) / (2 * d), h = Math.sqrt(Math.max(0, LU * LU - a * a));
    var nx = -dy / d, ny = dx / d;
    if (nx * hx + ny * hy < 0) { nx = -nx; ny = -ny; }
    return [px + dx * a / d + nx * h, py + dy * a / d + ny * h, fx, fy];
  }

  function standPose(f, t, amp, run, airborne, ang) {
    var phi = f.phase, nod = f.nod;
    var bob = 0.045 * amp * Math.max(0, Math.sin(phi));
    var P = { bx: 0, by: 0.47 + bob, ba: ang, bsx: 1, bsy: 1, arch: 0.1 + 0.05 * Math.max(0, Math.sin(phi + 0.6)) * amp,
      ht: 0.5 * nod - ang, eb: nod, eye: 1, tw: 1 };
    var head = bodyPt(P, 0.52 + 0.1 * nod, 0.21 - 0.27 * nod);
    P.hx = head[0]; P.hy = head[1];
    // tail: drops from the rump and curls up at rest, streams back at a run
    var rest = 1 - run;
    var sway = 0.08 * Math.sin(t * (f.speed < 10 ? 2.2 : 3.6) + f.seed) * (f.speed < 10 ? 1 : 0.5);
    var lift = airborne ? 0.3 : 0;
    var c = Math.cos(ang), s = Math.sin(ang);
    var T = [-0.28, -0.2 * rest + 0.04 * run + sway + lift - 0.06,
      -0.63, -0.1 * rest + 0.12 * run + sway * 1.5 + lift - 0.06,
      -0.65 + 0.08 * rest, 0.3 * rest + 0.2 * run + sway * 2 + lift - 0.06];
    P.t1x = T[0] * c - T[1] * s; P.t1y = T[0] * s + T[1] * c;
    P.t2x = T[2] * c - T[3] * s; P.t2y = T[2] * s + T[3] * c;
    P.t3x = T[4] * c - T[5] * s; P.t3y = T[4] * s + T[5] * c;
    // legs: swing from the gait phase (or tuck in the air); the FK knee
    // becomes the IK hint so the blend reproduces it exactly
    var A = 0.8 * amp, K = 1.15 * amp;
    var phases = [phi, phi + 0.5, phi + Math.PI + 0.45, phi + Math.PI];
    for (var i = 0; i < 4; i++) {
      var rear = i >= 2, pv = bodyPt(P, PIVOTS[i][0], PIVOTS[i][1]);
      var up = airborne ? (rear ? 0.9 : -0.6) : A * Math.sin(phases[i]);
      var bend = airborne ? 1.5 : K * Math.max(0, -Math.sin(phases[i] + 0.3));
      var low = airborne ? up + (rear ? 1.3 : -1.6) : up - bend * (rear ? -0.9 : 1);
      var kx = pv[0] + Math.sin(up) * LU, ky = pv[1] - Math.cos(up) * LU;
      var fx = kx + Math.sin(low) * LL, fy = ky - Math.cos(low) * LL;
      P[FX[i]] = fx; P[FY[i]] = fy;
      P[KX[i]] = kx - (pv[0] + fx) / 2; P[KY[i]] = ky - (pv[1] + fy) / 2;
    }
    return P;
  }

  function staticPose(o) {
    var P = { tw: 1, eye: 1, eb: 0 };
    for (var k in o) P[k] = o[k];
    return P;
  }

  function sitPose(f, t) {
    var swish = Math.sin(t * 2.2 + f.seed);
    return staticPose({ bx: 0.04, by: 0.24, ba: 0.75, bsx: 0.9, bsy: 1.05, arch: 0.06,
      hx: 0.42, hy: 0.72 + 0.015 * Math.sin(t * 1.3 + f.seed), ht: -0.1 + 0.6 * f.nod, eb: 0.3 * f.nod,
      t1x: -0.2, t1y: -0.1, t2x: 0.35, t2y: -0.12, t3x: 0.68 + 0.04 * swish, t3y: -0.06 + 0.03 * swish,
      f0x: 0.29, f0y: 0.03, f1x: 0.24, f1y: 0.03, f2x: 0.06, f2y: 0.03, f3x: 0.02, f3y: 0.03,
      k0x: 1, k0y: 0, k1x: 1, k1y: 0, k2x: 0.5, k2y: 1, k3x: 0.5, k3y: 1 });
  }

  function bowPose(f, t) {
    var wag = Math.sin(t * 10 + f.seed);
    return staticPose({ bx: 0.02, by: 0.34, ba: -0.55, bsx: 1, bsy: 1, arch: 0.04,
      hx: 0.62, hy: 0.3, ht: -0.05,
      t1x: -0.15, t1y: 0.22, t2x: -0.35, t2y: 0.42, t3x: -0.42 + 0.12 * wag, t3y: 0.42,
      f0x: 0.6, f0y: 0.03, f1x: 0.54, f1y: 0.03, f2x: -0.18, f2y: 0.03, f3x: -0.22, f3y: 0.03,
      k0x: 0.2, k0y: 1, k1x: 0.2, k1y: 1, k2x: -1, k2y: 0, k3x: -1, k3y: 0 });
  }

  function divePose(f, t) {
    var wag = Math.sin(t * 16 + f.seed);
    return staticPose({ bx: 0.02, by: 0.36, ba: -0.6, bsx: 1, bsy: 1, arch: 0.05,
      hx: 0.56, hy: 0.06, ht: 0.9,
      t1x: -0.1, t1y: 0.3, t2x: -0.2, t2y: 0.5, t3x: -0.18 + 0.08 * wag, t3y: 0.55,
      f0x: 0.5, f0y: 0.03, f1x: 0.45, f1y: 0.03, f2x: -0.18, f2y: 0.03, f3x: -0.22, f3y: 0.03,
      k0x: 0.2, k0y: 1, k1x: 0.2, k1y: 1, k2x: -1, k2y: 0, k3x: -1, k3y: 0 });
  }

  function crouchPose(f, t) {
    var wig = Math.sin(t * 18 + f.seed);
    return staticPose({ bx: 0.02, by: 0.31, ba: -0.18 + 0.05 * wig, bsx: 0.92, bsy: 1, arch: 0.12,
      hx: 0.56, hy: 0.37, ht: 0.35, eb: -0.5,
      t1x: -0.25, t1y: -0.03, t2x: -0.5, t2y: -0.05, t3x: -0.72, t3y: -0.04 + 0.05 * Math.sin(t * 15),
      f0x: 0.31, f0y: 0.03, f1x: 0.26, f1y: 0.03, f2x: -0.1, f2y: 0.03, f3x: -0.14, f3y: 0.03,
      k0x: -1, k0y: 0.4, k1x: -1, k1y: 0.4, k2x: 0.6, k2y: 1, k3x: 0.6, k3y: 1 });
  }

  function curlPose(f, t) {
    var breath = 1 + 0.035 * Math.sin(t * 1.7 + f.seed);
    return staticPose({ bx: 0.02, by: 0.2, ba: 0, bsx: 0.8, bsy: 1.32 * breath, arch: 0.2,
      hx: 0.3, hy: 0.17, ht: 0.45, eb: 0.5, eye: 0, tw: 0.92,
      t1x: -0.12, t1y: -0.28, t2x: 0.6, t2y: -0.3, t3x: 0.78, t3y: -0.16,
      f0x: 0.34, f0y: 0.05, f1x: 0.3, f1y: 0.05, f2x: 0.02, f2y: 0.05, f3x: -0.02, f3y: 0.05,
      k0x: 1, k0y: 0.2, k1x: 1, k1y: 0.2, k2x: 0.6, k2y: 1, k3x: 0.6, k3y: 1 });
  }

  var POSE_FNS = { sit: sitPose, bow: bowPose, dive: divePose, crouch: crouchPose, curl: curlPose };

  function paintFox(g, f, t) {
    var W = f.pw;
    var airborne = f.air > 0.02 * f.L;
    var amp = clamp(f.speed / (120 * (f.L / 170)), 0, 1.3) * W.stand;
    var run = Math.min(1, amp);
    var ang;
    if (f.state === 'mouse' && f.mPhase === 'leap') ang = f.leapAngle;
    else if (airborne) ang = 0.3 * Math.sin(clamp(f.airK, 0, 1) * Math.PI);
    else ang = -0.1 * amp * Math.sin(f.phase - 0.5);

    // blend the poses by weight
    var P = {}, i, k;
    for (i = 0; i < POSE_KEYS.length; i++) P[POSE_KEYS[i]] = 0;
    for (var name in W) {
      var w = W[name];
      if (w < 1e-3) continue;
      var Q = name === 'stand' ? standPose(f, t, amp, run, airborne, ang) : POSE_FNS[name](f, t);
      for (i = 0; i < POSE_KEYS.length; i++) { k = POSE_KEYS[i]; P[k] += w * Q[k]; }
    }
    var dt2 = t - f.earTwitch;
    if (dt2 < 0.45) P.eb -= 0.9 * Math.sin(dt2 / 0.45 * Math.PI) * W.curl;   // a sleeper's ear flick

    g.lineCap = 'round'; g.lineJoin = 'round';
    var tailFront = W.curl > 0.5;

    function tail() {
      var root = bodyPt(P, -0.27, 0.06);
      var p0x = root[0], p0y = root[1];
      var c1x = p0x + P.t1x, c1y = p0y + P.t1y, c2x = p0x + P.t2x, c2y = p0y + P.t2y, p3x = p0x + P.t3x, p3y = p0y + P.t3y;
      function cp(tt) {
        var u = 1 - tt, a = u * u * u, b = 3 * u * u * tt, c = 3 * u * tt * tt, d = tt * tt * tt;
        return [a * p0x + b * c1x + c * c2x + d * p3x, a * p0y + b * c1y + c * c2y + d * p3y];
      }
      var tw = P.tw;
      g.strokeStyle = COL_BODY;
      g.lineWidth = 0.24 * tw; g.beginPath(); g.moveTo(p0x, p0y); g.bezierCurveTo(c1x, c1y, c2x, c2y, p3x, p3y); g.stroke();
      g.fillStyle = COL_BODY;
      var fluff = [[0.18, 0.14], [0.36, 0.165], [0.54, 0.165], [0.7, 0.15]];
      for (var fi = 0; fi < fluff.length; fi++) {
        var fp = cp(fluff[fi][0]), fr = fluff[fi][1] * tw;
        g.beginPath(); g.ellipse(fp[0], fp[1], fr, fr * 0.9, 0, 0, TAU); g.fill();
      }
      var n = cp(0.72), n2 = cp(0.86);
      g.strokeStyle = COL_TIP; g.lineWidth = 0.2 * tw;
      g.beginPath(); g.moveTo(n[0], n[1]); g.quadraticCurveTo(n2[0], n2[1], p3x, p3y); g.stroke();
      g.fillStyle = COL_TIP; g.beginPath(); g.ellipse(n2[0], n2[1], 0.12 * tw, 0.11 * tw, 0, 0, TAU); g.fill();
    }

    function leg(i) {
      var pv = bodyPt(P, PIVOTS[i][0], PIVOTS[i][1]);
      var j = ik(pv[0], pv[1], P[FX[i]], P[FY[i]], P[KX[i]], P[KY[i]]);
      g.strokeStyle = COL_BODY; g.lineWidth = 0.12;
      g.beginPath(); g.moveTo(pv[0], pv[1]); g.lineTo(j[0], j[1]); g.stroke();
      g.strokeStyle = COL_SOCK; g.lineWidth = 0.085;
      g.beginPath(); g.moveTo(j[0], j[1]); g.lineTo(j[2], j[3]); g.stroke();
      g.fillStyle = COL_SOCK; g.beginPath(); g.ellipse(j[2] + 0.015, j[3] + 0.012, 0.055, 0.04, 0, 0, TAU); g.fill();
    }

    if (!tailFront) tail();
    leg(1); leg(3);   // far legs, behind the body

    // body: an arched spine over a tucked waist, chest and rump in front
    g.save();
    g.translate(P.bx, P.by); g.rotate(P.ba); g.scale(P.bsx, P.bsy);
    g.fillStyle = COL_BODY;
    g.beginPath();
    g.moveTo(0.3, 0.13);
    g.quadraticCurveTo(0.0, 0.17 + P.arch, -0.3, 0.1);
    g.lineTo(-0.3, -0.02);
    g.quadraticCurveTo(-0.05, -0.13, 0.3, -0.15);
    g.closePath(); g.fill();
    g.beginPath(); g.ellipse(0.25, -0.01, 0.165, 0.16, 0, 0, TAU); g.fill();   // chest
    g.beginPath(); g.ellipse(-0.24, 0.03, 0.14, 0.135, 0, 0, TAU); g.fill();  // rump
    g.restore();

    leg(2); leg(0);   // near legs

    var bib = bodyPt(P, 0.31, -0.07);
    g.fillStyle = COL_TIP; g.beginPath(); g.ellipse(bib[0], bib[1], 0.075, 0.065, 0, 0, TAU); g.fill();

    // neck + head (tilt + = nose down; eb leans the ears back)
    var nb = bodyPt(P, 0.27, 0.05), hx = P.hx, hy = P.hy;
    g.strokeStyle = COL_BODY; g.lineWidth = 0.21;
    g.beginPath(); g.moveTo(nb[0], nb[1]); g.lineTo(hx - 0.07, hy - 0.04); g.stroke();
    g.save();
    g.translate(hx, hy); g.rotate(-P.ht);
    g.fillStyle = COL_BODY;
    g.beginPath(); g.ellipse(0, 0, 0.145, 0.115, 0.15, 0, TAU); g.fill();
    g.fillStyle = COL_TIP; g.beginPath(); g.ellipse(-0.02, -0.08, 0.075, 0.05, 0.2, 0, TAU); g.fill(); // cheek ruff
    g.strokeStyle = COL_BODY;
    g.lineWidth = 0.1; g.beginPath(); g.moveTo(0.06, -0.01); g.lineTo(0.18, -0.06); g.stroke();       // muzzle
    g.lineWidth = 0.055; g.beginPath(); g.moveTo(0.17, -0.06); g.lineTo(0.25, -0.085); g.stroke();
    g.strokeStyle = COL_TIP; g.lineWidth = 0.045;
    g.beginPath(); g.moveTo(0.08, -0.07); g.lineTo(0.2, -0.1); g.stroke();                              // jaw
    g.fillStyle = COL_BODY;
    var ea = -0.25 * P.eb;
    g.beginPath(); g.moveTo(-0.12, 0.05); g.lineTo(-0.13 + ea, 0.34); g.lineTo(0.0, 0.09); g.closePath(); g.fill();
    g.beginPath(); g.moveTo(0.0, 0.06); g.lineTo(0.03 + ea, 0.35); g.lineTo(0.13, 0.07); g.closePath(); g.fill();
    if (P.eye > 0.5) { g.fillStyle = COL_EYE; g.beginPath(); g.ellipse(0.05, 0.03, 0.034, 0.034, 0, 0, TAU); g.fill(); }
    g.restore();

    if (tailFront) tail();
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
    this.drawZs(world);

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

  Renderer.prototype.drawZs = function (world) {
    for (var i = 0; i < world.zs.length; i++) {
      var p = world.zs[i];
      var age = (world.time - p.born) / 2.6;
      this.put(Math.floor(p.x / this.cw), Math.floor(p.y / this.ch), age < 0.35 ? 'z' : 'Z', C_MOON, 0.9 * (1 - age * age));
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
      this.put(Math.floor(x / this.cw), Math.floor(y / this.ch), age < 0.7 ? p.g : '.', p.col !== undefined ? p.col : C_PREY, 1 - age);
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
    var r0 = Math.max(0, Math.floor((oy - 1.25 * L) / ch)), r1 = Math.min(rows - 1, Math.floor((oy + 0.2 * L) / ch));
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
    // Boxes are used as-is. Merging nearby boxes once fused the full-width
    // header with the hero on short viewports and dimmed the whole sky.
    renderer.setDimBoxes(boxes);
    world.avoid = boxes;
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
