/*
 * Кольцо главной кнопки (макет для PowerOrbView). Всё рисуется кодом — то же самое потом делает
 * Android Canvas: дуги, градиенты (SweepGradient/RadialGradient), свечение (BlurMaskFilter).
 *
 * Анимация только пока идёт подбор, подключение или вспышка щита; в остальное время кадр
 * рисуется один раз и замирает — батарея не тратится.
 */
(function () {
  'use strict';

  function mulberry32(a) {
    return function () {
      a |= 0; a = a + 0x6D2B79F5 | 0;
      let t = Math.imul(a ^ a >>> 15, 1 | a);
      t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
      return ((t ^ t >>> 14) >>> 0) / 4294967296;
    };
  }
  function toRgb(v) {
    v = (v || '').trim();
    if (v.startsWith('rgb')) { const m = v.match(/[\d.]+/g).map(Number); return [m[0], m[1], m[2]]; }
    v = v.replace('#', '');
    if (v.length === 3) v = v.split('').map((c) => c + c).join('');
    const n = parseInt(v || 'ff8a1f', 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  }
  function rgba(c, a) { return 'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',' + Math.max(0, Math.min(1, a)).toFixed(3) + ')'; }
  function mix(a, b, t) { return [0, 1, 2].map((i) => Math.round(a[i] + (b[i] - a[i]) * t)); }
  const easeOut = (t) => 1 - Math.pow(1 - t, 3);
  const TAU = Math.PI * 2;
  const FLASH_MS = 1500;

  /** Щит как на 4-й картинке: острый верх, плечи, сужение к острию внизу. */
  function shieldPath(ctx, cx, cy, w, h) {
    const x = (u) => cx + u * w / 2, y = (v) => cy + v * h / 2;
    ctx.beginPath();
    ctx.moveTo(x(0), y(-1));
    ctx.bezierCurveTo(x(0.3), y(-0.83), x(0.62), y(-0.79), x(0.92), y(-0.78));
    ctx.bezierCurveTo(x(0.95), y(-0.18), x(0.86), y(0.3), x(0.55), y(0.62));
    ctx.bezierCurveTo(x(0.37), y(0.81), x(0.17), y(0.9), x(0), y(1));
    ctx.bezierCurveTo(x(-0.17), y(0.9), x(-0.37), y(0.81), x(-0.55), y(0.62));
    ctx.bezierCurveTo(x(-0.86), y(0.3), x(-0.95), y(-0.18), x(-0.92), y(-0.78));
    ctx.bezierCurveTo(x(-0.62), y(-0.79), x(-0.3), y(-0.83), x(0), y(-1));
    ctx.closePath();
  }

  class Ring {
    constructor(canvas, host) {
      this.cv = canvas;
      this.ctx = canvas.getContext('2d');
      this.host = host;
      this.state = 'off';
      this.shown = 0; this.target = 0; this.progFrom = 0; this.progAt = -1e9;
      this.flashAt = -1;
      this.raf = 0;
      this.t0 = performance.now();
      this.size = 0;
      // Дорожки «микросхемы» (3-я картинка): одни и те же при каждом запуске — зерно постоянное.
      const rnd = mulberry32(20261126);
      this.traces = [];
      const N = 64;
      for (let i = 0; i < N; i++) {
        const r = rnd();
        this.traces.push({
          a: (i / N) * TAU + (rnd() - 0.5) * (TAU / N) * 0.7,
          len: 0.28 + rnd() * 0.7,
          mid: 0.32 + rnd() * 0.3,
          bend: rnd() < 0.45 ? (rnd() < 0.5 ? -1 : 1) * (0.03 + rnd() * 0.06) : 0,
          end: r < 0.3 ? 'sq' : r < 0.58 ? 'dot' : '',
          w: rnd() < 0.24 ? 1.8 : 1,
          al: 0.35 + rnd() * 0.55,
        });
      }
      this.chips = [];
      for (let j = 0; j < 16; j++) this.chips.push({ a: rnd() * TAU, rf: 0.55 + rnd() * 0.4, s: 2.2 + rnd() * 4, al: 0.3 + rnd() * 0.5 });
      this.bars = [];
      for (let k = 0; k < 5; k++) this.bars.push({ a: rnd() * TAU, n: 4 + Math.floor(rnd() * 5), rf: 0.25 + rnd() * 0.4, al: 0.35 + rnd() * 0.4 });
      this.readColors();
    }

    readColors() {
      const cs = getComputedStyle(this.host);
      const g = (n) => toRgb(cs.getPropertyValue(n));
      this.col = {
        acc: g('--accent'), acc2: g('--accent2'), light: g('--accent-light'), err: g('--err'), warn: g('--warn'),
        discA: g('--disc-a'), discB: g('--disc-b'), off: g('--ring-off'), text: g('--text'),
      };
      // Полупрозрачные цвета диска («Стекло») — с альфой: rgba(…, a).
      const ga = (n) => {
        const v = cs.getPropertyValue(n).trim();
        const m = v.match(/rgba?\(([^)]+)\)/);
        if (!m) return toRgb(v).concat(1);
        const p = m[1].split(',').map((x) => parseFloat(x));
        return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
      };
      this.design = this.host.dataset.design || 'premium';
      if (this.design === 'soft') this.col.partner = g('--partner');
      if (this.design === 'glass') {
        this.col.a = g('--neon-a'); this.col.b = g('--neon-b');
        this.col.discAa = ga('--disc-a'); this.col.discBa = ga('--disc-b'); this.col.offA = ga('--ring-off');
      }
      this.dark = this.host.dataset.theme !== 'light';
      this.kick();
    }

    resize() {
      const css = this.cv.clientWidth;
      if (!css) return;
      const dpr = Math.min(3, window.devicePixelRatio || 1) * (window.__phoneScaleUp || 1);
      this.size = css; this.dpr = dpr;
      this.cv.width = Math.round(css * dpr); this.cv.height = Math.round(css * dpr);
      this.kick();
    }

    setState(s) {
      if (s === this.state) return;
      const prev = this.state;
      this.state = s;
      if (s === 'on' && (prev === 'connecting' || prev === 'scan')) this.flashAt = performance.now();
      if (s !== 'scan') { this.target = 0; this.shown = 0; this.progFrom = 0; }
      this.kick();
    }

    setProgress(p) {
      p = Math.max(0, Math.min(1, p));
      if (Math.abs(p - this.target) < 0.001) return;
      this.progFrom = this.shown; this.target = p; this.progAt = performance.now();
      if (p < this.progFrom - 0.25) { this.shown = p; this.progFrom = p; }
      this.kick();
    }

    animating(now) {
      return this.state === 'scan' || this.state === 'connecting' ||
        (this.flashAt > 0 && now - this.flashAt < FLASH_MS) || now - this.progAt < 320;
    }

    kick() { if (!this.raf) this.raf = requestAnimationFrame((t) => this.frame(t)); }

    frame(now) {
      this.raf = 0;
      if (!this.size) this.resize();
      this.draw(now);
      const vis = this.cv.offsetParent !== null && !this.cv.closest('.hidden');
      if (this.animating(now) && vis) this.raf = requestAnimationFrame((t) => this.frame(t));
    }

    draw(now) {
      const ctx = this.ctx, S = this.size;
      if (!S) return;
      ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      ctx.clearRect(0, 0, S, S);
      if (this.design === 'soft') { this.drawSoft(now); return; }
      if (this.design === 'glass') { this.drawGlass(now); return; }
      const cx = S / 2, cy = S / 2, R = S / 2;
      const r0 = R * 0.79, r1 = R * 0.725;
      const st = this.state, C = this.col, dark = this.dark;
      const t = (now - this.t0) / 1000;
      const k = S / 318; // толщины подстраиваются под размер кнопки
      if (st === 'scan') {
        const q = Math.min(1, (now - this.progAt) / 320);
        this.shown = this.progFrom + (this.target - this.progFrom) * easeOut(q);
      }
      const flashK = this.flashAt > 0 ? Math.min(1, (now - this.flashAt) / FLASH_MS) : 1;
      const flashing = flashK < 1 && st === 'on';
      const main = st === 'error' ? C.err : C.acc;

      // 1. Ореол вокруг кольца.
      let halo = 0;
      if (st === 'on') halo = dark ? 0.30 : 0.20;
      else if (st === 'error') halo = dark ? 0.22 : 0.13;
      else if (st === 'connecting') halo = (dark ? 0.13 : 0.08) + (dark ? 0.07 : 0.04) * Math.sin(t * 3.4);
      else if (st === 'scan') halo = dark ? 0.11 : 0.07;
      if (flashing) halo += (dark ? 0.38 : 0.24) * (1 - easeOut(flashK));
      if (halo > 0) {
        const g = ctx.createRadialGradient(cx, cy, r1 * 0.96, cx, cy, R);
        g.addColorStop(0, rgba(main, 0));
        g.addColorStop(0.22, rgba(main, halo));
        g.addColorStop(0.55, rgba(main, halo * 0.32));
        g.addColorStop(1, rgba(main, 0));
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.fill();
      }

      // 2. «Микросхема» вокруг кольца — только во время подбора.
      if (st === 'scan') this.drawCircuit(ctx, cx, cy, r0, R, t, k);

      // 3. Диск.
      const dg = ctx.createRadialGradient(cx, cy - r1 * 0.35, r1 * 0.05, cx, cy, r1);
      dg.addColorStop(0, rgba(C.discA, 1));
      dg.addColorStop(1, rgba(C.discB, 1));
      ctx.fillStyle = dg;
      ctx.beginPath(); ctx.arc(cx, cy, r1, 0, TAU); ctx.fill();
      ctx.lineWidth = 1;
      ctx.strokeStyle = rgba(main, dark ? 0.16 : 0.20);
      ctx.beginPath(); ctx.arc(cx, cy, r1 - 0.5, 0, TAU); ctx.stroke();

      // 4. Щит внутри диска: еле виден, при подключении вспыхивает.
      let sa = ({ off: 0.06, scan: 0.08, connecting: 0.10, on: 0.15, error: 0.10 })[st] || 0.06;
      if (!dark) sa *= 1.25;
      let blur = 0, sw = 1.6 * k;
      if (flashing) {
        const f = flashK < 0.2 ? easeOut(flashK / 0.2) : 1 - easeOut((flashK - 0.2) / 0.8);
        sa += (0.95 - sa) * f; blur = 28 * f * k; sw = (1.6 + 1.4 * f) * k;
      }
      ctx.save();
      shieldPath(ctx, cx, cy - r1 * 0.03, r1 * 1.5, r1 * 1.62);
      if (st === 'on' || flashing) {
        const sf = ctx.createLinearGradient(cx, cy - r1, cx, cy + r1);
        sf.addColorStop(0, rgba(C.acc, (dark ? 0.06 : 0.04) + (flashing ? 0.10 * (1 - flashK) : 0)));
        sf.addColorStop(1, rgba(C.acc, 0));
        ctx.fillStyle = sf; ctx.fill();
      }
      ctx.lineWidth = sw;
      ctx.strokeStyle = rgba(st === 'error' ? C.err : C.light, sa);
      if (blur > 0) { ctx.shadowColor = rgba(C.acc, 0.95); ctx.shadowBlur = blur; }
      ctx.stroke();
      ctx.restore();

      // 5. Кольцо.
      ctx.save();
      ctx.lineCap = 'round';
      if (st === 'off') {
        ctx.lineWidth = 3 * k;
        ctx.strokeStyle = rgba(C.off, 1);
        ctx.beginPath(); ctx.arc(cx, cy, r0, 0, TAU); ctx.stroke();
      } else if (st === 'scan') {
        ctx.lineWidth = 4 * k;
        ctx.strokeStyle = rgba(main, 0.17);
        ctx.beginPath(); ctx.arc(cx, cy, r0, 0, TAU); ctx.stroke();
        this.drawDial(ctx, cx, cy, r0 - 10 * k, k);
        const p = this.shown;
        if (p > 0.002) {
          const a0 = -Math.PI / 2, a1 = a0 + p * TAU;
          ctx.strokeStyle = this.sweep(ctx, cx, cy, a0, C.acc2, C.light, p);
          ctx.lineWidth = 5 * k;
          ctx.shadowColor = rgba(C.acc, dark ? 0.95 : 0.6);
          ctx.shadowBlur = 16 * k;
          ctx.beginPath(); ctx.arc(cx, cy, r0, a0, a1); ctx.stroke();
          ctx.shadowBlur = 20 * k;
          ctx.fillStyle = dark ? '#fff1e0' : '#fff';
          ctx.beginPath(); ctx.arc(cx + r0 * Math.cos(a1), cy + r0 * Math.sin(a1), 4.6 * k, 0, TAU); ctx.fill();
        }
      } else if (st === 'connecting') {
        ctx.lineWidth = 4 * k;
        ctx.strokeStyle = rgba(main, 0.20);
        ctx.beginPath(); ctx.arc(cx, cy, r0, 0, TAU); ctx.stroke();
        // По кольцу бежит свет: голова яркая, хвост гаснет.
        const head = -Math.PI / 2 + t * TAU / 1.25;
        const tail = Math.PI * 0.7, steps = 30;
        ctx.shadowColor = rgba(main, dark ? 0.9 : 0.55);
        ctx.shadowBlur = 14 * k;
        for (let i = 0; i < steps; i++) {
          const f0 = i / steps, f1 = (i + 1) / steps;
          ctx.strokeStyle = rgba(mix(C.acc2, C.light, f1), f1 * f1);
          ctx.lineWidth = (1.5 + 4 * f1) * k;
          ctx.beginPath(); ctx.arc(cx, cy, r0, head - tail + tail * f0, head - tail + tail * f1 + 0.012); ctx.stroke();
        }
        ctx.shadowBlur = 18 * k;
        ctx.fillStyle = dark ? '#fff1e0' : '#fff';
        ctx.beginPath(); ctx.arc(cx + r0 * Math.cos(head), cy + r0 * Math.sin(head), 4 * k, 0, TAU); ctx.fill();
      } else {
        // Подключено / нет связи: неоновое кольцо — широкая мягкая подложка и яркая сердцевина.
        ctx.lineWidth = 13 * k;
        ctx.strokeStyle = rgba(main, dark ? 0.13 : 0.09);
        ctx.beginPath(); ctx.arc(cx, cy, r0, 0, TAU); ctx.stroke();
        ctx.lineWidth = 5 * k;
        ctx.strokeStyle = st === 'error' ? rgba(main, 1) : this.sweepFull(ctx, cx, cy, C);
        ctx.shadowColor = rgba(main, dark ? 0.95 : 0.55);
        ctx.shadowBlur = (dark ? 24 : 12) * k;
        ctx.beginPath(); ctx.arc(cx, cy, r0, 0, TAU); ctx.stroke();
        ctx.shadowBlur = 0;
        ctx.lineWidth = 1.1 * k;
        ctx.strokeStyle = rgba(st === 'error' ? C.err : C.light, dark ? 0.6 : 0.8);
        ctx.beginPath(); ctx.arc(cx, cy, r0 - 0.5, 0, TAU); ctx.stroke();
      }
      ctx.restore();

      // 6. Вспышка: волна от кольца наружу.
      if (flashing) {
        const e = easeOut(flashK);
        ctx.save();
        ctx.lineWidth = (3 * (1 - e) + 0.6) * k;
        ctx.strokeStyle = rgba(C.light, 0.75 * (1 - e));
        ctx.shadowColor = rgba(C.acc, 0.8);
        ctx.shadowBlur = 14 * k;
        ctx.beginPath(); ctx.arc(cx, cy, r0 + (R - r0 - 2) * e, 0, TAU); ctx.stroke();
        ctx.restore();
      }
    }

    /** Ход заполнения при подборе (общий для всех дизайнов). */
    stepProgress(now) {
      if (this.state === 'scan') {
        const q = Math.min(1, (now - this.progAt) / 320);
        this.shown = this.progFrom + (this.target - this.progFrom) * easeOut(q);
      }
    }

    /**
     * «Нежный»: мягкий диск с тенью, толстое пастельное кольцо со скруглёнными концами.
     * Подбор — кольцо заполняется, вокруг медленно кружат три точки; подключение — от кольца мягко
     * расходятся круги («дыхание»); подключилось — распускаются лепестки, потом всё замирает.
     */
    drawSoft(now) {
      const ctx = this.ctx, S = this.size, C = this.col, dark = this.dark, st = this.state;
      const cx = S / 2, cy = S / 2, R = S / 2, k = S / 318;
      const r0 = R * 0.75, r1 = R * 0.69, lw = 11 * k;
      const t = (now - this.t0) / 1000;
      this.stepProgress(now);
      const flashK = this.flashAt > 0 ? Math.min(1, (now - this.flashAt) / FLASH_MS) : 1;
      const flashing = flashK < 1 && st === 'on';
      const main = st === 'error' ? C.err : C.light;
      const deep = st === 'error' ? C.err : C.acc;

      // 1. Мягкий ореол.
      let halo = ({ off: 0, scan: 0.22, connecting: 0.2, on: 0.42, error: 0.25 })[st] || 0;
      if (st === 'connecting') halo += 0.1 * Math.sin(t * 2.6);
      if (flashing) halo += 0.35 * (1 - easeOut(flashK));
      if (dark) halo *= 0.7;
      if (halo > 0) {
        const g = ctx.createRadialGradient(cx, cy, r1, cx, cy, R);
        g.addColorStop(0, rgba(main, halo));
        g.addColorStop(0.55, rgba(st === 'on' ? C.partner : main, halo * 0.35));
        g.addColorStop(1, rgba(main, 0));
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.fill();
      }

      // 2. Подключение: мягкие круги расходятся от кольца.
      if (st === 'connecting') {
        for (let i = 0; i < 2; i++) {
          const u = ((t / 1.8) + i / 2) % 1;
          ctx.lineWidth = (6 - 5 * u) * k;
          ctx.strokeStyle = rgba(main, (dark ? 0.45 : 0.6) * (1 - u));
          ctx.beginPath(); ctx.arc(cx, cy, r0 + (R - r0 - 3 * k) * easeOut(u), 0, TAU); ctx.stroke();
        }
      }

      // 3. Диск с мягкой тенью.
      ctx.save();
      ctx.shadowColor = dark ? 'rgba(0,0,0,0.45)' : rgba(deep, 0.18);
      ctx.shadowBlur = 26 * k; ctx.shadowOffsetY = 9 * k;
      const dg = ctx.createRadialGradient(cx - r1 * 0.25, cy - r1 * 0.35, r1 * 0.1, cx, cy, r1);
      dg.addColorStop(0, rgba(C.discA, 1));
      dg.addColorStop(1, rgba(C.discB, 1));
      ctx.fillStyle = dg;
      ctx.beginPath(); ctx.arc(cx, cy, r1, 0, TAU); ctx.fill();
      ctx.restore();
      // Блик сверху — диск как мягкая пуговица.
      const gl = ctx.createLinearGradient(cx, cy - r1, cx, cy);
      gl.addColorStop(0, dark ? 'rgba(255,255,255,0.07)' : 'rgba(255,255,255,0.9)');
      gl.addColorStop(1, 'rgba(255,255,255,0)');
      ctx.fillStyle = gl;
      ctx.beginPath(); ctx.ellipse(cx, cy - r1 * 0.38, r1 * 0.72, r1 * 0.5, 0, 0, TAU); ctx.fill();

      // 4. Дорожка кольца.
      ctx.save();
      ctx.lineCap = 'round';
      ctx.lineWidth = lw;
      ctx.strokeStyle = rgba(C.off, dark ? 0.9 : 1);
      ctx.beginPath(); ctx.arc(cx, cy, r0, 0, TAU); ctx.stroke();

      if (st === 'scan') {
        const p = this.shown;
        if (p > 0.002) {
          const a0 = -Math.PI / 2;
          ctx.strokeStyle = this.sweep(ctx, cx, cy, a0, C.light, C.acc, p);
          ctx.shadowColor = rgba(C.light, 0.8); ctx.shadowBlur = 10 * k;
          ctx.beginPath(); ctx.arc(cx, cy, r0, a0, a0 + p * TAU); ctx.stroke();
        }
        // Три точки кружат вокруг кольца.
        ctx.shadowBlur = 8 * k; ctx.shadowColor = rgba(C.light, 0.9);
        for (let i = 0; i < 3; i++) {
          const a = t * TAU / 3.2 + i * TAU / 3;
          const pulse = 0.6 + 0.4 * Math.sin(t * 3 + i * 2);
          ctx.fillStyle = rgba(i === 1 ? C.partner : C.light, 0.95);
          ctx.beginPath(); ctx.arc(cx + (r0 + 19 * k) * Math.cos(a), cy + (r0 + 19 * k) * Math.sin(a), (3.2 + 1.6 * pulse) * k, 0, TAU); ctx.fill();
        }
      } else if (st === 'connecting') {
        // Дуга плавно бежит по дорожке.
        const head = -Math.PI / 2 + t * TAU / 1.6;
        const len = Math.PI * (0.45 + 0.15 * Math.sin(t * 2));
        if (ctx.createConicGradient) {
          const g = ctx.createConicGradient(head - len, cx, cy);
          g.addColorStop(0, rgba(C.light, 0));
          g.addColorStop(len / TAU, rgba(C.acc, 1));
          g.addColorStop(Math.min(1, len / TAU + 0.001), rgba(C.light, 0));
          ctx.strokeStyle = g;
        } else ctx.strokeStyle = rgba(C.acc, 1);
        ctx.beginPath(); ctx.arc(cx, cy, r0, head - len, head); ctx.stroke();
      } else if (st === 'on' || st === 'error') {
        if (st === 'on' && ctx.createConicGradient) {
          const g = ctx.createConicGradient(-Math.PI / 2, cx, cy);
          g.addColorStop(0, rgba(C.light, 1));
          g.addColorStop(0.35, rgba(C.partner, 1));
          g.addColorStop(0.65, rgba(mix(C.light, C.acc, 0.35), 1));
          g.addColorStop(1, rgba(C.light, 1));
          ctx.strokeStyle = g;
        } else ctx.strokeStyle = rgba(main, 1);
        ctx.shadowColor = rgba(main, dark ? 0.6 : 0.75);
        ctx.shadowBlur = (flashing ? 22 : 12) * k;
        ctx.beginPath(); ctx.arc(cx, cy, r0, 0, TAU); ctx.stroke();
        // Тонкая светлая сердцевина — кольцо «объёмное», как сатиновая лента.
        ctx.shadowBlur = 0;
        ctx.lineWidth = 2 * k;
        ctx.strokeStyle = dark ? 'rgba(255,255,255,0.25)' : 'rgba(255,255,255,0.75)';
        ctx.beginPath(); ctx.arc(cx, cy, r0 - lw * 0.18, Math.PI * 1.05, Math.PI * 1.75); ctx.stroke();
      }
      ctx.restore();

      // 5. Подключилось: распускаются лепестки.
      if (flashing) {
        const e = easeOut(flashK);
        ctx.save();
        for (let i = 0; i < 10; i++) {
          const a = i * TAU / 10 + e * 0.5;
          const rr = r0 + (8 + 26 * e) * k;
          ctx.save();
          ctx.translate(cx + rr * Math.cos(a), cy + rr * Math.sin(a));
          ctx.rotate(a);
          ctx.fillStyle = rgba(i % 2 ? C.partner : C.light, 0.85 * (1 - e));
          ctx.beginPath(); ctx.ellipse(0, 0, (9 - 3 * e) * k, (4.5 - 1.5 * e) * k, 0, 0, TAU); ctx.fill();
          ctx.restore();
        }
        ctx.restore();
      }
    }

    /**
     * «Стекло»: прозрачный диск с бликом, за ним цветной свет; кольцо — неон двух цветов.
     * Подбор — вокруг кольца бежит луч и крутится пунктирная орбита; подключение — две кометы
     * догоняют друг друга; подключилось — по кольцу пробегает белый блик и расходится волна.
     */
    drawGlass(now) {
      const ctx = this.ctx, S = this.size, C = this.col, dark = this.dark, st = this.state;
      const cx = S / 2, cy = S / 2, R = S / 2, k = S / 318;
      const r0 = R * 0.78, r1 = R * 0.71;
      const t = (now - this.t0) / 1000;
      this.stepProgress(now);
      const flashK = this.flashAt > 0 ? Math.min(1, (now - this.flashAt) / FLASH_MS) : 1;
      const flashing = flashK < 1 && st === 'on';
      const A = st === 'error' ? C.err : C.a, B = st === 'error' ? C.err : C.b;

      // 1. Цветной свет за стеклом: A сверху слева, B снизу справа.
      let light = ({ off: 0.10, scan: 0.28, connecting: 0.30, on: 0.48, error: 0.32 })[st] || 0.1;
      if (st === 'connecting') light += 0.08 * Math.sin(t * 3.2);
      if (flashing) light += 0.35 * (1 - easeOut(flashK));
      if (!dark) light *= 0.75;
      const blob = (x, y, c, a) => {
        const g = ctx.createRadialGradient(x, y, 0, x, y, R * 0.95);
        g.addColorStop(0, rgba(c, a)); g.addColorStop(1, rgba(c, 0));
        ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.fill();
      };
      blob(cx - R * 0.32, cy - R * 0.3, A, light);
      blob(cx + R * 0.34, cy + R * 0.32, B, light * 0.9);

      // 2. Подбор: луч бежит вокруг кольца, снаружи крутится пунктирная орбита.
      if (st === 'scan') {
        if (ctx.createConicGradient) {
          const g = ctx.createConicGradient(t * TAU / 2, cx, cy);
          g.addColorStop(0, rgba(A, 0)); g.addColorStop(0.8, rgba(A, 0)); g.addColorStop(1, rgba(A, dark ? 0.32 : 0.22));
          ctx.fillStyle = g;
          ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.arc(cx, cy, r0 + 4 * k, 0, TAU, true); ctx.fill();
        }
        ctx.save();
        ctx.translate(cx, cy); ctx.rotate(-t * TAU / 14);
        ctx.setLineDash([2 * k, 7 * k]);
        ctx.lineWidth = 2 * k; ctx.strokeStyle = rgba(B, 0.6);
        ctx.beginPath(); ctx.arc(0, 0, r0 + 16 * k, 0, TAU); ctx.stroke();
        ctx.setLineDash([16 * k, 30 * k]);
        ctx.lineWidth = 1.2 * k; ctx.strokeStyle = rgba(A, 0.5);
        ctx.rotate(t * TAU / 6);
        ctx.beginPath(); ctx.arc(0, 0, r0 + 26 * k, 0, TAU); ctx.stroke();
        ctx.restore();
      }

      // 3. Стеклянный диск.
      const dg = ctx.createRadialGradient(cx - r1 * 0.3, cy - r1 * 0.4, r1 * 0.1, cx, cy, r1);
      const da = C.discAa, db = C.discBa;
      dg.addColorStop(0, 'rgba(' + da[0] + ',' + da[1] + ',' + da[2] + ',' + da[3] + ')');
      dg.addColorStop(1, 'rgba(' + db[0] + ',' + db[1] + ',' + db[2] + ',' + db[3] + ')');
      ctx.fillStyle = dg;
      ctx.beginPath(); ctx.arc(cx, cy, r1, 0, TAU); ctx.fill();
      // Цветной отсвет кольца на стекле.
      const tint = ctx.createLinearGradient(cx - r1, cy - r1, cx + r1, cy + r1);
      tint.addColorStop(0, rgba(A, dark ? 0.10 : 0.06)); tint.addColorStop(1, rgba(B, dark ? 0.12 : 0.07));
      ctx.fillStyle = tint;
      ctx.beginPath(); ctx.arc(cx, cy, r1, 0, TAU); ctx.fill();
      // Блик — стекло выпуклое.
      ctx.save();
      ctx.beginPath(); ctx.arc(cx, cy, r1, 0, TAU); ctx.clip();
      const hl = ctx.createLinearGradient(cx, cy - r1, cx, cy - r1 * 0.1);
      hl.addColorStop(0, dark ? 'rgba(255,255,255,0.22)' : 'rgba(255,255,255,0.85)');
      hl.addColorStop(1, 'rgba(255,255,255,0)');
      ctx.fillStyle = hl;
      ctx.beginPath(); ctx.ellipse(cx - r1 * 0.12, cy - r1 * 0.52, r1 * 0.78, r1 * 0.44, -0.25, 0, TAU); ctx.fill();
      ctx.restore();
      // Кромка стекла: светлая сверху, гаснет книзу.
      const edge = ctx.createLinearGradient(cx, cy - r1, cx, cy + r1);
      edge.addColorStop(0, dark ? 'rgba(255,255,255,0.45)' : 'rgba(255,255,255,1)');
      edge.addColorStop(1, dark ? 'rgba(255,255,255,0.06)' : 'rgba(255,255,255,0.3)');
      ctx.lineWidth = 1.3 * k; ctx.strokeStyle = edge;
      ctx.beginPath(); ctx.arc(cx, cy, r1 - 0.6, 0, TAU); ctx.stroke();

      // 4. Кольцо.
      ctx.save();
      ctx.lineCap = 'round';
      const neon = (rot) => {
        if (!ctx.createConicGradient) return rgba(A, 1);
        const g = ctx.createConicGradient(rot, cx, cy);
        g.addColorStop(0, rgba(A, 1)); g.addColorStop(0.5, rgba(B, 1)); g.addColorStop(1, rgba(A, 1));
        return g;
      };
      const oa = C.offA;
      ctx.lineWidth = 3 * k;
      ctx.strokeStyle = 'rgba(' + oa[0] + ',' + oa[1] + ',' + oa[2] + ',' + oa[3] + ')';
      ctx.beginPath(); ctx.arc(cx, cy, r0, 0, TAU); ctx.stroke();
      if (st === 'off') {
        ctx.globalAlpha = dark ? 0.28 : 0.35;
        ctx.lineWidth = 2 * k; ctx.strokeStyle = neon(-Math.PI / 2);
        ctx.beginPath(); ctx.arc(cx, cy, r0, 0, TAU); ctx.stroke();
        ctx.globalAlpha = 1;
      } else if (st === 'scan') {
        const p = this.shown;
        if (p > 0.002) {
          const a0 = -Math.PI / 2;
          ctx.strokeStyle = this.sweep(ctx, cx, cy, a0, A, B, p);
          ctx.lineWidth = 5 * k;
          ctx.shadowColor = rgba(A, 0.9); ctx.shadowBlur = 16 * k;
          ctx.beginPath(); ctx.arc(cx, cy, r0, a0, a0 + p * TAU); ctx.stroke();
          ctx.fillStyle = '#ffffff'; ctx.shadowColor = rgba(B, 1); ctx.shadowBlur = 16 * k;
          const a1 = a0 + p * TAU;
          ctx.beginPath(); ctx.arc(cx + r0 * Math.cos(a1), cy + r0 * Math.sin(a1), 4.2 * k, 0, TAU); ctx.fill();
        }
      } else if (st === 'connecting') {
        // Две кометы — цвета A и B — догоняют друг друга.
        for (let c = 0; c < 2; c++) {
          const col = c ? B : A;
          const head = -Math.PI / 2 + t * TAU / 1.4 + c * Math.PI;
          const tail = Math.PI * 0.55, steps = 24;
          ctx.shadowColor = rgba(col, 0.9); ctx.shadowBlur = 14 * k;
          for (let i = 0; i < steps; i++) {
            const f0 = i / steps, f1 = (i + 1) / steps;
            ctx.strokeStyle = rgba(col, f1 * f1);
            ctx.lineWidth = (1.2 + 4 * f1) * k;
            ctx.beginPath(); ctx.arc(cx, cy, r0, head - tail + tail * f0, head - tail + tail * f1 + 0.012); ctx.stroke();
          }
          ctx.fillStyle = '#ffffff';
          ctx.beginPath(); ctx.arc(cx + r0 * Math.cos(head), cy + r0 * Math.sin(head), 3.6 * k, 0, TAU); ctx.fill();
        }
      } else {
        // Подключено: неон двух цветов — мягкая подложка, свечение A и B, яркая сердцевина.
        ctx.lineWidth = 14 * k;
        ctx.strokeStyle = rgba(A, dark ? 0.10 : 0.08);
        ctx.beginPath(); ctx.arc(cx, cy, r0, 0, TAU); ctx.stroke();
        ctx.lineWidth = 5 * k;
        ctx.strokeStyle = st === 'error' ? rgba(A, 1) : neon(-Math.PI / 2);
        ctx.shadowColor = rgba(A, dark ? 0.95 : 0.6); ctx.shadowBlur = (dark ? 22 : 12) * k;
        ctx.beginPath(); ctx.arc(cx, cy, r0, -Math.PI / 2, Math.PI / 2); ctx.stroke();
        ctx.shadowColor = rgba(B, dark ? 0.95 : 0.6);
        ctx.beginPath(); ctx.arc(cx, cy, r0, Math.PI / 2, Math.PI * 1.5); ctx.stroke();
        ctx.shadowBlur = 0;
        ctx.lineWidth = 1.2 * k;
        ctx.strokeStyle = 'rgba(255,255,255,' + (dark ? 0.55 : 0.8) + ')';
        ctx.beginPath(); ctx.arc(cx, cy, r0 - 0.4, 0, TAU); ctx.stroke();
        // Вспышка: по кольцу пробегает белый блик.
        if (flashing && ctx.createConicGradient) {
          const head = -Math.PI / 2 + easeOut(flashK) * TAU;
          const g = ctx.createConicGradient(head - 0.9, cx, cy);
          g.addColorStop(0, 'rgba(255,255,255,0)');
          g.addColorStop(0.14, 'rgba(255,255,255,' + (0.95 * (1 - flashK)).toFixed(3) + ')');
          g.addColorStop(0.145, 'rgba(255,255,255,0)');
          g.addColorStop(1, 'rgba(255,255,255,0)');
          ctx.strokeStyle = g; ctx.lineWidth = 6 * k;
          ctx.shadowColor = 'rgba(255,255,255,0.9)'; ctx.shadowBlur = 16 * k;
          ctx.beginPath(); ctx.arc(cx, cy, r0, 0, TAU); ctx.stroke();
        }
      }
      ctx.restore();

      // 5. Волна от кольца наружу.
      if (flashing) {
        const e = easeOut(flashK);
        ctx.save();
        ctx.lineWidth = (2.6 * (1 - e) + 0.6) * k;
        ctx.strokeStyle = rgba(B, 0.8 * (1 - e));
        ctx.shadowColor = rgba(B, 0.9); ctx.shadowBlur = 14 * k;
        ctx.beginPath(); ctx.arc(cx, cy, r0 + (R - r0 - 2) * e, 0, TAU); ctx.stroke();
        ctx.restore();
      }
    }

    /** Заполненная часть кольца: тёмно-оранжевый у начала, светлый у головы. */
    sweep(ctx, cx, cy, a0, from, to, p) {
      if (!ctx.createConicGradient) return rgba(to, 1);
      const g = ctx.createConicGradient(a0, cx, cy);
      g.addColorStop(0, rgba(from, 1));
      g.addColorStop(Math.max(0.002, p), rgba(to, 1));
      g.addColorStop(Math.min(1, p + 0.002), rgba(from, 1));
      g.addColorStop(1, rgba(from, 1));
      return g;
    }

    /** Подключено: свет по кругу неровный — блики сверху-слева и справа, как на макете. */
    sweepFull(ctx, cx, cy, C) {
      if (!ctx.createConicGradient) return rgba(C.acc, 1);
      const g = ctx.createConicGradient(-Math.PI / 2, cx, cy);
      g.addColorStop(0, rgba(C.light, 1));
      g.addColorStop(0.18, rgba(C.acc, 1));
      g.addColorStop(0.32, rgba(C.light, 1));
      g.addColorStop(0.5, rgba(C.acc2, 1));
      g.addColorStop(0.7, rgba(C.acc, 1));
      g.addColorStop(0.86, rgba(C.light, 1));
      g.addColorStop(1, rgba(C.light, 1));
      return g;
    }

    /** Шкала внутри кольца во время подбора: пройденная часть подсвечена. */
    drawDial(ctx, cx, cy, r, k) {
      const C = this.col, n = 96, p = this.shown;
      ctx.save();
      ctx.lineCap = 'butt';
      for (let i = 0; i < n; i++) {
        const f = i / n, a = -Math.PI / 2 + f * TAU, long = i % 8 === 0;
        const lit = f <= p;
        ctx.strokeStyle = lit ? rgba(C.light, long ? 0.95 : 0.7) : rgba(C.acc, long ? 0.32 : 0.16);
        ctx.lineWidth = (long ? 1.6 : 1) * k;
        const r2 = r - (long ? 7 : 4) * k;
        ctx.beginPath();
        ctx.moveTo(cx + r * Math.cos(a), cy + r * Math.sin(a));
        ctx.lineTo(cx + r2 * Math.cos(a), cy + r2 * Math.sin(a));
        ctx.stroke();
      }
      ctx.restore();
    }

    drawCircuit(ctx, cx, cy, r0, R, t, k) {
      const C = this.col, dark = this.dark;
      const rot = t * TAU / 26; // медленно поворачивается — оборот за 26 с
      const base = r0 + 9 * k, span = R - base - 3 * k;
      const al = dark ? 1 : 0.85;
      ctx.save();
      // Луч-«радар»: светлый край ведёт, хвост гаснет.
      if (ctx.createConicGradient) {
        const g = ctx.createConicGradient(t * TAU / 2.4, cx, cy);
        g.addColorStop(0, rgba(C.acc, 0));
        g.addColorStop(0.84, rgba(C.acc, 0));
        g.addColorStop(1, rgba(C.acc, dark ? 0.20 : 0.12));
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.arc(cx, cy, r0 + 3 * k, 0, TAU, true); ctx.fill();
      }
      ctx.lineCap = 'butt';
      const pos = [];
      for (const tr of this.traces) {
        const a = tr.a + rot, a2 = a + tr.bend;
        const L = span * tr.len, rm = base + L * tr.mid, re = base + L;
        ctx.strokeStyle = rgba(C.acc, tr.al * 0.55 * al);
        ctx.lineWidth = tr.w * k;
        ctx.beginPath();
        ctx.moveTo(cx + base * Math.cos(a), cy + base * Math.sin(a));
        ctx.lineTo(cx + rm * Math.cos(a), cy + rm * Math.sin(a));
        if (tr.bend) ctx.arc(cx, cy, rm, a, a2, tr.bend < 0);
        ctx.lineTo(cx + re * Math.cos(a2), cy + re * Math.sin(a2));
        ctx.stroke();
        const ex = cx + re * Math.cos(a2), ey = cy + re * Math.sin(a2);
        ctx.fillStyle = rgba(C.acc, tr.al * 0.8 * al);
        if (tr.end === 'sq') ctx.fillRect(ex - 1.7 * k, ey - 1.7 * k, 3.4 * k, 3.4 * k);
        else if (tr.end === 'dot') { ctx.beginPath(); ctx.arc(ex, ey, 1.8 * k, 0, TAU); ctx.fill(); }
        pos.push({ a, a2, rm, re });
      }
      for (const ch of this.chips) {
        const a = ch.a + rot, r = base + span * ch.rf;
        ctx.fillStyle = rgba(C.acc, ch.al * 0.6 * al);
        ctx.fillRect(cx + r * Math.cos(a) - ch.s * k / 2, cy + r * Math.sin(a) - ch.s * k / 2, ch.s * k, ch.s * k);
      }
      // «Штрихкоды» — короткие поперечные полоски, как на 3-й картинке.
      for (const b of this.bars) {
        const r = base + span * b.rf;
        ctx.strokeStyle = rgba(C.light, b.al * 0.7 * al);
        ctx.lineWidth = 1.4 * k;
        for (let i = 0; i < b.n; i++) {
          const a = b.a + rot + i * 0.022;
          ctx.beginPath();
          ctx.moveTo(cx + r * Math.cos(a), cy + r * Math.sin(a));
          ctx.lineTo(cx + (r + 9 * k) * Math.cos(a), cy + (r + 9 * k) * Math.sin(a));
          ctx.stroke();
        }
      }
      // Импульсы бегут по дорожкам от кольца наружу.
      ctx.shadowColor = rgba(C.acc, 0.9);
      ctx.shadowBlur = 10 * k;
      const P = 9;
      for (let i = 0; i < P; i++) {
        const cyc = t * 0.75 + i / P;
        const idx = (Math.floor(cyc) * 11 + i * 17) % pos.length;
        const q = pos[idx], u = cyc % 1;
        const l1 = q.rm - base, l2 = Math.abs(q.a2 - q.a) * q.rm, l3 = q.re - q.rm, tot = l1 + l2 + l3;
        let d = u * tot, x, y;
        if (d <= l1) { const r = base + d; x = cx + r * Math.cos(q.a); y = cy + r * Math.sin(q.a); }
        else if (d <= l1 + l2) { const a = q.a + (q.a2 - q.a) * ((d - l1) / (l2 || 1)); x = cx + q.rm * Math.cos(a); y = cy + q.rm * Math.sin(a); }
        else { const r = q.rm + (d - l1 - l2); x = cx + r * Math.cos(q.a2); y = cy + r * Math.sin(q.a2); }
        ctx.fillStyle = rgba(dark ? [255, 236, 210] : C.light, (1 - u) * 0.95);
        ctx.beginPath(); ctx.arc(x, y, 2.1 * k, 0, TAU); ctx.fill();
      }
      ctx.restore();
    }
  }

  window.Ring = Ring;
  window.MockColor = { toRgb, rgba, mix, mulberry32, easeOut };
})();
