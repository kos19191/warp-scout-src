/*
 * Схема маршрута на тёмной карте (макет для будущей RouteMapView), по мотивам 5-й картинки:
 * кварталы и улицы рисуются кодом по постоянному зерну, по улицам светится маршрут
 * «вы → вход → выход WARP → второй выход», от выходов пунктиром — приложения, которые идут через них.
 * Линия прорисовывается при открытии и при подключении, потом картинка замирает.
 */
(function () {
  'use strict';
  const { toRgb, rgba, mulberry32, easeOut } = window.MockColor;
  const TAU = Math.PI * 2;
  const ANGLE = -0.12; // улицы чуть повёрнуты — карта не выглядит таблицей
  const DRAW_MS = 2300, BRANCH_MS = 700;

  class RouteMap {
    constructor(canvas, host) {
      this.cv = canvas; this.ctx = canvas.getContext('2d'); this.host = host;
      this.mode = 'on'; this.second = true;
      this.t0 = -1; this.raf = 0; this.base = null; this.W = 0; this.H = 0;
      this.labels = {
        you: 'Вы · мобильная', entry: 'Вход · 188.114.97.6:890', warp: 'Выход WARP · Стокгольм', second: 'Второй выход · NL',
      };
    }

    readColors() {
      const cs = getComputedStyle(this.host);
      const g = (n) => toRgb(cs.getPropertyValue(n));
      this.dark = this.host.dataset.theme !== 'light';
      this.col = { acc: g('--accent'), acc2: g('--accent2'), light: g('--accent-light'), text: g('--text'), blue: g('--blue') };
      // «Нежный» и «Стекло» задают карте свои цвета; у «Премиума» их нет — карта как была.
      const v = (n) => cs.getPropertyValue(n).trim();
      this.mapc = v('--map-bg') ? { bg: v('--map-bg'), block: g('--map-block'), street: v('--map-street'), core: g('--route-core') } : null;
      this.base = null;
    }

    resize() {
      const w = this.cv.clientWidth, h = this.cv.clientHeight;
      if (!w || !h) return;
      const dpr = Math.min(3, window.devicePixelRatio || 1) * (window.__phoneScaleUp || 1);
      this.W = w; this.H = h; this.dpr = dpr;
      this.cv.width = Math.round(w * dpr); this.cv.height = Math.round(h * dpr);
      this.base = null;
      this.kick();
    }

    setMode(m) {
      if (m === this.mode) return;
      const prev = this.mode;
      this.mode = m;
      if (m === 'on' && prev !== 'on') this.t0 = performance.now();
      if (m === 'connecting') this.t0 = performance.now();
      this.kick();
    }

    play() { this.t0 = performance.now(); this.kick(); }

    kick() { if (!this.raf) this.raf = requestAnimationFrame((t) => this.frame(t)); }

    frame(now) {
      this.raf = 0;
      if (!this.W) this.resize();
      if (!this.W) return;
      this.draw(now);
      const busy = this.mode === 'connecting' || (this.mode === 'on' && this.t0 > 0 && now - this.t0 < DRAW_MS + BRANCH_MS + 50);
      const vis = this.cv.offsetParent !== null && !this.cv.closest('.hidden');
      if (busy && vis) this.raf = requestAnimationFrame((t) => this.frame(t));
    }

    /** Точка в координатах сетки улиц → на экран (поворот вокруг центра). */
    toScreen(x, y) {
      const cx = this.W / 2, cy = this.H / 2, c = Math.cos(ANGLE), s = Math.sin(ANGLE);
      const dx = x - cx, dy = y - cy;
      return [cx + dx * c - dy * s, cy + dx * s + dy * c];
    }

    /** Город: кварталы, дома, улицы — один раз в отдельный холст. */
    buildBase() {
      const W = this.W, H = this.H, dpr = this.dpr, dark = this.dark;
      const off = document.createElement('canvas');
      off.width = Math.round(W * dpr); off.height = Math.round(H * dpr);
      const g = off.getContext('2d');
      g.setTransform(dpr, 0, 0, dpr, 0, 0);
      const mc = this.mapc;
      g.fillStyle = mc ? mc.bg : dark ? '#0d0a08' : '#efe6dc';
      g.fillRect(0, 0, W, H);
      const rnd = mulberry32(1126);
      g.save();
      g.translate(W / 2, H / 2); g.rotate(ANGLE); g.translate(-W / 2, -H / 2);
      const pad = 90, x0 = -pad, y0 = -pad, x1 = W + pad, y1 = H + pad;
      // Главные улицы — шаг 64, как сетка маршрута; между ними — переулки.
      const M = 64, ox = 20, oy = 18;
      const majX = [], majY = [];
      for (let x = ox - M * 3; x < x1; x += M) majX.push(x);
      for (let y = oy - M * 3; y < y1; y += M) majY.push(y);
      this.grid = { M, ox, oy };
      // Кварталы между главными улицами: дома мелкими прямоугольниками.
      const { mix } = window.MockColor;
      const shade = (f) => { const c = mix(mc.block, f > 0 ? [255, 255, 255] : [0, 0, 0], Math.abs(f)); return 'rgb(' + c.join(',') + ')'; };
      const houses = mc ? [shade(0), shade(0.12), shade(-0.08), shade(0.22), shade(-0.15)]
        : dark
        ? ['#2b1d13', '#33220f', '#3d2914', '#241912', '#4a2f15']
        : ['#e3cbb2', '#dcc1a6', '#ead6c1', '#d6b796', '#f0dfcc'];
      for (let i = 0; i < majX.length - 1; i++) {
        for (let j = 0; j < majY.length - 1; j++) {
          const bx = majX[i] + 6, by = majY[j] + 6, bw = M - 12, bh = M - 12;
          // переулок через квартал
          const split = rnd() < 0.6;
          const sx = bx + bw * (0.35 + rnd() * 0.3);
          for (let y = by; y < by + bh - 3; y += 6 + rnd() * 4) {
            for (let x = bx; x < bx + bw - 3; x += 6 + rnd() * 5) {
              if (split && Math.abs(x - sx) < 4) continue;
              if (rnd() < 0.18) continue;
              const w = 3 + rnd() * 5, h = 3 + rnd() * 4;
              g.globalAlpha = (dark ? 0.55 : 0.6) + rnd() * 0.4;
              g.fillStyle = houses[Math.floor(rnd() * houses.length)];
              g.fillRect(x, y, Math.min(w, bx + bw - x), Math.min(h, by + bh - y));
            }
          }
          g.globalAlpha = 1;
        }
      }
      // Улицы.
      g.lineCap = 'butt';
      g.strokeStyle = mc ? mc.street : dark ? 'rgba(120,100,85,0.22)' : 'rgba(255,255,255,0.95)';
      g.lineWidth = 3;
      for (const x of majX) { g.beginPath(); g.moveTo(x, y0); g.lineTo(x, y1); g.stroke(); }
      for (const y of majY) { g.beginPath(); g.moveTo(x0, y); g.lineTo(x1, y); g.stroke(); }
      g.strokeStyle = mc ? mc.street : dark ? 'rgba(120,100,85,0.12)' : 'rgba(255,255,255,0.7)';
      if (mc) g.globalAlpha = 0.55;
      g.lineWidth = 1.2;
      for (const x of majX) { g.beginPath(); g.moveTo(x + M / 2, y0); g.lineTo(x + M / 2, y1); g.stroke(); }
      for (const y of majY) { g.beginPath(); g.moveTo(x0, y + M / 2); g.lineTo(x1, y + M / 2); g.stroke(); }
      // Проспект наискосок.
      g.globalAlpha = 1;
      g.strokeStyle = mc ? mc.street : dark ? 'rgba(140,110,90,0.20)' : 'rgba(255,255,255,0.9)';
      g.lineWidth = 4;
      g.beginPath(); g.moveTo(x0, y1 - 60); g.lineTo(x1, y0 + 120); g.stroke();
      g.restore();
      // Края темнее — взгляд к маршруту.
      const v = g.createRadialGradient(W / 2, H / 2, Math.min(W, H) * 0.3, W / 2, H / 2, Math.max(W, H) * 0.75);
      v.addColorStop(0, 'rgba(0,0,0,0)');
      v.addColorStop(1, dark ? 'rgba(0,0,0,0.55)' : mc ? 'rgba(60,50,90,0.08)' : 'rgba(120,80,40,0.10)');
      g.fillStyle = v; g.fillRect(0, 0, W, H);
      this.base = off;
    }

    /** Маршрут по главным улицам: вершины в координатах сетки, у узлов — имена. */
    route() {
      const { M, ox, oy } = this.grid;
      const X = (i) => ox + M * i, Y = (j) => oy + M * j;
      const pts = [
        [X(1), Y(4), 'you'], [X(1), Y(3)], [X(2), Y(3)], [X(2), Y(1), 'entry'], [X(4), Y(1), 'warp'],
      ];
      if (this.second) pts.push([X(4), Y(3)], [X(5), Y(3), 'second']);
      return pts.map((p) => { const s = this.toScreen(p[0], p[1]); return { x: s[0], y: s[1], id: p[2] || '' }; });
    }

    draw(now) {
      const ctx = this.ctx, W = this.W, H = this.H, C = this.col, dark = this.dark;
      if (!this.base) this.buildBase();
      ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);
      ctx.drawImage(this.base, 0, 0, W, H);
      const pts = this.route();
      const seg = [], cum = [0];
      for (let i = 1; i < pts.length; i++) {
        const l = Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y);
        seg.push(l); cum.push(cum[i - 1] + l);
      }
      const total = cum[cum.length - 1];
      const entryAt = cum[pts.findIndex((p) => p.id === 'entry')];
      let reach, branches = 0;
      if (this.mode === 'off') {
        reach = 0;
      } else if (this.mode === 'connecting') {
        const q = ((now - this.t0) / 1500) % 1;
        reach = entryAt * easeOut(q);
      } else {
        const e = this.t0 > 0 ? Math.min(1, (now - this.t0) / DRAW_MS) : 1;
        reach = total * (e < 1 ? (e < 0.5 ? 2 * e * e : 1 - Math.pow(-2 * e + 2, 2) / 2) : 1);
        branches = this.t0 > 0 ? Math.max(0, Math.min(1, (now - this.t0 - DRAW_MS) / BRANCH_MS)) : 1;
      }

      // Будущий путь — тусклым пунктиром.
      ctx.save();
      ctx.setLineDash([3, 6]);
      ctx.lineWidth = 1.6;
      ctx.strokeStyle = rgba(C.acc, this.mode === 'off' ? 0.35 : 0.25);
      this.polyline(ctx, pts, total);
      ctx.restore();

      if (reach > 0.5) {
        // Тёплое пятно вдоль маршрута, широкое свечение и яркая сердцевина.
        ctx.save();
        ctx.lineJoin = 'round'; ctx.lineCap = 'round';
        ctx.strokeStyle = rgba(C.acc, dark ? 0.10 : 0.10); ctx.lineWidth = 34;
        this.polyline(ctx, pts, reach);
        ctx.strokeStyle = rgba(C.acc, dark ? 0.30 : 0.28); ctx.lineWidth = 9;
        ctx.shadowColor = rgba(C.acc, 0.9); ctx.shadowBlur = dark ? 16 : 8;
        this.polyline(ctx, pts, reach);
        ctx.shadowBlur = 0;
        ctx.strokeStyle = this.mapc ? rgba(this.mapc.core, 1) : dark ? rgba([255, 214, 160], 1) : rgba(C.acc, 1); ctx.lineWidth = 2.6;
        this.polyline(ctx, pts, reach);
        ctx.restore();
      }

      // Ответвления к приложениям.
      if (branches > 0) this.drawBranches(ctx, pts, branches);

      // Узлы.
      pts.forEach((p, i) => {
        if (!p.id) return;
        const at = cum[i];
        let pop = this.mode === 'off' ? (p.id === 'you' ? 1 : 0.35) : reach >= at - 0.5 ? 1 : 0.35;
        if (this.mode === 'connecting' && p.id !== 'you' && p.id !== 'entry') pop = 0.35;
        this.node(ctx, p, pop >= 1, now);
      });
    }

    polyline(ctx, pts, upTo) {
      ctx.beginPath();
      ctx.moveTo(pts[0].x, pts[0].y);
      let done = 0;
      for (let i = 1; i < pts.length; i++) {
        const a = pts[i - 1], b = pts[i];
        const l = Math.hypot(b.x - a.x, b.y - a.y);
        if (done + l <= upTo) { ctx.lineTo(b.x, b.y); done += l; continue; }
        const f = Math.max(0, (upTo - done) / l);
        ctx.lineTo(a.x + (b.x - a.x) * f, a.y + (b.y - a.y) * f);
        break;
      }
      ctx.stroke();
    }

    node(ctx, p, lit, now) {
      const C = this.col, dark = this.dark;
      ctx.save();
      if (p.id === 'you') {
        // Метка «вы»: белая капля с кольцом.
        const x = p.x, y = p.y;
        ctx.fillStyle = dark ? 'rgba(255,255,255,0.12)' : 'rgba(0,0,0,0.08)';
        ctx.beginPath(); ctx.ellipse(x, y, 9, 4, 0, 0, TAU); ctx.fill();
        ctx.strokeStyle = dark ? '#ffffff' : '#2a211b'; ctx.lineWidth = 2.2;
        ctx.beginPath(); ctx.arc(x, y, 4, 0, TAU); ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(x, y - 6);
        ctx.bezierCurveTo(x - 9, y - 16, x - 10, y - 30, x, y - 31);
        ctx.bezierCurveTo(x + 10, y - 30, x + 9, y - 16, x, y - 6);
        ctx.fillStyle = dark ? '#0d0a08' : '#fff';
        ctx.fill(); ctx.stroke();
        ctx.beginPath(); ctx.arc(x, y - 21, 4, 0, TAU); ctx.stroke();
      } else {
        const r = p.id === 'second' ? 8 : 6.5;
        if (lit) { ctx.shadowColor = rgba(C.acc, 0.95); ctx.shadowBlur = 16; }
        if (p.id === 'second') {
          ctx.strokeStyle = lit ? (dark ? '#fff1e0' : rgba(C.acc, 1)) : rgba(C.acc, 0.4); ctx.lineWidth = 2.4;
          ctx.fillStyle = dark ? '#0d0a08' : '#fff';
          ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, TAU); ctx.fill(); ctx.stroke();
          ctx.fillStyle = lit ? rgba(C.acc, 1) : rgba(C.acc, 0.4);
          ctx.beginPath(); ctx.arc(p.x, p.y, 3, 0, TAU); ctx.fill();
        } else {
          ctx.fillStyle = lit ? rgba(C.acc, 1) : rgba(C.acc, 0.35);
          ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, TAU); ctx.fill();
          ctx.shadowBlur = 0;
          ctx.fillStyle = dark ? '#fff4e6' : '#fff';
          ctx.beginPath(); ctx.arc(p.x, p.y, 2.6, 0, TAU); ctx.fill();
        }
      }
      ctx.restore();
      if (lit || p.id === 'you') this.label(ctx, p);
    }

    label(ctx, p) {
      const text = this.labels[p.id];
      if (!text) return;
      const dark = this.dark;
      ctx.save();
      ctx.font = '600 11.5px Roboto, "Segoe UI", system-ui, sans-serif';
      const w = ctx.measureText(text).width + 16, h = 22;
      const off = { you: [14, -2], entry: [-w / 2, -32], warp: [-w / 2, -32], second: [-w + 6, 14] }[p.id] || [10, -10];
      let x = p.x + off[0], y = p.y + off[1];
      x = Math.max(6, Math.min(this.W - w - 6, x)); y = Math.max(6, Math.min(this.H - h - 6, y));
      ctx.fillStyle = dark ? 'rgba(14,10,8,0.82)' : 'rgba(255,255,255,0.92)';
      ctx.strokeStyle = rgba(this.col.acc, dark ? 0.35 : 0.30);
      ctx.lineWidth = 1;
      const r = 8;
      ctx.beginPath();
      ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r);
      ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
      ctx.fill(); ctx.stroke();
      ctx.fillStyle = dark ? '#f5efe9' : '#1e1915';
      ctx.textBaseline = 'middle';
      ctx.fillText(text, x + 8, y + h / 2 + 0.5);
      ctx.restore();
    }

    /** Пунктир к приложениям: от выхода WARP и от второго выхода, синие кружки — как на 5-й картинке. */
    drawBranches(ctx, pts, k) {
      const C = this.col, dark = this.dark;
      const find = (id) => pts.find((p) => p.id === id);
      const sets = [];
      const warp = find('warp'), second = find('second');
      if (warp) sets.push({ from: warp, items: [['Y', -70, -54], ['In', 34, -64]] });
      if (second) sets.push({ from: second, items: [['GPT', -86, 66], ['Cl', -34, 82], ['T', 12, 74]] });
      ctx.save();
      ctx.globalAlpha = k;
      for (const s of sets) {
        for (const [txt, dx, dy] of s.items) {
          const x = Math.max(16, Math.min(this.W - 16, s.from.x + dx)), y = Math.max(16, Math.min(this.H - 16, s.from.y + dy));
          ctx.setLineDash([2, 4]);
          ctx.strokeStyle = dark ? 'rgba(255,255,255,0.75)' : 'rgba(40,30,20,0.55)';
          ctx.lineWidth = 1.5;
          ctx.beginPath(); ctx.moveTo(s.from.x, s.from.y); ctx.lineTo(s.from.x, y); ctx.lineTo(x, y); ctx.stroke();
          ctx.setLineDash([]);
          ctx.shadowColor = rgba(C.blue, 0.9); ctx.shadowBlur = 14;
          ctx.fillStyle = rgba(C.blue, 1);
          ctx.beginPath(); ctx.arc(x, y, 12, 0, TAU); ctx.fill();
          ctx.shadowBlur = 0;
          ctx.strokeStyle = 'rgba(255,255,255,0.9)'; ctx.lineWidth = 1.5;
          ctx.beginPath(); ctx.arc(x, y, 12, 0, TAU); ctx.stroke();
          ctx.fillStyle = '#ffffff';
          ctx.font = '800 ' + (txt.length > 2 ? 8.5 : 10.5) + 'px Roboto, system-ui, sans-serif';
          ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
          ctx.fillText(txt, x, y + 0.5);
        }
      }
      ctx.restore();
    }
  }

  window.RouteMap = RouteMap;
})();
