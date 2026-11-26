/*
 * Фон экрана: тёплая темнота, свечение за кнопкой и диагональные неоновые линии, как на макете.
 * Рисуется один раз (и при смене темы или размера) — неподвижный, батарею не тратит.
 */
(function () {
  'use strict';
  const { toRgb, rgba } = window.MockColor;

  function line(g, x0, y0, x1, y1, c, a, glow) {
    const gr = g.createLinearGradient(x0, y0, x1, y1);
    gr.addColorStop(0, rgba(c, 0));
    gr.addColorStop(0.45, rgba(c, a));
    gr.addColorStop(0.6, rgba(c, a * 0.8));
    gr.addColorStop(1, rgba(c, 0));
    if (glow) {
      g.save();
      g.strokeStyle = gr; g.globalAlpha = 0.16; g.lineWidth = 9;
      g.beginPath(); g.moveTo(x0, y0); g.lineTo(x1, y1); g.stroke();
      g.restore();
    }
    g.strokeStyle = gr; g.lineWidth = 1.2;
    g.beginPath(); g.moveTo(x0, y0); g.lineTo(x1, y1); g.stroke();
  }

  function plane(g, pts, c, a, dir) {
    const gr = g.createLinearGradient(dir[0], dir[1], dir[2], dir[3]);
    gr.addColorStop(0, rgba(c, a));
    gr.addColorStop(1, rgba(c, 0));
    g.fillStyle = gr;
    g.beginPath(); g.moveTo(pts[0][0], pts[0][1]);
    for (let i = 1; i < pts.length; i++) g.lineTo(pts[i][0], pts[i][1]);
    g.closePath(); g.fill();
  }

  /**
   * variant: 'simple' — линии вокруг кнопки (её центр — orbY); 'calm' — для расширенного режима и
   * маршрута: только свечение сверху и пара линий по краям.
   */
  function drawBackground(canvas, host, variant, orbY) {
    const W = canvas.clientWidth, H = canvas.clientHeight;
    if (!W || !H) return;
    const dpr = Math.min(3, window.devicePixelRatio || 1) * (window.__phoneScaleUp || 1);
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
    const g = canvas.getContext('2d');
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    const cs = getComputedStyle(host);
    const dark = host.dataset.theme !== 'light';
    const design = host.dataset.design || 'premium';
    if (design === 'soft') { softBackground(g, W, H, cs, dark, variant, orbY); return; }
    if (design === 'glass') { glassBackground(g, W, H, cs, dark, variant, orbY); return; }
    const acc = toRgb(cs.getPropertyValue('--accent'));
    const bg0 = toRgb(cs.getPropertyValue('--bg0')), bg1 = toRgb(cs.getPropertyValue('--bg1'));

    const base = g.createLinearGradient(0, 0, 0, H);
    base.addColorStop(0, rgba(bg1, 1)); base.addColorStop(0.55, rgba(bg0, 1)); base.addColorStop(1, rgba(bg1, 1));
    g.fillStyle = base; g.fillRect(0, 0, W, H);

    const cy = variant === 'simple' ? (orbY || H * 0.36) : H * 0.12;
    const glow = g.createRadialGradient(W / 2, cy, 0, W / 2, cy, W * (variant === 'simple' ? 0.85 : 0.9));
    glow.addColorStop(0, rgba(acc, dark ? 0.13 : 0.08));
    glow.addColorStop(0.5, rgba(acc, dark ? 0.045 : 0.03));
    glow.addColorStop(1, rgba(acc, 0));
    g.fillStyle = glow; g.fillRect(0, 0, W, H);

    const a = dark ? 0.55 : 0.32, pa = dark ? 0.05 : 0.035;
    if (variant === 'simple') {
      // Плоскости по краям — лёгкий объём, как на макете.
      plane(g, [[0, cy - W * 0.2], [W * 0.32, cy + W * 0.12], [0, cy + W * 0.45]], acc, pa, [0, cy, W * 0.3, cy]);
      plane(g, [[W, cy - W * 0.2], [W * 0.68, cy + W * 0.12], [W, cy + W * 0.45]], acc, pa, [W, cy, W * 0.7, cy]);
      plane(g, [[0, 0], [W * 0.45, 0], [0, cy * 0.55]], acc, pa * 0.8, [0, 0, W * 0.2, cy * 0.3]);
      plane(g, [[W, 0], [W * 0.55, 0], [W, cy * 0.55]], acc, pa * 0.8, [W, 0, W * 0.8, cy * 0.3]);
      // Крест за верхом кнопки и «галочка» к низу экрана.
      line(g, -W * 0.05, cy - W * 0.62, W * 0.62, cy + W * 0.05, acc, a, dark);
      line(g, W * 1.05, cy - W * 0.62, W * 0.38, cy + W * 0.05, acc, a, dark);
      line(g, -W * 0.02, cy + W * 0.05, W * 0.42, cy + W * 0.55, acc, a * 0.75, dark);
      line(g, W * 1.02, cy + W * 0.05, W * 0.58, cy + W * 0.55, acc, a * 0.75, dark);
      line(g, -W * 0.05, H * 0.86, W * 0.4, H * 0.7, acc, a * 0.45, false);
      line(g, W * 1.05, H * 0.86, W * 0.6, H * 0.7, acc, a * 0.45, false);
    } else {
      line(g, -W * 0.1, H * 0.02, W * 0.55, H * 0.2, acc, a * 0.6, dark);
      line(g, W * 1.1, H * 0.02, W * 0.45, H * 0.2, acc, a * 0.6, dark);
      plane(g, [[0, 0], [W * 0.5, 0], [0, H * 0.18]], acc, pa, [0, 0, W * 0.3, H * 0.1]);
      plane(g, [[W, 0], [W * 0.5, 0], [W, H * 0.18]], acc, pa, [W, 0, W * 0.7, H * 0.1]);
    }
    // Лёгкая виньетка.
    const v = g.createRadialGradient(W / 2, H * 0.45, Math.min(W, H) * 0.35, W / 2, H * 0.45, Math.max(W, H) * 0.8);
    v.addColorStop(0, 'rgba(0,0,0,0)');
    v.addColorStop(1, dark ? 'rgba(0,0,0,0.45)' : 'rgba(120,70,30,0.06)');
    g.fillStyle = v; g.fillRect(0, 0, W, H);
  }

  function blob(g, x, y, r, c, a) {
    const gr = g.createRadialGradient(x, y, 0, x, y, r);
    gr.addColorStop(0, rgba(c, a));
    gr.addColorStop(0.55, rgba(c, a * 0.45));
    gr.addColorStop(1, rgba(c, 0));
    g.fillStyle = gr;
    g.fillRect(x - r, y - r, r * 2, r * 2);
  }

  /**
   * «Нежный»: светлая пастель — мягкие пятна основного цвета и цвета-напарника, как акварель, внизу
   * две плавные волны и несколько тихих кружков. В тёмной теме — те же пятна, приглушённые.
   */
  function softBackground(g, W, H, cs, dark, variant, orbY) {
    const bg0 = toRgb(cs.getPropertyValue('--bg0')), bg1 = toRgb(cs.getPropertyValue('--bg1'));
    const pastel = toRgb(cs.getPropertyValue('--pastel')), partner = toRgb(cs.getPropertyValue('--partner'));
    const base = g.createLinearGradient(0, 0, W * 0.3, H);
    base.addColorStop(0, rgba(bg1, 1)); base.addColorStop(0.5, rgba(bg0, 1)); base.addColorStop(1, rgba(bg1, 1));
    g.fillStyle = base; g.fillRect(0, 0, W, H);
    const k = dark ? 0.32 : 1;
    const cy = variant === 'simple' ? (orbY || H * 0.36) : H * 0.1;
    if (variant === 'simple') {
      blob(g, W * 0.12, cy - W * 0.55, W * 0.75, pastel, 0.55 * k);
      blob(g, W * 0.95, cy - W * 0.05, W * 0.62, partner, 0.5 * k);
      blob(g, W * 0.5, cy, W * 0.55, pastel, 0.28 * k);
      blob(g, W * 0.05, H * 0.82, W * 0.6, partner, 0.32 * k);
    } else {
      blob(g, W * 0.1, -W * 0.1, W * 0.7, pastel, 0.5 * k);
      blob(g, W * 0.95, H * 0.12, W * 0.55, partner, 0.38 * k);
      blob(g, W * 0.8, H * 0.9, W * 0.6, pastel, 0.25 * k);
    }
    // Волны у низа экрана.
    const wave = (y0, amp, c, a, ph) => {
      g.beginPath(); g.moveTo(0, H);
      for (let x = 0; x <= W; x += 6) g.lineTo(x, y0 + Math.sin(x / W * Math.PI * 2 + ph) * amp + Math.sin(x / W * Math.PI * 5 + ph * 2) * amp * 0.25);
      g.lineTo(W, H); g.closePath();
      const gr = g.createLinearGradient(0, y0 - amp, 0, H);
      gr.addColorStop(0, rgba(c, a)); gr.addColorStop(1, rgba(c, a * 0.2));
      g.fillStyle = gr; g.fill();
    };
    wave(H * 0.86, 14, pastel, 0.30 * k, 0.6);
    wave(H * 0.9, 12, partner, 0.26 * k, 2.4);
    // Тихие кружки — несколько, всегда на тех же местах.
    const { mulberry32 } = window.MockColor;
    const rnd = mulberry32(variant === 'simple' ? 7 : 11);
    for (let i = 0; i < 9; i++) {
      const x = rnd() * W, y = rnd() * H * 0.8, r = 3 + rnd() * 9, c = rnd() < 0.5 ? pastel : partner;
      g.fillStyle = rgba(c, (dark ? 0.16 : 0.45) * (0.5 + rnd() * 0.5));
      g.beginPath(); g.arc(x, y, r, 0, Math.PI * 2); g.fill();
      if (rnd() < 0.4) {
        g.strokeStyle = rgba(c, dark ? 0.22 : 0.6); g.lineWidth = 1.2;
        g.beginPath(); g.arc(x, y, r + 5 + rnd() * 6, 0, Math.PI * 2); g.stroke();
      }
    }
  }

  /**
   * «Стекло»: глубокий тёмно-синий фон с двумя неоновыми пятнами — их свет виден сквозь
   * полупрозрачные карточки; тонкая сетка точек и перспективная сетка у низа. В светлой теме — те же
   * пятна на светлом, без сетки у низа.
   */
  function glassBackground(g, W, H, cs, dark, variant, orbY) {
    const bg0 = toRgb(cs.getPropertyValue('--bg0')), bg1 = toRgb(cs.getPropertyValue('--bg1'));
    const A = toRgb(cs.getPropertyValue('--neon-a')), B = toRgb(cs.getPropertyValue('--neon-b'));
    const base = g.createLinearGradient(0, 0, 0, H);
    base.addColorStop(0, rgba(bg1, 1)); base.addColorStop(0.5, rgba(bg0, 1)); base.addColorStop(1, rgba(bg1, 1));
    g.fillStyle = base; g.fillRect(0, 0, W, H);
    const k = dark ? 1 : 0.62;
    const cy = variant === 'simple' ? (orbY || H * 0.36) : H * 0.1;
    if (variant === 'simple') {
      blob(g, W * 0.08, cy - W * 0.42, W * 0.78, A, 0.42 * k);
      blob(g, W * 0.98, cy + W * 0.28, W * 0.74, B, 0.40 * k);
      blob(g, W * 0.2, H * 0.92, W * 0.6, B, 0.22 * k);
      blob(g, W * 0.92, H * 0.78, W * 0.42, A, 0.16 * k);
    } else {
      blob(g, W * 0.05, -W * 0.05, W * 0.75, A, 0.36 * k);
      blob(g, W * 1.0, H * 0.22, W * 0.62, B, 0.30 * k);
      blob(g, W * 0.3, H * 0.95, W * 0.6, B, 0.18 * k);
    }
    // Сетка точек.
    g.fillStyle = dark ? 'rgba(255,255,255,0.055)' : 'rgba(30,40,90,0.06)';
    for (let y = 12; y < H; y += 22) for (let x = 11; x < W; x += 22) g.fillRect(x, y, 1.3, 1.3);
    if (dark && variant === 'simple') {
      // Перспективная неоновая сетка у низа.
      const top = H * 0.8, vx = W / 2;
      g.save();
      g.beginPath(); g.rect(0, top, W, H - top); g.clip();
      const fade = g.createLinearGradient(0, top, 0, H);
      fade.addColorStop(0, rgba(B, 0)); fade.addColorStop(1, rgba(B, 0.22));
      g.strokeStyle = fade; g.lineWidth = 1;
      for (let i = -10; i <= 10; i++) { g.beginPath(); g.moveTo(vx + i * 14, top); g.lineTo(vx + i * 70, H); g.stroke(); }
      for (let j = 1; j < 8; j++) { const y = top + (H - top) * Math.pow(j / 8, 1.8); g.beginPath(); g.moveTo(0, y); g.lineTo(W, y); g.stroke(); }
      g.restore();
    }
    const v = g.createRadialGradient(W / 2, H * 0.45, Math.min(W, H) * 0.35, W / 2, H * 0.45, Math.max(W, H) * 0.8);
    v.addColorStop(0, 'rgba(0,0,0,0)');
    v.addColorStop(1, dark ? 'rgba(0,0,0,0.5)' : 'rgba(40,50,110,0.06)');
    g.fillStyle = v; g.fillRect(0, 0, W, H);
  }

  window.drawBackground = drawBackground;
})();
