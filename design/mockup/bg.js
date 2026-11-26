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

  window.drawBackground = drawBackground;
})();
