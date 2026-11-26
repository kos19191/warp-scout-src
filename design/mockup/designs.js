/*
 * Дизайны макета: «Премиум» (как в бете 7), «Нежный» (пастель, 6 цветов на выбор) и «Стекло»
 * (неоновое стекло, 5 сочетаний). Цвета — переменные CSS на корне приложения: их же читают холсты
 * кнопки, фона и схемы маршрута. Облик карточек, кнопок и вкладок — в style.css по data-design.
 */
(function () {
  'use strict';

  /** «Нежный»: пастель для заливок и глубокий оттенок того же цвета для текста и значков. */
  const SOFT = [
    { id: 'lavender', name: 'Лаванда', pastel: '#C9B8F2', deep: '#6B55C0', partner: '#F4BCD2' },
    { id: 'mint', name: 'Мята', pastel: '#A9E4D0', deep: '#2E8A6E', partner: '#B5D3F5' },
    { id: 'peach', name: 'Персик', pastel: '#FFCAB0', deep: '#C8633A', partner: '#F7C2D4' },
    { id: 'sky', name: 'Небо', pastel: '#B3D1F6', deep: '#3A73BD', partner: '#CBBDF3' },
    { id: 'rose', name: 'Роза', pastel: '#F6BED2', deep: '#BD4C77', partner: '#FFD3B8' },
    { id: 'vanilla', name: 'Ваниль', pastel: '#F2DE9A', deep: '#94700C', partner: '#B5E5D3' },
  ];

  /** «Стекло»: два неоновых цвета; для светлой темы — их же насыщенные тёмные варианты. */
  const GLASS = [
    { id: 'cyber', name: 'Киберпанк', a: '#22E1FF', b: '#FF3DF2', la: '#0096B8', lb: '#C215B8' },
    { id: 'aurora', name: 'Аврора', a: '#3DFFB0', b: '#4D8DFF', la: '#0E9F6E', lb: '#2E63D6' },
    { id: 'sunset', name: 'Закат', a: '#FF4D8D', b: '#FFB443', la: '#DB2266', lb: '#D97706' },
    { id: 'violet', name: 'Ультрафиолет', a: '#A066FF', b: '#38CFFF', la: '#7434E0', lb: '#0284C7' },
    { id: 'acid', name: 'Кислота', a: '#C8FF3D', b: '#2BF5D0', la: '#4D8A06', lb: '#0B8F80' },
  ];

  function hex(c) {
    c = c.replace('#', '');
    const n = parseInt(c, 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  }
  function toHex(rgb) { return '#' + rgb.map((v) => Math.round(v).toString(16).padStart(2, '0')).join(''); }
  function mix(a, b, t) { const x = hex(a), y = hex(b); return toHex(x.map((v, i) => v + (y[i] - v) * t)); }
  function rgba(c, a) { const x = hex(c); return 'rgba(' + x[0] + ',' + x[1] + ',' + x[2] + ',' + a + ')'; }

  function softVars(t, dark) {
    if (!dark) {
      const ink = mix(t.deep, '#1d1a26', 0.72);
      return {
        '--bg0': mix(t.pastel, '#ffffff', 0.9), '--bg1': mix(t.pastel, '#ffffff', 0.78),
        '--text': ink, '--text2': mix(ink, '#ffffff', 0.38), '--text3': mix(ink, '#ffffff', 0.6),
        '--accent': t.deep, '--accent2': mix(t.deep, '#000000', 0.12), '--accent-light': t.pastel,
        '--accent-soft': rgba(t.pastel, 0.38), '--accent-line': rgba(t.deep, 0.32), '--glow': rgba(t.pastel, 0.7),
        '--card': 'rgba(255, 255, 255, .74)', '--card-solid': '#ffffff', '--card-border': 'rgba(255, 255, 255, .95)',
        '--card-shadow': '0 10px 30px ' + rgba(t.deep, 0.10) + ', 0 2px 6px ' + rgba(t.deep, 0.05),
        '--line': rgba(t.deep, 0.12), '--line-soft': rgba(t.deep, 0.07),
        '--field': rgba(t.pastel, 0.22), '--field-border': rgba(t.deep, 0.14),
        '--sw-off': rgba(t.deep, 0.10), '--sw-border': rgba(t.deep, 0.10), '--sw-knob': '#ffffff',
        '--ok': '#3E9E78', '--warn': '#C98A2B', '--err': '#D0566A', '--blue': '#5B93D1',
        '--nav-bg': 'rgba(255, 255, 255, .80)',
        '--disc-a': '#ffffff', '--disc-b': mix(t.pastel, '#ffffff', 0.55), '--ring-off': mix(t.pastel, '#ffffff', 0.35),
        '--sheet': mix(t.pastel, '#ffffff', 0.93), '--scrim': rgba(t.deep, 0.22),
        '--partner': t.partner, '--pastel': t.pastel,
        '--map-bg': mix(t.pastel, '#ffffff', 0.82), '--map-block': mix(t.pastel, '#ffffff', 0.45),
        '--map-street': 'rgba(255, 255, 255, .95)', '--route-core': '#ffffff',
      };
    }
    const bg = mix(t.deep, '#15131c', 0.82);
    return {
      '--bg0': bg, '--bg1': mix(t.deep, '#1c1a26', 0.72),
      '--text': mix(t.pastel, '#ffffff', 0.82), '--text2': mix(t.pastel, '#a7a2b4', 0.7), '--text3': mix(t.pastel, '#6f6a7c', 0.75),
      '--accent': t.pastel, '--accent2': mix(t.pastel, t.deep, 0.35), '--accent-light': mix(t.pastel, '#ffffff', 0.4),
      '--accent-soft': rgba(t.pastel, 0.14), '--accent-line': rgba(t.pastel, 0.4), '--glow': rgba(t.pastel, 0.45),
      '--card': 'rgba(255, 255, 255, .06)', '--card-solid': mix(bg, '#ffffff', 0.05), '--card-border': 'rgba(255, 255, 255, .08)',
      '--card-shadow': '0 12px 30px rgba(0, 0, 0, .30)',
      '--line': 'rgba(255, 255, 255, .09)', '--line-soft': 'rgba(255, 255, 255, .05)',
      '--field': 'rgba(255, 255, 255, .05)', '--field-border': 'rgba(255, 255, 255, .10)',
      '--sw-off': 'rgba(255, 255, 255, .10)', '--sw-border': 'rgba(255, 255, 255, .12)', '--sw-knob': mix(t.pastel, '#ffffff', 0.7),
      '--ok': '#7FD8B0', '--warn': '#F2C27A', '--err': '#F28B9A', '--blue': '#9CC3F2',
      '--nav-bg': rgba(bg, 0.92),
      '--disc-a': mix(bg, t.pastel, 0.12), '--disc-b': mix(bg, '#000000', 0.15), '--ring-off': mix(bg, t.pastel, 0.2),
      '--sheet': mix(bg, '#ffffff', 0.04), '--scrim': 'rgba(0, 0, 0, .5)',
      '--partner': t.partner, '--pastel': t.pastel,
      '--map-bg': mix(bg, '#000000', 0.2), '--map-block': mix(bg, t.pastel, 0.16),
      '--map-street': rgba(t.pastel, 0.16), '--route-core': mix(t.pastel, '#ffffff', 0.75),
    };
  }

  function glassVars(t, dark) {
    if (dark) {
      return {
        '--bg0': '#07070d', '--bg1': '#0e0d1a',
        '--text': '#f3f4ff', '--text2': '#aab0cc', '--text3': '#6f7594',
        '--accent': t.a, '--accent2': t.b, '--accent-light': mix(t.a, '#ffffff', 0.45),
        '--accent-soft': rgba(t.a, 0.12), '--accent-line': rgba(t.a, 0.5), '--glow': rgba(t.a, 0.55),
        '--card': 'rgba(255, 255, 255, .065)', '--card-solid': '#121224', '--card-border': 'rgba(255, 255, 255, .16)',
        '--card-shadow': '0 10px 36px rgba(0, 0, 0, .45), inset 0 1px 0 rgba(255, 255, 255, .16)',
        '--line': 'rgba(255, 255, 255, .11)', '--line-soft': 'rgba(255, 255, 255, .06)',
        '--field': 'rgba(255, 255, 255, .06)', '--field-border': 'rgba(255, 255, 255, .14)',
        '--sw-off': 'rgba(255, 255, 255, .10)', '--sw-border': 'rgba(255, 255, 255, .18)', '--sw-knob': '#e9ebff',
        '--ok': '#3dffa8', '--warn': '#ffc84d', '--err': '#ff5470', '--blue': t.b,
        '--nav-bg': 'rgba(14, 14, 28, .55)',
        '--disc-a': 'rgba(255, 255, 255, .13)', '--disc-b': 'rgba(255, 255, 255, .025)', '--ring-off': 'rgba(255, 255, 255, .20)',
        '--sheet': 'rgba(20, 20, 38, .82)', '--scrim': 'rgba(0, 0, 0, .5)',
        '--neon-a': t.a, '--neon-b': t.b,
        '--map-bg': '#08080f', '--map-block': '#151528',
        '--map-street': rgba(t.b, 0.16), '--route-core': '#ffffff',
      };
    }
    return {
      '--bg0': '#eef0f9', '--bg1': '#e3e6f5',
      '--text': '#13152b', '--text2': '#50567a', '--text3': '#8a90ae',
      '--accent': t.la, '--accent2': t.lb, '--accent-light': t.a,
      '--accent-soft': rgba(t.la, 0.10), '--accent-line': rgba(t.la, 0.40), '--glow': rgba(t.a, 0.45),
      '--card': 'rgba(255, 255, 255, .55)', '--card-solid': '#ffffff', '--card-border': 'rgba(255, 255, 255, .9)',
      '--card-shadow': '0 10px 30px rgba(40, 50, 100, .12), inset 0 1px 0 #ffffff',
      '--line': 'rgba(30, 40, 90, .11)', '--line-soft': 'rgba(30, 40, 90, .06)',
      '--field': 'rgba(255, 255, 255, .5)', '--field-border': 'rgba(30, 40, 90, .14)',
      '--sw-off': 'rgba(30, 40, 90, .10)', '--sw-border': 'rgba(30, 40, 90, .14)', '--sw-knob': '#ffffff',
      '--ok': '#0e9f6e', '--warn': '#d97706', '--err': '#e11d48', '--blue': t.lb,
      '--nav-bg': 'rgba(255, 255, 255, .55)',
      '--disc-a': 'rgba(255, 255, 255, .85)', '--disc-b': 'rgba(255, 255, 255, .35)', '--ring-off': 'rgba(30, 40, 90, .14)',
      '--sheet': 'rgba(255, 255, 255, .86)', '--scrim': 'rgba(20, 25, 60, .25)',
      '--neon-a': t.a, '--neon-b': t.b,
      '--map-bg': '#e8ebf7', '--map-block': '#d5daf0',
      '--map-street': 'rgba(255, 255, 255, .95)', '--route-core': '#ffffff',
    };
  }

  /** Все переменные, которые может поставить дизайн, — чтобы при смене их снять. */
  const ALL = Object.keys(Object.assign({}, softVars(SOFT[0], true), softVars(SOFT[0], false), glassVars(GLASS[0], true), glassVars(GLASS[0], false)));

  function apply(host, design, tone, dark) {
    ALL.forEach((k) => host.style.removeProperty(k));
    host.dataset.design = design;
    if (design === 'soft') {
      const vars = softVars(SOFT[tone % SOFT.length], dark);
      Object.keys(vars).forEach((k) => host.style.setProperty(k, vars[k]));
    } else if (design === 'glass') {
      const vars = glassVars(GLASS[tone % GLASS.length], dark);
      Object.keys(vars).forEach((k) => host.style.setProperty(k, vars[k]));
    }
  }

  window.Designs = { SOFT, GLASS, apply };
})();
