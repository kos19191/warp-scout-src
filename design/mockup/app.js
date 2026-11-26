/* Макет: состояния, экраны, темы, шторки. Данные выдуманы, логика — только для показа. */
(function () {
  'use strict';
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const app = $('#app');

  const M = {
    theme: 'system', screen: 'simple', back: 'simple', state: 'on', progress: 0,
    connectedAt: Date.now() - 1021 * 1000, tab: 0, run: 0, act: '', dn: 118, up: 115,
  };

  const ringS = new Ring($('#orbS canvas'), app);
  const ringA = new Ring($('#orbA canvas'), app);
  const rings = [ringS, ringA];
  const map = new RouteMap($('#map'), app);

  // ───────── тема ─────────
  const mq = window.matchMedia('(prefers-color-scheme: dark)');
  const effTheme = () => (M.theme === 'system' ? (mq.matches ? 'dark' : 'light') : M.theme);
  function applyTheme() {
    app.dataset.theme = effTheme();
    rings.forEach((r) => r.readColors());
    map.readColors(); map.kick();
    drawBg();
    mark('#ctlTheme', M.theme);
    $$('#themeRadios .radio').forEach((r) => r.classList.toggle('on', r.dataset.v === M.theme));
  }
  if (mq.addEventListener) mq.addEventListener('change', () => { if (M.theme === 'system') applyTheme(); });

  function drawBg() {
    const simple = M.screen === 'simple';
    let orbY;
    if (simple) {
      const o = $('#orbS'), scr = $('#scrSimple');
      orbY = 30 + o.offsetTop + o.offsetHeight / 2 - scr.scrollTop;
    }
    drawBackground($('#bg'), app, simple ? 'simple' : 'calm', orbY);
  }

  function mark(sel, v) { $$(sel + ' button').forEach((b) => b.classList.toggle('on', b.dataset.v === v)); }

  // ───────── экраны ─────────
  function showScreen(s) {
    if (s === M.screen) return;
    if (s === 'route') M.back = M.screen;
    M.screen = s;
    $('#scrSimple').classList.toggle('hidden', s !== 'simple');
    $('#scrRoute').classList.toggle('hidden', s !== 'route');
    $('#scrAdv').classList.toggle('hidden', s !== 'adv');
    $('#sMode').classList.remove('on');
    $('#aMode').classList.add('on');
    mark('#ctlScreen', s);
    closeSheet();
    requestAnimationFrame(() => {
      drawBg();
      rings.forEach((r) => { r.resize(); r.kick(); });
      if (s === 'route') { map.resize(); map.mode = mapMode(); map.play(); }
    });
  }

  // ───────── состояние ─────────
  const TITLE = { off: 'Выключено', scan: 'Подбор точек…', connecting: 'Подключаю…', on: 'Подключено', error: 'Нет связи' };
  const EP = '188.114.97.6:890';

  function clockText() {
    const s = Math.max(0, Math.floor((Date.now() - M.connectedAt) / 1000));
    const p = (n) => String(n).padStart(2, '0');
    return p(Math.floor(s / 3600)) + ':' + p(Math.floor(s / 60) % 60) + ':' + p(s % 60);
  }
  function rateText(k) { return k < 1000 ? Math.round(k) + ' Кбит/с' : (k / 1000).toFixed(1).replace('.', ',') + ' Мбит/с'; }
  const mapMode = () => (M.state === 'on' || M.state === 'error' ? 'on' : M.state === 'connecting' ? 'connecting' : 'off');

  function setState(s, fresh) {
    const prev = M.state;
    M.state = s;
    if ((s === 'on' || s === 'error') && prev !== 'on' && prev !== 'error') M.connectedAt = fresh ? Date.now() : Date.now() - 1021 * 1000;
    if (s !== 'scan') M.progress = 0;
    if (s !== 'scan' && s !== 'connecting') M.act = '';
    rings.forEach((r) => r.setState(s));
    map.setMode(mapMode());
    mark('#ctlState', s);
    render();
  }

  function render() {
    const s = M.state;
    ['#orbS', '#orbA'].forEach((id) => {
      const o = $(id);
      o.dataset.state = s;
      $('.state', o).textContent = TITLE[s];
      const sub = $('.sub', o);
      let t = '';
      if (s === 'scan') t = Math.round(M.progress * 100) + ' %';
      else if (s === 'connecting') t = 'нажмите, чтобы отменить';
      else if (s === 'on' || s === 'error') t = clockText();
      sub.textContent = t;
      sub.classList.toggle('hint', s === 'connecting');
      sub.style.display = t ? '' : 'none';
      $('.rate', o).style.display = s === 'on' ? '' : 'none';
      $('.dn', o).textContent = rateText(M.dn);
      $('.up', o).textContent = rateText(M.up);
    });
    ['#sAct', '#aAct'].forEach((id) => { $(id).textContent = M.act; });
    // Карточка маршрута.
    let l1, l2;
    if (s === 'on') { l1 = 'мобильная · вход <b>' + EP + '</b>'; l2 = 'выход <b>Стокгольм</b> · второй выход <b>NL</b>'; }
    else if (s === 'error') { l1 = 'мобильная · вход <b>' + EP + '</b>'; l2 = 'выход <b>не отвечает</b>'; }
    else if (s === 'connecting') { l1 = 'подключаюсь к <b>' + EP + '</b>'; l2 = 'выход — после проверки связи'; }
    else if (s === 'scan') { l1 = 'мобильная · идёт подбор'; l2 = 'проверено <b>' + found(M.progress) + '</b> из 96 точек'; }
    else { l1 = 'мобильная · туннель выключен'; l2 = 'последняя точка <b>' + EP + '</b>'; }
    $$('.route-card').forEach((c) => { $('.l1', c).innerHTML = l1; $('.l2', c).innerHTML = l2; });
    // Плашки состояния.
    const pill = {
      on: ['', 'Подключено · ' + clockText().slice(0, 5)], error: ['err', 'Нет связи'], connecting: ['warn', 'Подключаю…'],
      scan: ['warn', 'Подбор ' + Math.round(M.progress * 100) + ' %'], off: ['off', 'Выключено'],
    }[s];
    ['#aPill', '#rPill'].forEach((id) => { $(id).innerHTML = '<span class="dot ' + pill[0] + '"></span>' + pill[1]; });
    $$('#rSteps .si').forEach((el, i) => el.classList.toggle('off', i >= 2 && s !== 'on' && s !== 'error'));
  }

  // ───────── сценарии ─────────
  const SCAN_ACTS = [
    [0, () => 'Готовлю подбор: ключи и список точек'],
    [0.07, (p) => 'Ищу точки: ' + found(p) + ' из 96'],
    [0.5, () => 'Проверяю ' + EP + ' · шум Q3'],
    [0.72, () => 'Проверяю, не встают ли данные: ' + EP],
    [0.9, () => 'Проверяю, открываются ли сайты'],
  ];
  /** Сколько точек проверено: первая половина подбора — поиск по всем 96, дальше — проверка лучших. */
  function found(p) { return Math.min(96, Math.round(p * 2 * 96)); }
  function scanAct(p) {
    let f = SCAN_ACTS[0][1];
    for (const [at, fn] of SCAN_ACTS) if (p >= at) f = fn;
    return f(p);
  }

  async function scanPhase(id, loop) {
    do {
      for (let i = 0; i <= 100; i++) {
        if (id !== M.run) return false;
        M.progress = i / 100;
        M.act = scanAct(M.progress);
        rings.forEach((r) => r.setProgress(M.progress));
        render();
        await sleep(i < 8 ? 120 : 70);
      }
      if (loop) { await sleep(600); if (id !== M.run) return false; rings.forEach((r) => r.setProgress(0)); }
    } while (loop);
    return true;
  }

  async function connectPhase(id) {
    setState('connecting');
    M.act = 'Подключаюсь к ' + EP; render();
    await sleep(1500); if (id !== M.run) return;
    M.act = 'Проверяю, идут ли данные через ' + EP; render();
    await sleep(1400); if (id !== M.run) return;
    setState('on', true);
  }

  async function scenario(withScan) {
    const id = ++M.run;
    if (withScan) {
      setState('scan');
      if (!(await scanPhase(id, false))) return;
    }
    await connectPhase(id);
  }

  function cancelRun() { M.run++; }

  function onOrb() {
    const s = M.state;
    if (s === 'off') scenario(false);
    else if (s === 'scan') { cancelRun(); setState('off'); toast('Подбор остановлен'); }
    else { cancelRun(); setState('off'); }
  }

  // ───────── скорость и часы ─────────
  setInterval(() => {
    const d = new Date();
    $('#clock').textContent = String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
    if (M.state === 'on') {
      M.dn = Math.max(30, Math.min(4800, M.dn * (0.7 + Math.random() * 0.62) + (Math.random() < 0.15 ? 600 : 0)));
      M.up = Math.max(20, Math.min(1800, M.up * (0.75 + Math.random() * 0.5)));
    }
    if (M.state === 'on' || M.state === 'error') render();
  }, 1000);

  // ───────── шторки ─────────
  const APPS = [
    ['ChatGPT', '#10a37f', 'G', 'second'], ['Claude', '#d97757', 'C', 'second'], ['Gemini', 'linear-gradient(135deg,#4285f4,#9b72cb)', 'G', 'second'],
    ['Grok', '#151515', 'X', 'second'], ['TikTok', '#000000', 'T', 'second'], ['Instagram', 'linear-gradient(135deg,#f58529,#dd2a7b,#8134af)', 'I', 'warp'],
    ['YouTube', '#ff0000', '▶', 'warp'], ['Chrome', '#1a73e8', 'C', 'warp'], ['Facebook', '#1877f2', 'f', 'warp'], ['X', '#151515', 'X', 'warp'],
    ['Telegram', '#2aabee', 'T', 'auto'], ['WhatsApp', '#25d366', 'W', 'auto'], ['Discord', '#5865f2', 'D', 'auto'],
  ];
  const EXIT = { auto: 'Само', warp: 'WARP', second: 'Второй выход' };
  const NEXT = { auto: 'warp', warp: 'second', second: 'auto' };
  function appRows(n) {
    return APPS.slice(0, n).map((a) =>
      '<div class="app-row"><span class="check on js-tick"></span><span class="app-ic" style="background:' + a[1] + '">' + a[2] +
      '</span><span class="an">' + a[0] + '</span><button class="exit ' + (a[3] === 'auto' ? '' : a[3]) + ' js-exit" data-e="' + a[3] + '">' +
      EXIT[a[3]] + '</button></div>').join('');
  }
  function fillAppsFold() {
    const box = $('#appsList');
    if (box.dataset.ok) return;
    box.dataset.ok = '1';
    box.innerHTML =
      '<div class="pad" style="padding-bottom:6px"><div class="field" style="display:flex;align-items:center;gap:10px"><svg class="ico" viewBox="0 0 24 24" width="20" height="20"><use href="#i-search"/></svg>Поиск приложения</div></div>' +
      '<div class="row js-check" style="padding-top:6px;padding-bottom:6px"><div class="rl"><div class="rt2">Показывать системные приложения</div></div><span class="check"></span></div>' +
      '<div class="pad muted" style="padding-top:2px;padding-bottom:8px;font-size:12.5px">Кнопка в строке — выход приложения: «Само», «WARP» или «Второй выход». Сам второй выход настраивается на вкладке «Обход».</div>' +
      appRows(APPS.length);
  }

  function openSheet(html) {
    const sh = $('#sheet');
    sh.innerHTML = '<div class="handle"></div>' + html;
    $('#scrim').classList.add('on');
    sh.classList.add('on');
    sh.scrollTop = 0;
  }
  function closeSheet() { $('#scrim').classList.remove('on'); $('#sheet').classList.remove('on'); }

  function tunnelSheet() {
    openSheet(
      '<h3>Туннелирование</h3><div class="sub3">Что идёт через туннель. Остальное — напрямую, как без VPN.</div>' +
      '<div class="opt on js-opt"><svg class="ico" viewBox="0 0 24 24"><use href="#i-apps"/></svg><div><div class="ot">Приложения</div><div class="os">выбрано 16 · свой выход у 5</div></div></div>' +
      '<div class="opt js-opt"><svg class="ico" viewBox="0 0 24 24"><use href="#i-globe"/></svg><div><div class="ot">Сайты</div><div class="os">свои домены и адреса</div></div></div>' +
      '<div class="opt js-opt"><svg class="ico" viewBox="0 0 24 24"><use href="#i-list"/></svg><div><div class="ot">Списки</div><div class="os">заблокированное, соцсети, ИИ-сервисы…</div></div></div>' +
      '<div class="sh" style="margin-top:18px">Приложения</div><div class="card">' + appRows(6) + '</div>' +
      '<button class="btn primary js-close" style="margin-top:14px">Готово</button>');
  }
  function backupSheet() {
    const pt = (ep, sub, on) => '<div class="opt js-opt' + (on ? ' on' : '') + '"><span class="radio' + (on ? ' on' : '') + '" style="padding:0"><i></i></span><div><div class="ot" style="font-family:Roboto Mono,ui-monospace,monospace;font-size:14px">' + ep + '</div><div class="os">' + sub + '</div></div></div>';
    openSheet(
      '<h3>Резервная точка</h3><div class="sub3">На неё туннель перейдёт первой, если текущая замолчит.</div>' +
      pt('8.39.214.2:988', '<span class="dot"></span>отвечает · 44 мс · проверено в 13:36', true) +
      pt('162.159.195.4:2408', '<span class="dot"></span>отвечает · 51 мс', false) +
      pt('188.114.96.11:4500', '<span class="dot off"></span>для Wi-Fi · 22 мс', false) +
      '<button class="btn primary js-close" style="margin-top:14px">Готово</button>');
  }

  let toastTimer = 0;
  function toast(text) {
    const t = $('#toast');
    t.textContent = text; t.classList.add('on');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('on'), 2300);
  }

  // ───────── нажатия ─────────
  $('#orbS').addEventListener('click', onOrb);
  $('#orbA').addEventListener('click', onOrb);
  $('#sRescan').addEventListener('click', () => scenario(true));
  $('#aScan').addEventListener('click', () => scenario(true));
  $('#sUpdate').addEventListener('click', () => toast('Обновлений нет — стоит последняя бета'));
  $('#sRoute').addEventListener('click', () => showScreen('route'));
  $('#aRoute').addEventListener('click', () => showScreen('route'));
  $('#rBack').addEventListener('click', () => showScreen(M.back === 'route' ? 'simple' : M.back));
  $('#rReplay').addEventListener('click', () => { if (M.state === 'on' || M.state === 'error') map.play(); else toast('Маршрут прорисуется после подключения'); });
  $('#sTunnel').addEventListener('click', tunnelSheet);
  $('#sBackup').addEventListener('click', backupSheet);
  $('#scrim').addEventListener('click', closeSheet);
  $('#sMode').addEventListener('click', (e) => { e.currentTarget.classList.add('on'); setTimeout(() => showScreen('adv'), 280); });
  $('#aMode').addEventListener('click', (e) => { e.currentTarget.classList.remove('on'); setTimeout(() => showScreen('simple'), 280); });
  $('#scrSimple').addEventListener('scroll', () => drawBg(), { passive: true });

  $$('#nav button').forEach((b) => b.addEventListener('click', () => {
    M.tab = +b.dataset.tab;
    $$('#nav button').forEach((x) => x.classList.toggle('on', x === b));
    $$('#advBody .tab').forEach((t) => t.classList.toggle('on', +t.dataset.tab === M.tab));
    $('#advBody').scrollTop = 0;
    if (M.tab === 0) requestAnimationFrame(() => { ringA.resize(); ringA.kick(); });
  }));

  // Общие элементы: гармошки, переключатели, отметки, сегменты, выходы приложений.
  app.addEventListener('click', (e) => {
    const t = e.target;
    const foldH = t.closest('.fold-h');
    if (foldH) {
      const f = foldH.parentElement;
      f.classList.toggle('open');
      if (f.id === 'foldApps') fillAppsFold();
      return;
    }
    const sw = t.closest('.js-sw');
    if (sw) { sw.classList.toggle('on'); return; }
    const exit = t.closest('.js-exit');
    if (exit) {
      const n = NEXT[exit.dataset.e];
      exit.dataset.e = n; exit.textContent = EXIT[n];
      exit.className = 'exit ' + (n === 'auto' ? '' : n) + ' js-exit';
      return;
    }
    const tick = t.closest('.js-tick');
    if (tick) { tick.classList.toggle('on'); return; }
    const chk = t.closest('.js-check');
    if (chk) { $('.check', chk).classList.toggle('on'); return; }
    const seg = t.closest('.js-seg button');
    if (seg) { $$('button', seg.parentElement).forEach((b) => b.classList.toggle('on', b === seg)); return; }
    const radio = t.closest('.js-radio');
    if (radio) { $$('.js-radio', radio.parentElement).forEach((r) => r.classList.toggle('on', r === radio)); return; }
    const opt = t.closest('.js-opt');
    if (opt) {
      $$('.js-opt', opt.parentElement).forEach((o) => {
        o.classList.toggle('on', o === opt);
        const r = $('.radio', o); if (r) r.classList.toggle('on', o === opt);
      });
      return;
    }
    if (t.closest('.js-close')) { closeSheet(); return; }
    const th = t.closest('#themeRadios .radio');
    if (th) { M.theme = th.dataset.v; applyTheme(); }
  });

  // ───────── панель макета ─────────
  $$('#ctlTheme button').forEach((b) => b.addEventListener('click', () => { M.theme = b.dataset.v; applyTheme(); }));
  $$('#ctlScreen button').forEach((b) => b.addEventListener('click', () => showScreen(b.dataset.v)));
  $$('#ctlState button').forEach((b) => b.addEventListener('click', () => {
    cancelRun();
    const v = b.dataset.v;
    if (v === 'scan') { const id = ++M.run; setState('scan'); scanPhase(id, true); }
    else if (v === 'connecting') { const id = ++M.run; connectPhase(id); }
    else setState(v);
  }));
  $('#ctlPlay').addEventListener('click', async () => {
    cancelRun(); setState('off');
    if (M.screen === 'route') showScreen('simple');
    await sleep(700);
    scenario(true);
  });
  $('#fab').addEventListener('click', () => $('#panel').classList.toggle('open'));

  // ───────── размер телефона ─────────
  function fit() {
    const stage = $('#stage'), sc = $('#phoneScale');
    if (window.innerWidth <= 760) { sc.style.transform = ''; window.__phoneScaleUp = 1; }
    else {
      const s = Math.min((stage.clientHeight - 28) / 936, (stage.clientWidth - 28) / 456, 1.3);
      sc.style.transform = 'scale(' + s.toFixed(4) + ')';
      window.__phoneScaleUp = Math.max(1, s);
    }
    rings.forEach((r) => r.resize());
    map.resize();
    drawBg();
  }
  window.addEventListener('resize', fit);

  // ───────── старт ─────────
  applyTheme();
  mark('#ctlScreen', 'simple');
  setState('on');
  fit();
  setTimeout(fit, 300);
})();
