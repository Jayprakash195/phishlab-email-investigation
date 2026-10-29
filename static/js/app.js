(() => {
  'use strict';
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const maxUploadBytes = Number(document.documentElement.dataset.maxUploadBytes || 2097152);
  const state = { file: null, history: [], totalUrls: 0 };
  const titles = { overview: 'Overview', investigate: 'Email investigation', history: 'Analysis history', reports: 'Incident reports', tests: 'Test information', about: 'About project' };

  function toast(message) {
    const el = $('#toast');
    el.textContent = message;
    el.classList.add('show');
    window.setTimeout(() => el.classList.remove('show'), 2600);
  }
  function navigate(view) {
    if (!titles[view]) return;
    $$('.view').forEach(el => el.classList.toggle('active', el.id === `view-${view}`));
    $$('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === view));
    $('#current-section').textContent = titles[view];
    $('#sidebar').classList.remove('open');
    $('#mobile-menu').setAttribute('aria-expanded', 'false');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
  $$('.nav-item').forEach(button => button.addEventListener('click', () => navigate(button.dataset.view)));
  $$('[data-go]').forEach(button => button.addEventListener('click', () => navigate(button.dataset.go)));
  $('#mobile-menu').addEventListener('click', () => {
    const sidebar = $('#sidebar');
    const open = sidebar.classList.toggle('open');
    $('#mobile-menu').setAttribute('aria-expanded', String(open));
  });

  fetch('/health', { headers: { Accept: 'application/json' } })
    .then(response => { if (!response.ok) throw new Error('Backend unavailable'); return response.json(); })
    .then(data => {
      $('#parser-status').textContent = data.parser_available ? 'Ready' : 'Unavailable';
      $('#parser-status').style.color = data.parser_available ? 'var(--green)' : 'var(--red)';
      $('#parser-status-note').textContent = data.parser_available ? 'Python parser endpoint responding' : 'Parser could not be loaded';
    })
    .catch(() => {
      $('#parser-status').textContent = 'Offline';
      $('#parser-status').style.color = 'var(--red)';
      $('#parser-status-note').textContent = 'Start the Flask app to analyze files';
    });

  const input = $('#email-file');
  const dropzone = $('#dropzone');
  const selected = $('#selected-file');
  const analyzeButton = $('#analyze-button');
  const formError = $('#form-error');
  function setError(message) { formError.textContent = message; formError.hidden = !message; }
  function selectFile(file) {
    setError('');
    if (!file) { clearFile(); return; }
    if (!file.name.toLowerCase().endsWith('.eml')) { clearFile(); setError('Only .eml files are accepted.'); return; }
    if (file.size === 0) { clearFile(); setError('The selected file is empty.'); return; }
    if (file.size > maxUploadBytes) { clearFile(); setError(`File is too large. Maximum size is ${(maxUploadBytes / 1048576).toFixed(0)} MB.`); return; }
    state.file = file;
    $('#file-name').textContent = file.name;
    $('#file-size').textContent = `${(file.size / 1024).toFixed(1)} KB`;
    selected.hidden = false;
    dropzone.hidden = true;
    analyzeButton.disabled = false;
  }
  function clearFile() {
    state.file = null;
    input.value = '';
    selected.hidden = true;
    dropzone.hidden = false;
    analyzeButton.disabled = true;
  }
  input.addEventListener('change', () => selectFile(input.files[0]));
  $('#remove-file').addEventListener('click', clearFile);
  dropzone.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); input.click(); } });
  ['dragenter', 'dragover'].forEach(type => dropzone.addEventListener(type, event => { event.preventDefault(); dropzone.classList.add('dragover'); }));
  ['dragleave', 'drop'].forEach(type => dropzone.addEventListener(type, event => { event.preventDefault(); dropzone.classList.remove('dragover'); }));
  dropzone.addEventListener('drop', event => selectFile(event.dataTransfer.files[0]));

  function element(tag, className, text) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined) el.textContent = text;
    return el;
  }
  function section(title) {
    const el = element('section', 'result-section');
    el.append(element('h3', '', title));
    return el;
  }
  function addDetail(grid, label, value) {
    const item = element('div', 'detail-item');
    item.append(element('label', '', label), element('p', '', value || 'Not present in message'));
    grid.append(item);
  }
  function renderResult(result) {
    const root = $('#results-panel');
    root.replaceChildren();
    root.hidden = false;
    $('#results-placeholder').hidden = true;
    const card = element('article', 'result-card');
    const head = element('div', 'result-head');
    const titleBox = element('div');
    titleBox.append(element('h2', '', result.subject || '(No subject)'), element('p', '', result.filename));
    const verdict = element('span', `verdict${result.verdict === 'No obvious indicators found' ? ' safe' : ''}`, result.verdict);
    head.append(titleBox, verdict); card.append(head);

    const overview = section('Message overview');
    const grid = element('div', 'detail-grid');
    addDetail(grid, 'FROM', result.from); addDetail(grid, 'TO', result.to);
    addDetail(grid, 'REPLY-TO', result.reply_to); addDetail(grid, 'DATE', result.date);
    addDetail(grid, 'MESSAGE ID', result.message_id); addDetail(grid, 'SUBJECT', result.subject);
    overview.append(grid); card.append(overview);

    const headerSection = section('Extracted headers');
    const headerGrid = element('div', 'detail-grid');
    const entries = Object.entries(result.headers || {});
    if (entries.length) entries.forEach(([name, values]) => addDetail(headerGrid, name.toUpperCase(), Array.isArray(values) ? values.join('\n') : String(values)));
    else addDetail(headerGrid, 'HEADERS', 'No supported headers were found.');
    headerSection.append(headerGrid); card.append(headerSection);

    const indicatorsSection = section('Review indicators');
    if (result.indicators && result.indicators.length) {
      result.indicators.forEach(item => {
        const indicator = element('div', `indicator${item.level === 'info' ? ' info' : ''}`);
        indicator.append(element('span', 'level', item.level === 'info' ? 'INFORMATION' : 'REVIEW'), element('strong', '', item.title), element('p', '', item.detail));
        indicatorsSection.append(indicator);
      });
    } else {
      const item = element('div', 'indicator info');
      item.append(element('span', 'level', 'OBSERVATION'), element('strong', '', 'No obvious indicators were derived'), element('p', '', 'This does not prove the email is safe. Continue review using trusted sources and organizational procedures.'));
      indicatorsSection.append(item);
    }
    card.append(indicatorsSection);

    const urlsSection = section(`Extracted URLs (${(result.urls || []).length})`);
    if (result.urls && result.urls.length) {
      const list = element('div', 'url-list');
      result.urls.forEach(item => {
        const row = element('div', 'url-item');
        row.append(element('code', '', item.defanged), element('small', '', 'Defanged for display · Reputation not checked'));
        list.append(row);
      });
      urlsSection.append(list);
    } else {
      urlsSection.append(element('p', 'body-copy', 'No URLs were extracted from the text parts of this message.'));
    }
    card.append(urlsSection);

    const limitationsSection = section('Analysis limitations');
    const list = element('ul', 'limitations');
    (result.limitations || []).forEach(item => list.append(element('li', '', item)));
    limitationsSection.append(list); card.append(limitationsSection);
    root.append(card);
  }
  function updateHistory(result) {
    const item = { filename: result.filename, subject: result.subject, verdict: result.verdict, time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), urlCount: (result.urls || []).length, result };
    state.history.unshift(item);
    state.totalUrls += item.urlCount;
    $('#metric-analyses').textContent = String(state.history.length);
    $('#metric-urls').textContent = String(state.totalUrls);
    const recent = $('#recent-list');
    recent.replaceChildren();
    state.history.slice(0, 4).forEach(record => {
      const row = element('div', 'mini-list');
      const entry = element('div');
      entry.append(element('span', 'mini-check', '✓'));
      const text = element('span');
      text.append(element('strong', '', record.filename), element('small', '', `${record.subject} · ${record.verdict}`));
      entry.append(text); row.append(entry); recent.append(row);
    });
    renderHistoryTable();
  }
  function renderHistoryTable() {
    const tbody = $('#history-table'); tbody.replaceChildren();
    if (!state.history.length) { const tr = element('tr'); const td = element('td', 'table-empty', 'No analyses in this session.'); td.colSpan = 5; tr.append(td); tbody.append(tr); return; }
    state.history.forEach((record, index) => {
      const tr = element('tr');
      [record.filename, record.subject].forEach(value => tr.append(element('td', '', value)));
      const status = element('td'); status.append(element('span', 'status-label', record.verdict)); tr.append(status);
      tr.append(element('td', '', record.time));
      const actionCell = element('td'); const button = element('button', 'row-action', 'View'); button.type = 'button'; button.addEventListener('click', () => { renderResult(record.result); navigate('investigate'); }); actionCell.append(button); tr.append(actionCell);
      tbody.append(tr);
    });
  }
  $('#clear-history').addEventListener('click', () => {
    state.history = []; state.totalUrls = 0;
    $('#metric-analyses').textContent = '0'; $('#metric-urls').textContent = '0';
    $('#recent-list').className = 'empty-state'; $('#recent-list').replaceChildren(element('span', 'empty-icon', '⌕'), element('strong', '', 'No investigations yet'), element('p', '', 'Upload an .eml file to see the real parser results here.'));
    renderHistoryTable(); toast('Session history cleared.');
  });

  $('#upload-form').addEventListener('submit', async event => {
    event.preventDefault(); setError('');
    if (!state.file) { setError('Choose an .eml file first.'); return; }
    const label = $('.button-label', analyzeButton); const spinner = $('.button-spinner', analyzeButton);
    analyzeButton.disabled = true; label.textContent = 'Analyzing…'; spinner.hidden = false;
    try {
      const formData = new FormData(); formData.append('file', state.file, state.file.name);
      const response = await fetch('/api/analyze', { method: 'POST', body: formData, headers: { Accept: 'application/json' } });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.ok) throw new Error(payload.error || `Analysis failed (${response.status}).`);
      renderResult(payload.result); updateHistory(payload.result); toast('Email parsed successfully. Review the evidence before drawing a conclusion.');
    } catch (error) {
      setError(error.message || 'Could not connect to the local backend.');
    } finally {
      analyzeButton.disabled = !state.file; label.textContent = 'Analyze email'; spinner.hidden = true;
    }
  });

  $('#copy-tests').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText('py -m unittest discover -s tests -v'); toast('Test command copied.'); }
    catch { toast('Copy unavailable. Select the command and copy it manually.'); }
  });
})();
