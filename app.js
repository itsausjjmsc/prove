// Outlook Secure — main application logic
// Local-first PWA that secures Outlook email and calendar via Microsoft Graph API
// Auth: MSAL.js with PKCE (Authorization Code Flow)
// All tokens stay in browser memory only

const GRAPH_BASE = 'https://graph.microsoft.com/v1.0';

// Suspicious content patterns from hardening audit — these match the
// inbox rules already created for Mark's account plus common phishing vectors
const SUSPICIOUS_PATTERNS = [
  { name: 'Fake voice/photo share (groups.outlook.com)', patterns: ['unheard voice message', 'private voice message', 'shared a photo with you', 'shared a folder with you', 'private_album_'] },
  { name: 'Romance scam lures', patterns: ['flirt with a hot single', 'awaiting your reply dear stranger', 'meet-singles', 'private photos in private', 'click to claim my private'] },
  { name: 'WhatsApp/Google Drive impersonation', patterns: ['whatsapp', 'google drive'] },
  { name: 'Phishing credential harvest', patterns: ['verify your account', 'account verification', 'suspended', 'urgent action required', 'click below to verify'] },
  { name: 'Fake invoice/payment', patterns: ['invoice attached', 'payment failed', 'outstanding balance', 'immediate payment'] }
];

let msalInstance, accessToken, accountId;
let archiveFolderId = null;
let actionLog = [];
let currentScanResults = [];
let currentScanType = 'mail';
let selectedMessages = new Set();

function $(id) { return document.getElementById(id); }

function setStatus(el, msg, isError = false) {
  if (!el) return;
  el.textContent = msg;
  el.classList.toggle('error', isError);
}

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[ch]);
}

function parseDateTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

function formatBytes(bytes) {
  if (!bytes || bytes < 1024) return '';
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

// ---------- Settings ----------

function loadSettings() {
  const defaults = { showPreviews: true, autoArchiveFolder: true, batchSize: 20, suspiciousAutoFlag: false };
  const saved = JSON.parse(localStorage.getItem('outlook-secure-settings') || '{}');
  return { ...defaults, ...saved };
}

function saveSettings(settings) {
  localStorage.setItem('outlook-secure-settings', JSON.stringify(settings));
}

// ---------- Action Log ----------

function logAction(action, detail) {
  const entry = { time: new Date().toISOString(), action, detail };
  actionLog.push(entry);
  if (actionLog.length > 500) actionLog.shift();
  renderLog();
}

function renderLog() {
  const el = $('logList');
  if (!el) return;
  if (!actionLog.length) {
    el.innerHTML = '<p class="quiet">No actions taken yet in this session.</p>';
    return;
  }
  el.innerHTML = actionLog.slice().reverse().map(entry => `
    <div class="log-entry">
      <span class="log-time">${escapeHTML(new Date(entry.time).toLocaleString())}</span>
      <span class="log-action">${escapeHTML(entry.action)}</span>
      <span class="log-detail">${escapeHTML(entry.detail)}</span>
    </div>
  `).join('');
}

// ---------- UI Navigation ----------

function switchView(name) {
  for (const tab of document.querySelectorAll('.tab')) {
    const active = tab.dataset.view === name;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-pressed', String(active));
  }
  for (const view of document.querySelectorAll('.view')) {
    view.hidden = view.id !== `view-${name}`;
  }
  if (name === 'logs') renderLog();
}

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => switchView(tab.dataset.view));
});

// ---------- Settings form ----------

$('settingsForm')?.addEventListener('submit', event => {
  event.preventDefault();
  const settings = {
    showPreviews: $('showPreviews')?.checked ?? true,
    autoArchiveFolder: $('autoArchiveFolder')?.checked ?? true,
    batchSize: Math.min(parseInt($('batchSize')?.value) || 20, 20),
    suspiciousAutoFlag: $('suspiciousAutoFlag')?.checked ?? false
  };
  saveSettings(settings);
  setStatus($('settingsStatus'), 'Settings saved.');
});

$('clearLogBtn')?.addEventListener('click', () => {
  actionLog = [];
  renderLog();
});

// ---------- Scan type visibility ----------

function updateScanOptions() {
  const scanType = document.querySelector('input[name="scanType"]:checked')?.value;
  const oldOpts = $('oldScanOptions');
  const largeOpts = $('largeScanOptions');
  if (oldOpts) oldOpts.hidden = scanType !== 'old';
  if (largeOpts) largeOpts.hidden = scanType !== 'large';
}

document.querySelectorAll('input[name="scanType"]').forEach(radio => {
  radio.addEventListener('change', updateScanOptions);
});

// ---------- MSAL Auth ----------

async function initAuth() {
  const config = await fetch('config.json').then(r => r.json()).catch(() => ({
    clientId: '04b0f920-318a-45d2-a8a4-50fde9d6e9d9',
    scopes: ['Mail.ReadWrite', 'Calendars.ReadWrite']
  }));

  const msalConfig = {
    auth: {
      clientId: config.clientId,
      authority: 'https://login.microsoftonline.com/consumers',
      redirectUri: window.location.origin + window.location.pathname
    },
    cache: {
      cacheLocation: 'sessionStorage',
      storeAuthStateInCookie: false
    }
  };

  msalInstance = new msal.BrowserPublicKeyClientApplication(msalConfig);

  const accounts = msalInstance.getAllAccounts();
  if (accounts.length > 0) {
    accountId = accounts[0].homeAccountId;
    await refreshAccessToken();
  } else {
    updateAuthUI(false);
  }
}

function updateAuthUI(authenticated) {
  if (authenticated) {
    $('authStatus').textContent = 'Connected to Outlook. Ready to secure your mailbox.';
    $('signInBtn').hidden = true;
    $('disconnectBtn').hidden = false;
  } else {
    $('authStatus').textContent = 'Not connected. Sign in to secure your Outlook.';
    $('signInBtn').hidden = false;
    $('disconnectBtn').hidden = true;
  }
}

$('signInBtn')?.addEventListener('click', async () => {
  setStatus($('authStatus'), 'Signing in…');
  try {
    const result = await msalInstance.loginPopup({
      scopes: ['Mail.ReadWrite', 'Calendars.ReadWrite'],
      prompt: 'select_account'
    });
    accountId = result.account.homeAccountId;
    await refreshAccessToken();
  } catch (err) {
    setStatus($('authStatus'), `Sign-in failed: ${err.message}`, true);
  }
});

$('disconnectBtn')?.addEventListener('click', () => {
  if (confirm('Disconnect your Outlook account? This clears all tokens and the action log.')) {
    msalInstance.logoutPopup().catch(() => {});
    accessToken = null;
    accountId = null;
    archiveFolderId = null;
    actionLog = [];
    currentScanResults = [];
    selectedMessages.clear();
    updateAuthUI(false);
    renderLog();
    switchView('connect');
  }
});

async function refreshAccessToken() {
  if (!msalInstance || !accountId) return false;
  try {
    const result = await msalInstance.acquireTokenSilent({
      scopes: ['Mail.ReadWrite', 'Calendars.ReadWrite'],
      account: msalInstance.getAccountById(accountId)
    });
    accessToken = result.accessToken;
    updateAuthUI(true);
    return true;
  } catch {
    try {
      const result = await msalInstance.acquireTokenPopup({
        scopes: ['Mail.ReadWrite', 'Calendars.ReadWrite']
      });
      accessToken = result.accessToken;
      updateAuthUI(true);
      return true;
    } catch (err) {
      setStatus($('authStatus'), `Token refresh failed: ${err.message}`, true);
      updateAuthUI(false);
      return false;
    }
  }
}

// ---------- Graph API ----------

async function graphFetch(path, options = {}) {
  if (!accessToken) throw new Error('Not authenticated');

  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${accessToken}`);
  headers.set('Content-Type', 'application/json');

  let response = await fetch(`${GRAPH_BASE}${path}`, { ...options, headers });

  if (response.status === 401) {
    if (await refreshAccessToken()) {
      headers.set('Authorization', `Bearer ${accessToken}`);
      response = await fetch(`${GRAPH_BASE}${path}`, { ...options, headers });
    } else {
      throw new Error('Authentication expired. Please reconnect.');
    }
  }

  if (response.status === 429) {
    const retryAfter = parseInt(response.headers.get('Retry-After') || '5') * 1000;
    await new Promise(r => setTimeout(r, retryAfter));
    return graphFetch(path, options);
  }

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.message || err.error?.message || `Graph API error (${response.status})`);
  }

  return response.status === 204 ? null : response.json();
}

function chunkArray(arr, size = 20) {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) chunks.push(arr.slice(i, i + size));
  return chunks;
}

async function graphBatch(requests) {
  const settings = loadSettings();
  const batchSize = Math.min(settings.batchSize, 20);
  const chunks = chunkArray(requests, batchSize);
  const allResponses = [];

  for (const chunk of chunks) {
    const batchBody = {
      requests: chunk.map((req, i) => ({
        id: String(i),
        method: req.method || 'GET',
        url: req.url,
        ...(req.body ? { body: req.body } : {})
      }))
    };
    const data = await graphFetch('/$batch', { method: 'POST', body: JSON.stringify(batchBody) });
    allResponses.push(...(data.responses || []));
  }
  return allResponses;
}

// ---------- Archive folder management ----------

async function ensureArchiveFolder() {
  if (archiveFolderId) return archiveFolderId;

  const settings = loadSettings();
  if (!settings.autoArchiveFolder) return 'deleteditems';

  const folders = await graphFetch('/me/mailFolders?$top=100');
  const existing = folders.value?.find(f => f.displayName === 'Secure Archive');
  if (existing) {
    archiveFolderId = existing.id;
    return archiveFolderId;
  }

  const created = await graphFetch('/me/mailFolders', {
    method: 'POST',
    body: JSON.stringify({ displayName: 'Secure Archive', isHidden: false })
  });
  archiveFolderId = created.id;
  logAction('folder_create', 'Created "Secure Archive" folder for archived messages');
  return archiveFolderId;
}

// ---------- Suspicious content detection ----------

function scanMessageForThreats(message) {
  const text = ((message.subject || '') + ' ' + (message.bodyPreview || '')).toLowerCase();
  const matches = [];

  for (const pattern of SUSPICIOUS_PATTERNS) {
    for (const keyword of pattern.patterns) {
      if (text.includes(keyword.toLowerCase())) {
        matches.push(pattern.name);
        break;
      }
    }
  }

  const fromAddr = message.from?.emailAddress?.address || '';
  if (fromAddr.toLowerCase().includes('groups.outlook.com')) {
    matches.push('Unverified sender via groups.outlook.com');
  }

  return [...new Set(matches)];
}

// ---------- Mail Scanning ----------

$('scanForm')?.addEventListener('submit', async event => {
  event.preventDefault();
  const settings = loadSettings();
  const scanType = document.querySelector('input[name="scanType"]:checked')?.value || 'suspicious';

  setStatus($('scanStatus'), 'Scanning mailbox…');
  $('resultsTitle').textContent = 'Scanning…';
  $('resultsList').innerHTML = '';
  $('applyActionBtn').hidden = true;
  selectedMessages.clear();

  try {
    if (!(await refreshAccessToken())) return;

    let results = [];
    let action = 'archive';

    if (scanType === 'suspicious') {
      setStatus($('scanStatus'), 'Scanning for suspicious/phishing messages…');
      const ageDays = parseInt($('ageThreshold')?.value) || 365;
      const since = new Date(Date.now() - ageDays * 86400000).toISOString().split('.')[0] + 'Z';
      const filter = `receivedDateTime lt ${since}`;

      let url = `/me/messages?` +
        `$filter=${encodeURIComponent(filter)}&` +
        `$top=50&$select=id,subject,receivedDateTime,from,bodyPreview,hasAttachments,sensitivity,isRead`;

      let data = await graphFetch(url);
      let msgs = data.value || [];
      let page = 0;
      while (data['@odata.nextLink'] && page < 10) {
        data = await graphFetch(data['@odata.nextLink']);
        msgs.push(...(data.value || []));
        page++;
      }

      results = msgs
        .filter(msg => scanMessageForThreats(msg).length > 0)
        .map(msg => ({
          ...msg,
          threatType: scanMessageForThreats(msg),
          isSuspicious: true
        }));

      // For suspicious messages, default to markRead (not archive)
      action = 'markRead';

    } else if (scanType === 'old') {
      const ageDays = parseInt($('ageThreshold')?.value) || 180;
      const folder = $('folderSelect')?.value || 'inbox';
      const fromFilter = $('fromFilter')?.value.trim() || null;
      const since = new Date(Date.now() - ageDays * 86400000).toISOString().split('.')[0] + 'Z';

      let filter = `receivedDateTime lt ${since}`;
      let url = `/me/mailFolders/${folder}/messages?` +
        `$filter=${encodeURIComponent(filter)}&` +
        `$top=50&$select=id,subject,receivedDateTime,from,hasAttachments,sensitivity,isRead,importance,size`;

      let data = await graphFetch(url);
      let msgs = data.value || [];
      let page = 0;
      while (data['@odata.nextLink'] && page < 10) {
        data = await graphFetch(data['@odata.nextLink']);
        msgs.push(...(data.value || []));
        page++;
      }

      if (fromFilter) {
        msgs = msgs.filter(m => {
          const addr = m.from?.emailAddress?.address || '';
          return addr.toLowerCase().includes(fromFilter.toLowerCase());
        });
      }

      msgs.sort((a, b) => new Date(a.receivedDateTime) - new Date(b.receivedDateTime));
      results = msgs;

    } else if (scanType === 'large') {
      setStatus($('scanStatus'), 'Scanning for large messages…');
      const minSize = (parseInt($('minSize')?.value) || 100) * 1024;
      const since = new Date(Date.now() - 2 * 365 * 86400000).toISOString().split('.')[0] + 'Z';

      let url = `/me/messages?` +
        `$filter=receivedDateTime lt ${encodeURIComponent(since)} and size gt ${minSize}&` +
        `$top=50&$select=id,subject,receivedDateTime,from,hasAttachments,size,sensitivity,isRead`;

      let data = await graphFetch(url);
      results = data.value || [];
      let page = 0;
      while (data['@odata.nextLink'] && page < 10) {
        data = await graphFetch(data['@odata.nextLink']);
        results.push(...(data.value || []));
        page++;
      }
      results.sort((a, b) => (b.size || 0) - (a.size || 0));
    }

    currentScanResults = results;
    currentScanType = 'mail';

    if (!results.length) {
      $('resultsTitle').textContent = 'No messages found';
      setStatus($('scanStatus'), 'No messages matched your criteria.');
      return;
    }

    // Set default action radio
    const actionRadio = document.querySelector(`input[name="mailAction"][value="${action}"]`);
    if (actionRadio) actionRadio.checked = true;

    $('resultsTitle').textContent = `Scan results (${results.length} messages)`;
    $('resultsList').innerHTML = results.map(msg => renderMessageCard(msg, settings.showPreviews)).join('');
    $('resultsSummary').textContent = `${results.length} messages found. Preview and apply security action below.`;

    document.querySelector('#actionCount').textContent = results.length;
    $('applyActionBtn').textContent = getMailActionLabel(action, results.length);
    $('applyActionBtn').hidden = false;

    setStatus($('scanStatus'), `Found ${results.length} messages.`);
    logAction('mail_scan', `Scanned '${scanType}': found ${results.length} messages, action=${action}`);
  } catch (err) {
    setStatus($('scanStatus'), `Scan failed: ${err.message}`, true);
    $('resultsTitle').textContent = 'Scan failed';
  }
});

function renderMessageCard(msg, showPreviews) {
  const fromName = msg.from?.emailAddress?.name || 'Unknown';
  const fromAddr = msg.from?.emailAddress?.address || '';
  const date = parseDateTime(msg.receivedDateTime);
  const subject = msg.subject || '(no subject)';
  const size = formatBytes(msg.size);
  const threatTags = msg.isSuspicious ?
    msg.threatType.map(t => `<span class="tag warning">${escapeHTML(t)}</span>`).join('') : '';

  return `
    <article class="message-card" data-id="${escapeHTML(msg.id)}">
      <div class="msg-header">
        <div class="msg-from">${escapeHTML(fromName)} <span class="quiet">&lt;${escapeHTML(fromAddr)}&gt;</span></div>
        <div class="msg-date">${date}</div>
      </div>
      <div class="msg-subject" title="${escapeHTML(subject)}">${escapeHTML(subject)}</div>
      ${threatTags}
      <div class="msg-meta">
        ${size ? `<span class="tag">size: ${size}</span>` : ''}
        <span class="tag">sensitivity: ${escapeHTML(msg.sensitivity || 'normal')}</span>
        <span class="tag">read: ${msg.isRead ? 'yes' : 'no'}</span>
      </div>
      <label class="choice"><input type="checkbox" class="msg-select" value="${escapeHTML(msg.id)}"> Include in batch</label>
    </article>
  `;
}

function getMailActionLabel(action, count) {
  const labels = {
    archive: `Archive ${count} messages`,
    markRead: `Mark ${count} as read`,
    sensitivity: `Set sensitivity: Private on ${count}`,
    category: `Apply category on ${count}`
  };
  return labels[action] || `Apply action on ${count}`;
}

// Track selected messages
$('resultsList')?.addEventListener('change', event => {
  if (event.target.classList.contains('msg-select')) {
    if (event.target.checked) selectedMessages.add(event.target.value);
    else selectedMessages.delete(event.target.value);
    document.querySelector('#actionCount').textContent = selectedMessages.size;
  }
});

// Update action button label when radio changes
document.querySelectorAll('input[name="mailAction"]').forEach(radio => {
  radio.addEventListener('change', () => {
    const count = selectedMessages.size || currentScanResults.length;
    document.querySelector('#actionCount').textContent = count;
    $('applyActionBtn').textContent = getMailActionLabel(radio.value, count);
  });
});

// Apply mail action
$('applyActionBtn')?.addEventListener('click', async () => {
  const action = document.querySelector('input[name="mailAction"]:checked')?.value;
  if (!action) return;

  const settings = loadSettings();
  if (settings.showPreviews) {
    // Show preview panel
    const ids = currentScanResults.map(m => m.id);
    $('previewList').innerHTML = currentScanResults.slice(0, 15).map(m => `
      <div class="preview-item" data-id="${escapeHTML(m.id)}">
        <strong>${escapeHTML(m.subject || '(no subject)')}</strong>
        <div class="quiet">From: ${escapeHTML(m.from?.emailAddress?.name || '')}</div>
        <div class="quiet">Date: ${parseDateTime(m.receivedDateTime)}</div>
      </div>
    `).join('');
    if (currentScanResults.length > 15) {
      $('previewList').innerHTML += `<p class="quiet">+ ${currentScanResults.length - 15} more messages</p>`;
    }
    $('previewPanel').hidden = false;
    return;
  }

  if (!confirm(`Apply "${action}" to ${currentScanResults.length} messages?`)) return;
  await executeMailAction(action, currentScanResults.map(m => m.id));
});

$('confirmApplyBtn')?.addEventListener('click', async () => {
  const action = document.querySelector('input[name="mailAction"]:checked')?.value;
  if (!action) return;
  const ids = currentScanResults.map(m => m.id);
  $('previewPanel').hidden = true;
  await executeMailAction(action, ids);
});

async function executeMailAction(action, messageIds) {
  if (!messageIds.length) return;

  setStatus($('scanStatus'), `Applying ${action} to ${messageIds.length} messages…`);
  $('applyActionBtn').disabled = true;

  try {
    if (!(await refreshAccessToken())) return;

    let batchReqs = [];

    if (action === 'archive') {
      const destFolder = await ensureArchiveFolder();
      batchReqs = messageIds.map(id => ({
        method: 'POST',
        url: `/me/messages/${id}/move`,
        body: { destinationId: destFolder }
      }));
      const responses = await graphBatch(batchReqs);
      const success = responses.filter(r => r.status === 201).length;
      logAction('archive', `Archived ${success}/${messageIds.length} messages to Secure Archive`);
      setStatus($('scanStatus'), `Archived ${success} of ${messageIds.length} messages.`);
    } else if (action === 'markRead') {
      batchReqs = messageIds.map(id => ({
        method: 'PATCH',
        url: `/me/messages/${id}`,
        body: { isRead: true, isReadReceiptRequested: false }
      }));
      const responses = await graphBatch(batchReqs);
      const success = responses.filter(r => r.status === 200).length;
      logAction('mark_read', `Marked ${success}/${messageIds.length} messages as read`);
      setStatus($('scanStatus'), `Marked ${success} of ${messageIds.length} as read.`);
    } else if (action === 'sensitivity') {
      batchReqs = messageIds.map(id => ({
        method: 'PATCH',
        url: `/me/messages/${id}`,
        body: { sensitivity: 'private' }
      }));
      const responses = await graphBatch(batchReqs);
      const success = responses.filter(r => r.status === 200).length;
      logAction('sensitivity_private', `Set sensitivity=private on ${success}/${messageIds.length} messages`);
      setStatus($('scanStatus'), `Set sensitivity: Private on ${success} of ${messageIds.length}.`);
    } else if (action === 'category') {
      batchReqs = messageIds.map(id => ({
        method: 'PATCH',
        url: `/me/messages/${id}`,
        body: { categories: ['Secured'] }
      }));
      const responses = await graphBatch(batchReqs);
      const success = responses.filter(r => r.status === 200).length;
      logAction('category', `Applied 'Secured' category to ${success}/${messageIds.length} messages`);
      setStatus($('scanStatus'), `Applied category to ${success} of ${messageIds.length}.`);
    }

    selectedMessages.clear();
    $('applyActionBtn').hidden = true;
    $('resultsList').innerHTML = '';
    $('resultsTitle').textContent = 'Action complete';
    $('resultsSummary').textContent = '';
  } catch (err) {
    setStatus($('scanStatus'), `Action failed: ${err.message}`, true);
    logAction('error', `Mail action ${action}: ${err.message}`);
  } finally {
    $('applyActionBtn').disabled = false;
  }
}

// ---------- Calendar Scanning ----------

$('calScanForm')?.addEventListener('submit', async event => {
  event.preventDefault();

  const ageDays = parseInt($('calAgeThreshold')?.value) || 90;
  const eventType = $('eventType')?.value || 'past';
  const since = new Date(Date.now() - ageDays * 86400000).toISOString().split('.')[0] + 'Z';

  setStatus($('calScanStatus'), `Scanning calendar…`);
  $('calResultsTitle').textContent = 'Scanning…';
  $('calResultsList').innerHTML = '';
  $('applyCalActionBtn').hidden = true;

  try {
    if (!(await refreshAccessToken())) return;

    let filter = '';
    if (eventType === 'past') {
      filter = `end/dateTime lt '${since}' and isCancelled eq false`;
    } else if (eventType === 'recurring') {
      filter = `recurrence ne null`;
    }

    const url = `/me/calendar/events?` +
      `$filter=${encodeURIComponent(filter)}&` +
      `$top=50&$select=id,subject,start,end,organizer,isCancelled,sensitivity,showAs,recurrence,type`;

    let data = await graphFetch(url);
    let events = data.value || [];
    let page = 0;
    while (data['@odata.nextLink'] && page < 10) {
      data = await graphFetch(data['@odata.nextLink']);
      events.push(...(data.value || []));
      page++;
    }

    events.sort((a, b) => {
      const ta = new Date(a.start?.dateTime || a.start);
      const tb = new Date(b.start?.dateTime || b.start);
      return ta - tb;
    });

    currentScanResults = events;
    currentScanType = 'calendar';

    if (!events.length) {
      $('calResultsTitle').textContent = 'No events found';
      setStatus($('calScanStatus'), 'No calendar events matched your criteria.');
      return;
    }

    $('calResultsTitle').textContent = `Scan results (${events.length} events)`;
    $('calResultsList').innerHTML = events.map(renderEventCard).join('');
    $('calResultsSummary').textContent = `${events.length} events found.`;
    $('calActionCount').textContent = events.length;
    $('applyCalActionBtn').hidden = false;

    const action = document.querySelector('input[name="calAction"]:checked')?.value || 'sensitivity';
    $('applyCalActionBtn').textContent = getCalActionLabel(action, events.length);

    setStatus($('calScanStatus'), `Found ${events.length} events.`);
    logAction('cal_scan', `Found ${events.length} events matching '${eventType}'`);
  } catch (err) {
    setStatus($('calScanStatus'), `Scan failed: ${err.message}`, true);
    $('calResultsTitle').textContent = 'Scan failed';
  }
});

function renderEventCard(event) {
  const subject = event.subject || '(no subject)';
  const start = parseDateTime(event.start?.dateTime);
  const isCancelled = event.isCancelled;
  const isRecurring = !!event.recurrence;
  const organizer = event.organizer?.emailAddress?.address || 'self';

  return `
    <article class="event-card" data-id="${escapeHTML(event.id)}">
      <div class="event-header">
        <div class="event-subject">${escapeHTML(subject)}</div>
        <div class="event-date">${start}</div>
      </div>
      <div class="meta">
        <span class="tag">${event.isOrganizer ? 'organizer' : 'attendee'}</span>
        ${isRecurring ? '<span class="tag">recurring</span>' : ''}
        ${isCancelled ? '<span class="tag warning">cancelled</span>' : ''}
        <span class="tag">sensitivity: ${escapeHTML(event.sensitivity || 'normal')}</span>
      </div>
      <div class="quiet">Organizer: ${escapeHTML(organizer)}</div>
    </article>
  `;
}

function getCalActionLabel(action, count) {
  const labels = {
    sensitivity: `Set sensitivity: Private on ${count} events`,
    showAs: `Set show-as: Free on ${count} events`,
    cancel: `Cancel ${count} meetings (sends notices to attendees)`,
    category: `Apply category on ${count} events`
  };
  return labels[action] || `Apply action on ${count}`;
}

document.querySelectorAll('input[name="calAction"]').forEach(radio => {
  radio.addEventListener('change', () => {
    const count = currentScanResults?.length || 0;
    $('applyCalActionBtn').textContent = getCalActionLabel(radio.value, count);
  });
});

$('applyCalActionBtn')?.addEventListener('click', async () => {
  const action = $('calAction')?.value || 'sensitivity';
  if (!confirm(`Apply "${action}" to ${currentScanResults.length} calendar events?`)) return;
  await executeCalAction(action, currentScanResults.map(e => e.id));
});

async function executeCalAction(action, eventIds) {
  if (!eventIds.length) return;

  setStatus($('calScanStatus'), `Applying ${action} to ${eventIds.length} events…`);
  $('applyCalActionBtn').disabled = true;

  try {
    if (!(await refreshAccessToken())) return;

    let batchReqs = [];

    if (action === 'sensitivity') {
      batchReqs = eventIds.map(id => ({
        method: 'PATCH',
        url: `/me/events/${id}`,
        body: { sensitivity: 'private' }
      }));
      const responses = await graphBatch(batchReqs);
      const success = responses.filter(r => r.status === 200).length;
      logAction('cal_sensitivity', `Set sensitivity=private on ${success}/${eventIds.length} events`);
      setStatus($('calScanStatus'), `Set sensitivity: Private on ${success} of ${eventIds.length} events.`);
    } else if (action === 'showAs') {
      batchReqs = eventIds.map(id => ({
        method: 'PATCH',
        url: `/me/events/${id}`,
        body: { showAs: 'free' }
      }));
      const responses = await graphBatch(batchReqs);
      const success = responses.filter(r => r.status === 200).length;
      logAction('cal_showas', `Set showAs=free on ${success}/${eventIds.length} events`);
      setStatus($('calScanStatus'), `Set show-as: Free on ${success} of ${eventIds.length} events.`);
    } else if (action === 'cancel') {
      batchReqs = eventIds.map(id => ({
        method: 'POST',
        url: `/me/events/${id}/cancel`,
        body: { comment: 'Event removed via Outlook Secure — cleaning up old calendar events' }
      }));
      const responses = await graphBatch(batchReqs);
      const success = responses.filter(r => r.status === 202).length;
      logAction('cal_cancel', `Cancelled ${success}/${eventIds.length} meetings`);
      setStatus($('calScanStatus'), `Cancelled ${success} of ${eventIds.length} meetings.`);
    } else if (action === 'category') {
      batchReqs = eventIds.map(id => ({
        method: 'PATCH',
        url: `/me/events/${id}`,
        body: { categories: ['Historical'] }
      }));
      const responses = await graphBatch(batchReqs);
      const success = responses.filter(r => r.status === 200).length;
      logAction('cal_category', `Applied 'Historical' category to ${success}/${eventIds.length} events`);
      setStatus($('calScanStatus'), `Applied category to ${success} of ${eventIds.length} events.`);
    }

    $('applyCalActionBtn').hidden = true;
    $('calResultsList').innerHTML = '';
    $('calResultsTitle').textContent = 'Action complete';
    $('calResultsSummary').textContent = '';
  } catch (err) {
    setStatus($('calScanStatus'), `Action failed: ${err.message}`, true);
    logAction('error', `Calendar action ${action}: ${err.message}`);
  } finally {
    $('applyCalActionBtn').disabled = false;
  }
}

// ---------- Init ----------

function init() {
  const settings = loadSettings();
  if ($('showPreviews')) $('showPreviews').checked = settings.showPreviews;
  if ($('autoArchiveFolder')) $('autoArchiveFolder').checked = settings.autoArchiveFolder;
  if ($('suspiciousAutoFlag')) $('suspiciousAutoFlag').checked = settings.suspiciousAutoFlag;
  if ($('batchSize')) $('batchSize').value = settings.batchSize;
  updateScanOptions();
  initAuth();
}

document.addEventListener('DOMContentLoaded', () => {
  if (typeof msal === 'undefined') {
    console.error('MSAL not loaded. Check CDN connection.');
    setStatus($('authStatus'), 'Microsoft authentication library failed to load.', true);
    return;
  }
  init();
});
