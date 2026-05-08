/**
 * Calendar Integration Routes
 * Supports: Google Calendar, Microsoft Outlook (OAuth 2.0), Apple Calendar (CalDAV)
 * Bi-directional: inbound busy-block filtering + outbound event creation
 *
 * Required .env variables:
 *   GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI
 *   MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET, MICROSOFT_REDIRECT_URI
 *   FRONTEND_URL          (e.g. http://localhost:5173)
 *   CALENDAR_ENCRYPTION_KEY  (32 chars, for Apple password encryption)
 */

const express = require('express');
const router = express.Router();
const { XMLParser } = require('fast-xml-parser');
const CalendarConnection = require('../models/CalendarConnection');
const Store = require('../models/Store');
const { protect } = require('../middleware/auth');

const FRONTEND = () => process.env.FRONTEND_URL || 'http://localhost:5173';
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// ── OAuth URL builders ────────────────────────────────────────────────────────

function buildGoogleAuthUrl(storeId) {
  const params = new URLSearchParams({
    client_id:     process.env.GOOGLE_CLIENT_ID,
    redirect_uri:  process.env.GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: [
      'https://www.googleapis.com/auth/calendar.events',
      'https://www.googleapis.com/auth/calendar.readonly',
      'https://www.googleapis.com/auth/userinfo.email',
    ].join(' '),
    access_type: 'offline',
    prompt:      'consent',
    state: Buffer.from(JSON.stringify({ storeId, provider: 'google' })).toString('base64'),
  });
  return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
}

function buildMicrosoftAuthUrl(storeId) {
  const params = new URLSearchParams({
    client_id:     process.env.MICROSOFT_CLIENT_ID,
    redirect_uri:  process.env.MICROSOFT_REDIRECT_URI,
    response_type: 'code',
    scope:         'offline_access Calendars.ReadWrite User.Read',
    state: Buffer.from(JSON.stringify({ storeId, provider: 'microsoft' })).toString('base64'),
  });
  return `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?${params}`;
}

// ── Token exchange ────────────────────────────────────────────────────────────

async function exchangeGoogleCode(code) {
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id:     process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri:  process.env.GOOGLE_REDIRECT_URI,
      grant_type:    'authorization_code',
    }),
  });
  if (!res.ok) { const e = await res.json(); throw new Error(e.error_description || 'Google token exchange failed'); }
  return res.json();
}

async function exchangeMicrosoftCode(code) {
  const res = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id:     process.env.MICROSOFT_CLIENT_ID,
      client_secret: process.env.MICROSOFT_CLIENT_SECRET,
      redirect_uri:  process.env.MICROSOFT_REDIRECT_URI,
      grant_type:    'authorization_code',
      scope:         'offline_access Calendars.ReadWrite User.Read',
    }),
  });
  if (!res.ok) { const e = await res.json(); throw new Error(e.error_description || 'Microsoft token exchange failed'); }
  return res.json();
}

// ── Account email fetchers ────────────────────────────────────────────────────

async function getGoogleUserEmail(accessToken) {
  const res = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const data = await res.json();
  return data.email || null;
}

async function getMicrosoftUserEmail(accessToken) {
  const res = await fetch('https://graph.microsoft.com/v1.0/me', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const data = await res.json();
  return data.mail || data.userPrincipalName || null;
}

// ── Token refresh ─────────────────────────────────────────────────────────────

async function refreshGoogleToken(connection) {
  if (!connection.refreshToken) throw new Error('No Google refresh token');
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      refresh_token: connection.refreshToken,
      client_id:     process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      grant_type:    'refresh_token',
    }),
  });
  if (!res.ok) throw new Error('Google token refresh failed');
  const data = await res.json();
  connection.accessToken = data.access_token;
  connection.expiresAt   = new Date(Date.now() + (data.expires_in || 3600) * 1000);
  await connection.save();
  return connection.accessToken;
}

async function refreshMicrosoftToken(connection) {
  if (!connection.refreshToken) throw new Error('No Microsoft refresh token');
  const res = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      refresh_token: connection.refreshToken,
      client_id:     process.env.MICROSOFT_CLIENT_ID,
      client_secret: process.env.MICROSOFT_CLIENT_SECRET,
      grant_type:    'refresh_token',
      scope:         'offline_access Calendars.ReadWrite',
    }),
  });
  if (!res.ok) throw new Error('Microsoft token refresh failed');
  const data = await res.json();
  connection.accessToken = data.access_token;
  if (data.refresh_token) connection.refreshToken = data.refresh_token;
  connection.expiresAt = new Date(Date.now() + (data.expires_in || 3600) * 1000);
  await connection.save();
  return connection.accessToken;
}

async function getValidToken(connection) {
  if (connection.expiresAt && new Date(connection.expiresAt) < new Date(Date.now() + 60000)) {
    if (connection.provider === 'google')    return refreshGoogleToken(connection);
    if (connection.provider === 'microsoft') return refreshMicrosoftToken(connection);
  }
  return connection.accessToken;
}

// ── Apple CalDAV helpers ──────────────────────────────────────────────────────

async function verifyAppleCalDav(email, password, calDavUrl) {
  const auth = Buffer.from(`${email}:${password}`).toString('base64');
  const res = await fetch(`${calDavUrl}`, {
    method: 'PROPFIND',
    headers: {
      Authorization: `Basic ${auth}`,
      Depth: '0',
      'Content-Type': 'application/xml',
    },
    body: `<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:current-user-principal/></D:prop></D:propfind>`,
  });
  // iCloud returns 207 Multi-Status on success, 401 on bad creds
  return res.status === 207 || res.status === 200;
}

async function getAppleBusyBlocks(connection, dateStr) {
  const password = connection.getApplePassword();
  const email    = connection.appleEmail || connection.email;
  const calDavUrl = connection.calDavUrl || 'https://caldav.icloud.com/';
  const auth = Buffer.from(`${email}:${password}`).toString('base64');

  const dateObj = new Date(dateStr);
  const start = dateObj.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
  const endObj = new Date(dateObj.getTime() + 86400000);
  const end   = endObj.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';

  const body = `<?xml version="1.0" encoding="utf-8"?>
<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav">
  <C:time-range start="${start}" end="${end}"/>
</C:free-busy-query>`;

  try {
    const res = await fetch(`${calDavUrl}`, {
      method: 'REPORT',
      headers: {
        Authorization: `Basic ${auth}`,
        Depth: '1',
        'Content-Type': 'application/xml',
      },
      body,
    });
    if (!res.ok) return [];
    const xml = await res.text();
    const parser = new XMLParser({ ignoreAttributes: false });
    const parsed = parser.parse(xml);
    // Extract DTSTART/DTEND pairs from VFREEBUSY FREEBUSY property
    const blocks = [];
    const extractFreebusy = (obj) => {
      if (!obj) return;
      if (typeof obj === 'object') {
        const fb = obj['FREEBUSY'] || obj['freebusy'];
        if (fb) {
          const entries = Array.isArray(fb) ? fb : [fb];
          entries.forEach(e => {
            const str = typeof e === 'string' ? e : String(e);
            str.split(',').forEach(range => {
              const [s, en] = range.split('/');
              if (s && en) blocks.push({ start: new Date(s), end: new Date(en) });
            });
          });
        }
        Object.values(obj).forEach(v => extractFreebusy(v));
      }
    };
    extractFreebusy(parsed);
    return blocks;
  } catch {
    return [];
  }
}

// ── Busy-block fetchers with 5-min cache ──────────────────────────────────────

async function getGoogleBusyBlocks(connection, dateStr) {
  const token   = await getValidToken(connection);
  const timeMin = new Date(dateStr).toISOString();
  const timeMax = new Date(new Date(dateStr).getTime() + 86400000).toISOString();
  const res = await fetch('https://www.googleapis.com/calendar/v3/freeBusy', {
    method:  'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ timeMin, timeMax, items: [{ id: connection.calendarId || 'primary' }] }),
  });
  if (!res.ok) return [];
  const data = await res.json();
  const busy = data.calendars?.[connection.calendarId || 'primary']?.busy || [];
  return busy.map(b => ({ start: new Date(b.start), end: new Date(b.end) }));
}

async function getMicrosoftBusyBlocks(connection, dateStr) {
  const token  = await getValidToken(connection);
  const startDT = new Date(dateStr).toISOString();
  const endDT   = new Date(new Date(dateStr).getTime() + 86400000).toISOString();
  const res = await fetch(
    `https://graph.microsoft.com/v1.0/me/calendarView?startDateTime=${startDT}&endDateTime=${endDT}&$select=start,end`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) return [];
  const data = await res.json();
  return (data.value || []).map(e => ({
    start: new Date(e.start.dateTime + 'Z'),
    end:   new Date(e.end.dateTime + 'Z'),
  }));
}

/**
 * Returns busy blocks for a store on a given date.
 * Checks the 5-min cache first; fetches from external APIs only if stale.
 * Exported for use in services.js slot endpoint.
 */
async function getStoreBusyBlocks(storeId, dateStr) {
  const connections = await CalendarConnection
    .findOne({ store: storeId }) // force select of sensitive fields
    .select('+accessToken +refreshToken +applePassword')
    .then(() => CalendarConnection.find({ store: storeId, isActive: true, syncEnabled: true }).select('+accessToken +refreshToken +applePassword'));

  const all = [];
  for (const conn of connections) {
    // Check cache
    const cached = conn.busyCache.find(c => c.date === dateStr);
    if (cached && (Date.now() - new Date(cached.cachedAt).getTime()) < CACHE_TTL_MS) {
      all.push(...cached.blocks.map(b => ({ start: new Date(b.start), end: new Date(b.end) })));
      continue;
    }

    // Fresh fetch
    try {
      let blocks = [];
      if (conn.provider === 'google')    blocks = await getGoogleBusyBlocks(conn, dateStr);
      if (conn.provider === 'microsoft') blocks = await getMicrosoftBusyBlocks(conn, dateStr);
      if (conn.provider === 'apple')     blocks = await getAppleBusyBlocks(conn, dateStr);

      all.push(...blocks);

      // Update cache
      const idx = conn.busyCache.findIndex(c => c.date === dateStr);
      if (idx >= 0) {
        conn.busyCache[idx].blocks   = blocks;
        conn.busyCache[idx].cachedAt = new Date();
      } else {
        conn.busyCache.push({ date: dateStr, blocks, cachedAt: new Date() });
        // Keep only last 30 dates to avoid unbounded growth
        if (conn.busyCache.length > 30) conn.busyCache.splice(0, conn.busyCache.length - 30);
      }
      conn.lastSynced = new Date();
      await conn.save();
    } catch (err) {
      console.error(`Calendar busy-fetch error (${conn.provider}):`, err.message);
    }
  }
  return all;
}

// ── Outbound event creators ───────────────────────────────────────────────────

async function createGoogleEvent(connection, appointment, serviceName) {
  const token = await getValidToken(connection);
  const dateStr = new Date(appointment.appointmentDate).toISOString().split('T')[0];
  const body = {
    summary: `BookEase: ${serviceName}`,
    description: `Customer: ${appointment.customer?.name || ''}\nPhone: ${appointment.customer?.phone || ''}`,
    start: { dateTime: `${dateStr}T${appointment.startTime}:00`, timeZone: 'Asia/Kolkata' },
    end:   { dateTime: `${dateStr}T${appointment.endTime}:00`,   timeZone: 'Asia/Kolkata' },
  };
  const res = await fetch(
    `https://www.googleapis.com/calendar/v3/calendars/${connection.calendarId || 'primary'}/events`,
    {
      method:  'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }
  );
  if (!res.ok) throw new Error(`Google event creation failed: ${res.status}`);
}

async function createMicrosoftEvent(connection, appointment, serviceName) {
  const token = await getValidToken(connection);
  const dateStr = new Date(appointment.appointmentDate).toISOString().split('T')[0];
  const body = {
    subject: `BookEase: ${serviceName}`,
    body: {
      contentType: 'text',
      content: `Customer: ${appointment.customer?.name || ''}\nPhone: ${appointment.customer?.phone || ''}`,
    },
    start: { dateTime: `${dateStr}T${appointment.startTime}:00`, timeZone: 'Asia/Calcutta' },
    end:   { dateTime: `${dateStr}T${appointment.endTime}:00`,   timeZone: 'Asia/Calcutta' },
  };
  const res = await fetch('https://graph.microsoft.com/v1.0/me/events', {
    method:  'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Microsoft event creation failed: ${res.status}`);
}

async function createAppleEvent(connection, appointment, serviceName) {
  const password = connection.getApplePassword();
  const email    = connection.appleEmail || connection.email;
  const calDavUrl = connection.calDavUrl || 'https://caldav.icloud.com/';
  const auth = Buffer.from(`${email}:${password}`).toString('base64');

  const dateStr = new Date(appointment.appointmentDate).toISOString().split('T')[0];
  const uid = `bookkromess-${appointment._id}@bookease`;
  const now = new Date().toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
  const dtstart = `${dateStr.replace(/-/g, '')}T${appointment.startTime.replace(':', '')}00`;
  const dtend   = `${dateStr.replace(/-/g, '')}T${appointment.endTime.replace(':', '')}00`;

  const ics = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//BookEase//EN',
    'BEGIN:VEVENT',
    `UID:${uid}`,
    `DTSTAMP:${now}`,
    `DTSTART;TZID=Asia/Kolkata:${dtstart}`,
    `DTEND;TZID=Asia/Kolkata:${dtend}`,
    `SUMMARY:BookEase: ${serviceName}`,
    `DESCRIPTION:Customer: ${appointment.customer?.name || ''}`,
    'END:VEVENT',
    'END:VCALENDAR',
  ].join('\r\n');

  const res = await fetch(`${calDavUrl}${uid}.ics`, {
    method:  'PUT',
    headers: {
      Authorization:  `Basic ${auth}`,
      'Content-Type': 'text/calendar',
    },
    body: ics,
  });
  if (res.status >= 300 && res.status !== 201 && res.status !== 204) {
    throw new Error(`Apple CalDAV event creation failed: ${res.status}`);
  }
}

/**
 * Push a confirmed appointment to the provider's default connected calendar.
 * Call fire-and-forget from appointments.js — errors are swallowed.
 */
async function createEventForAppointment(storeId, appointment) {
  const conn = await CalendarConnection.findOne({ store: storeId, isDefault: true, isActive: true })
    .select('+accessToken +refreshToken +applePassword');
  if (!conn) return;

  const Service = require('../models/Service');
  const service = await Service.findById(appointment.service).select('name').lean();
  const serviceName = service?.name || 'Appointment';

  if (conn.provider === 'google')    await createGoogleEvent(conn, appointment, serviceName);
  if (conn.provider === 'microsoft') await createMicrosoftEvent(conn, appointment, serviceName);
  if (conn.provider === 'apple')     await createAppleEvent(conn, appointment, serviceName);
}

// ── Routes ────────────────────────────────────────────────────────────────────

/**
 * GET /api/calendar/auth/:provider
 * Returns the OAuth authorization URL.
 */
router.get('/auth/:provider', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });

    const { provider } = req.params;
    if (provider === 'google') {
      if (!process.env.GOOGLE_CLIENT_ID) return res.status(501).json({ success: false, message: 'Google Calendar not configured — add GOOGLE_CLIENT_ID to .env' });
      return res.json({ success: true, authUrl: buildGoogleAuthUrl(store._id.toString()) });
    }
    if (provider === 'microsoft') {
      if (!process.env.MICROSOFT_CLIENT_ID) return res.status(501).json({ success: false, message: 'Microsoft Calendar not configured — add MICROSOFT_CLIENT_ID to .env' });
      return res.json({ success: true, authUrl: buildMicrosoftAuthUrl(store._id.toString()) });
    }
    return res.status(400).json({ success: false, message: 'Use /apple/connect for Apple Calendar' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

/**
 * GET /api/calendar/callback/:provider?code=&state=
 * OAuth callback — exchanges code, saves connection, redirects to /dashboard/calendar.
 */
router.get('/callback/:provider', async (req, res) => {
  const { provider } = req.params;
  const { code, error, state } = req.query;
  const base = FRONTEND();

  if (error || !code) {
    return res.redirect(`${base}/dashboard/calendar?error=${encodeURIComponent(error || 'cancelled')}`);
  }

  try {
    const { storeId } = JSON.parse(Buffer.from(state, 'base64').toString());
    let accessToken, refreshToken, expiresIn, email;

    if (provider === 'google') {
      const tokens = await exchangeGoogleCode(code);
      accessToken  = tokens.access_token;
      refreshToken = tokens.refresh_token;
      expiresIn    = tokens.expires_in || 3600;
      email        = await getGoogleUserEmail(accessToken);
    } else if (provider === 'microsoft') {
      const tokens = await exchangeMicrosoftCode(code);
      accessToken  = tokens.access_token;
      refreshToken = tokens.refresh_token;
      expiresIn    = tokens.expires_in || 3600;
      email        = await getMicrosoftUserEmail(accessToken);
    } else {
      return res.redirect(`${base}/dashboard/calendar?error=unsupported_provider`);
    }

    // Check if this is the first connection for this store (make it default)
    const existingCount = await CalendarConnection.countDocuments({ store: storeId, isActive: true });

    await CalendarConnection.findOneAndUpdate(
      { store: storeId, provider },
      {
        accessToken,
        refreshToken,
        expiresAt:   new Date(Date.now() + expiresIn * 1000),
        email,
        isActive:    true,
        isDefault:   existingCount === 0, // first connection becomes default
        lastSynced:  new Date(),
        busyCache:   [],
      },
      { upsert: true, new: true }
    );

    return res.redirect(`${base}/dashboard/calendar?connected=${provider}`);
  } catch (err) {
    console.error('Calendar callback error:', err);
    return res.redirect(`${FRONTEND()}/dashboard/calendar?error=${encodeURIComponent(err.message)}`);
  }
});

/**
 * POST /api/calendar/apple/connect
 * Connect Apple Calendar via CalDAV credentials.
 * Body: { email, password }
 */
router.post('/apple/connect', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });

    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'email and password are required' });

    const calDavUrl = 'https://caldav.icloud.com/';
    const valid = await verifyAppleCalDav(email, password, calDavUrl);
    if (!valid) return res.status(401).json({ success: false, message: 'Invalid Apple ID or app-specific password. Make sure you are using an app-specific password, not your main Apple ID password.' });

    const existingCount = await CalendarConnection.countDocuments({ store: store._id, isActive: true });

    const conn = await CalendarConnection.findOneAndUpdate(
      { store: store._id, provider: 'apple' },
      {
        email,
        appleEmail:    email,
        applePassword: password, // pre-save hook encrypts this
        calDavUrl,
        isActive:      true,
        isDefault:     existingCount === 0,
        lastSynced:    new Date(),
        busyCache:     [],
      },
      { upsert: true, new: true, runValidators: true }
    );

    res.json({ success: true, connection: { _id: conn._id, provider: 'apple', email, isDefault: conn.isDefault, isActive: true } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

/**
 * GET /api/calendar/connections
 * List connected calendars for the current provider (tokens excluded).
 */
router.get('/connections', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });

    const connections = await CalendarConnection.find({ store: store._id })
      .select('-accessToken -refreshToken -applePassword -busyCache')
      .sort('provider');

    res.json({ success: true, connections });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

/**
 * DELETE /api/calendar/connections/:id
 * Disconnect a calendar.
 */
router.delete('/connections/:id', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });

    const connection = await CalendarConnection.findOne({ _id: req.params.id, store: store._id });
    if (!connection) return res.status(404).json({ success: false, message: 'Connection not found' });

    await connection.deleteOne();

    // If the deleted connection was default, auto-promote the next one
    if (connection.isDefault) {
      const next = await CalendarConnection.findOne({ store: store._id, isActive: true });
      if (next) { next.isDefault = true; await next.save(); }
    }

    res.json({ success: true, message: 'Calendar disconnected' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

/**
 * PATCH /api/calendar/connections/:id/setDefault
 * Set a calendar as the default for outbound events.
 */
router.patch('/connections/:id/setDefault', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });

    const connection = await CalendarConnection.findOne({ _id: req.params.id, store: store._id });
    if (!connection) return res.status(404).json({ success: false, message: 'Connection not found' });

    // Clear all defaults for this store, then set this one
    await CalendarConnection.updateMany({ store: store._id }, { isDefault: false });
    connection.isDefault = true;
    await connection.save();

    res.json({ success: true, message: 'Default calendar updated' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

/**
 * GET /api/calendar/busy?date=YYYY-MM-DD
 * Protected — get busy blocks for the provider's store on a given date.
 */
router.get('/busy', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });
    if (!req.query.date) return res.status(400).json({ success: false, message: 'date query param required' });

    const blocks = await getStoreBusyBlocks(store._id, req.query.date);
    res.json({ success: true, busyBlocks: blocks });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
module.exports.getStoreBusyBlocks    = getStoreBusyBlocks;
module.exports.createEventForAppointment = createEventForAppointment;
