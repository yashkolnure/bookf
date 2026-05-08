const mongoose = require('mongoose');
const crypto = require('crypto');

const ALGO = 'aes-256-cbc';
const KEY_LEN = 32;

function getKey() {
  const k = process.env.CALENDAR_ENCRYPTION_KEY || '';
  return Buffer.from(k.padEnd(KEY_LEN, '0').slice(0, KEY_LEN));
}

function encrypt(text) {
  if (!text) return '';
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGO, getKey(), iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  if (!text || !text.includes(':')) return '';
  try {
    const [ivHex, dataHex] = text.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGO, getKey(), iv);
    return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
  } catch {
    return '';
  }
}

const BusyCacheEntrySchema = new mongoose.Schema({
  date:     { type: String, required: true },   // 'YYYY-MM-DD'
  blocks:   [{ start: Date, end: Date }],
  cachedAt: { type: Date, default: Date.now },
}, { _id: false });

const CalendarConnectionSchema = new mongoose.Schema({
  store:    { type: mongoose.Schema.Types.ObjectId, ref: 'Store', required: true },
  provider: { type: String, enum: ['google', 'microsoft', 'apple'], required: true },
  email:    { type: String, default: null },

  // OAuth — Google & Microsoft
  accessToken:  { type: String, select: false, default: null },
  refreshToken: { type: String, select: false, default: null },
  expiresAt:    { type: Date, default: null },

  // Apple CalDAV (password AES-encrypted at rest)
  appleEmail:    { type: String, default: null },
  applePassword: { type: String, select: false, default: null },
  calDavUrl:     { type: String, default: 'https://caldav.icloud.com/' },

  // Behaviour
  isDefault:   { type: Boolean, default: false },  // outbound events go here
  isActive:    { type: Boolean, default: true },
  syncEnabled: { type: Boolean, default: true },

  calendarId: { type: String, default: 'primary' },

  // 5-min busy-block cache per date
  busyCache: { type: [BusyCacheEntrySchema], default: [] },

  lastSynced:  { type: Date, default: null },
  connectedAt: { type: Date, default: Date.now },
});

CalendarConnectionSchema.index({ store: 1, provider: 1 }, { unique: true });

// Encrypt apple password before saving
CalendarConnectionSchema.pre('save', function (next) {
  if (this.isModified('applePassword') && this.applePassword && !this.applePassword.includes(':')) {
    this.applePassword = encrypt(this.applePassword);
  }
  next();
});

CalendarConnectionSchema.methods.getApplePassword = function () {
  return decrypt(this.applePassword);
};

module.exports = mongoose.model('CalendarConnection', CalendarConnectionSchema);
