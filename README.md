/**
 * webhook_server_sample.js
 * Production-ready Express webhook receiver for Travel Approval Workflow
 *
 * Features:
 * - API Key auth (header: x-api-key)
 * - SecurityHash verification (HMAC-SHA256 using SECRET_SIGNING_KEY)
 * - AppSheet API update helper
 * - M-Pesa (Daraja) OAuth + STK Push helper
 * - MPesa callback endpoint (stub/verify)
 * - Logging via winston
 * - Rate limiting
 *
 * Required environment variables (.env):
 * PORT=4000
 * WEBHOOK_API_KEY=replace_with_strong_random_key
 * SECRET_SIGNING_KEY=replace_with_signing_secret_for_hashes
 * APPSHEET_APP_ID=your_appsheet_app_id
 * APPSHEET_ACCESS_KEY=your_appsheet_application_access_key
 * MPESA_CONSUMER_KEY=...
 * MPESA_CONSUMER_SECRET=...
 * MPESA_ENV=sandbox | production
 * MPESA_SHORTCODE=...
 * MPESA_PASSKEY=... (for STK)
 * MPESA_CALLBACK_URL=https://webhook.yourdomain.com/mpesa/callback
 * ADMIN_EMAIL=stunnersonof@gmail.com
 *
 * Install dependencies:
 * npm i express body-parser helmet dotenv node-fetch crypto winston express-rate-limit
 *
 * Run:
 * node webhook_server_sample.js
 *
 * NOTE: This is a template. You MUST secure your server, rotate keys, use HTTPS via nginx/Certbot.
 */

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const crypto = require('crypto');
const fetch = require('node-fetch'); // node >= 18 has fetch builtin; using node-fetch for compatibility
const winston = require('winston');
const rateLimit = require('express-rate-limit');

const {
  WEBHOOK_API_KEY,
  SECRET_SIGNING_KEY,
  APPSHEET_APP_ID,
  APPSHEET_ACCESS_KEY,
  MPESA_CONSUMER_KEY,
  MPESA_CONSUMER_SECRET,
  MPESA_ENV,
  MPESA_SHORTCODE,
  MPESA_PASSKEY,
  MPESA_CALLBACK_URL,
  PORT = 4000
} = process.env;

if (!WEBHOOK_API_KEY || !SECRET_SIGNING_KEY) {
  console.error('Missing required env vars: WEBHOOK_API_KEY or SECRET_SIGNING_KEY. Exiting.');
  process.exit(1);
}

/* -------------------------
   Simple logger (winston)
   -------------------------*/
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(info => `[${info.timestamp}] ${info.level.toUpperCase()}: ${info.message}`)
  ),
  transports: [new winston.transports.Console()]
});

/* -------------------------
   Express App + security
   -------------------------*/
const app = express();
app.use(helmet());
app.use(bodyParser.json({ limit: '1mb' }));

// Rate limiter - adjust as necessary
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
});
app.use(limiter);

/* -------------------------
   Middleware: API Key auth
   -------------------------*/
function apiKeyAuth(req, res, next) {
  const key = (req.headers['x-api-key'] || '').toString();
  if (!key || key !== WEBHOOK_API_KEY) {
    logger.warn(`Unauthorized request from ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized' });
  }
  return next();
}

/* -------------------------
   Utility: HMAC SHA256 verify
   - Expected: HMAC_SHA256(SECRET_SIGNING_KEY, canonicalPayload)
   - canonicalPayload: JSON string of payload fields in agreed order (see caller)
   -------------------------*/
function computeHmac(payloadString) {
  return crypto.createHmac('sha256', SECRET_SIGNING_KEY).update(payloadString, 'utf8').digest('hex');
}

/* -------------------------
   AppSheet API helper
   -------------------------*/
async function appsheetEditRow(tableName, rowObj) {
  if (!APPSHEET_APP_ID || !APPSHEET_ACCESS_KEY) {
    throw new Error('AppSheet credentials missing in env');
  }
  const url = `https://api.appsheet.com/api/v2/apps/${APPSHEET_APP_ID}/tables/${encodeURIComponent(tableName)}/Action`;
  const body = {
    Action: 'Edit',
    Properties: { Locale: 'en-US' },
    Rows: [rowObj]
  };
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'ApplicationAccessKey': APPSHEET_ACCESS_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  const json = await resp.json();
  if (!resp.ok) {
    logger.error('AppSheet API error: ' + JSON.stringify(json));
    throw new Error('AppSheet API failed: ' + (json.error || JSON.stringify(json)));
  }
  return json;
}

/* -------------------------
   M-Pesa (Daraja) helpers
   - getMpesaToken()
   - lipaNaMpesaSTK()
   - handleMpesaCallback()
   -------------------------*/
const MPESA_BASE = (MPESA_ENV === 'production') ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke';

async function getMpesaToken() {
  if (!MPESA_CONSUMER_KEY || !MPESA_CONSUMER_SECRET) {
    throw new Error('M-Pesa credentials not set');
  }
  const url = `${MPESA_BASE}/oauth/v1/generate?grant_type=client_credentials`;
  const auth = Buffer.from(`${MPESA_CONSUMER_KEY}:${MPESA_CONSUMER_SECRET}`).toString('base64');
  const resp = await fetch(url, {
    method: 'GET',
    headers: {
      Authorization: `Basic ${auth}`
    }
  });
  const data = await resp.json();
  if (!resp.ok) {
    logger.error('M-Pesa token error: ' + JSON.stringify(data));
    throw new Error('M-Pesa token error');
  }
  return data.access_token;
}

// Encoded password for STK: base64(shortcode + passkey + timestamp)
function buildStkPassword(shortcode, passkey, timestamp) {
  return Buffer.from(`${shortcode}${passkey}${timestamp}`).toString('base64');
}

async function lipaNaMpesaSTK(amount, phoneNumber, accountRef, callbackUrl) {
  const accessToken = await getMpesaToken();
  const url = `${MPESA_BASE}/mpesa/stkpush/v1/processrequest`;
  const timestamp = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
  const password = buildStkPassword(MPESA_SHORTCODE, MPESA_PASSKEY, timestamp);
  const body = {
    BusinessShortCode: MPESA_SHORTCODE,
    Password: password,
    Timestamp: timestamp,
    TransactionType: 'CustomerPayBillOnline',
    Amount: amount,
    PartyA: phoneNumber,
    PartyB: MPESA_SHORTCODE,
    PhoneNumber: phoneNumber,
    CallBackURL: callbackUrl || MPESA_CALLBACK_URL,
    AccountReference: accountRef || 'Withdrawal',
    TransactionDesc: 'Withdrawal Payment'
  };
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  const data = await resp.json();
  if (!resp.ok) {
    logger.error('STK push error: ' + JSON.stringify(data));
    throw new Error('STK push failed');
  }
  return data;
}

/* -------------------------
   Endpoint: /webhook/withdrawal
   - expects JSON payload with RequestID, User, TotalCost, Status, SecurityHash, etc.
   - middleware: apiKeyAuth
   - verifies SecurityHash (HMAC)
   - processes request: e.g., validate, create job, call mpesa if instructed, update AppSheet
   -------------------------*/
app.post('/webhook/withdrawal', apiKeyAuth, async (req, res) => {
  try {
    const payload = req.body || {};
    // Basic validation
    const { RequestID, User, TotalCost, Status, SecurityHash, MPesaNumber, Action } = payload;
    if (!RequestID || !User || !TotalCost || !SecurityHash) {
      logger.warn('Bad payload: missing required fields');
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Canonical payload string - MUST match client-side generation
    // Use consistent ordering of fields — change as needed (communicate to AppSheet generator)
    const canonical = `${RequestID}|${User}|${TotalCost}|${Status || ''}`;
    const expected = computeHmac(canonical);

    if (expected !== SecurityHash) {
      logger.warn(`Invalid SecurityHash for ${RequestID} - expected ${expected}, got ${SecurityHash}`);
      return res.status(403).json({ error: 'Invalid SecurityHash' });
    }

    logger.info(`Webhook received valid payload for ${RequestID} (action: ${Action || 'none'})`);

    // Example: if action instructs to pay, trigger M-Pesa STK
    if (Action === 'PAY' && MPesaNumber) {
      logger.info(`Triggering STK push for ${RequestID} -> ${MPesaNumber} amount ${TotalCost}`);
      try {
        const stkResp = await lipaNaMpesaSTK(TotalCost, MPesaNumber, RequestID);
        // You may want to store stkResp.TransactionId or CheckoutRequestID in DB for correlation
        logger.info(`STK push response: ${JSON.stringify(stkResp)}`);

        // Optionally, update AppSheet record to note STK initiated
        await appsheetEditRow('Withdrawals', {
          ID: RequestID,
          Status: 'Payment Initiated',
          AuditNotes: `STK initiated: ${stkResp.CheckoutRequestID || stkResp.ResponseDescription || JSON.stringify(stkResp)}`
        });
        return res.json({ status: 'stk_initiated', detail: stkResp });
      } catch (err) {
        logger.error('Error during STK push: ' + err.message);
        await appsheetEditRow('Withdrawals', {
          ID: RequestID,
          AuditNotes: `STK error: ${err.message}`
        }).catch(e => logger.warn('AppSheet update failed: ' + e.message));
        return res.status(500).json({ error: 'STK push failed', detail: err.message });
      }
    }

    // If not a payment action — maybe it's a record creation or status sync
    if (Action === 'CREATE' || Action === 'UPDATE') {
      // Translate payload to AppSheet edit or add as needed.
      const row = {
        ID: RequestID,
        Status: Status || 'Pending',
        AuditNotes: `Webhook received from ${User} at ${new Date().toISOString()}`
      };
      await appsheetEditRow('Withdrawals', row);
      return res.json({ status: 'ok', message: 'AppSheet updated' });
    }

    // Default: just accept and log
    return res.json({ status: 'received' });
  } catch (err) {
    logger.error('Webhook error: ' + err.stack);
    return res.status(500).json({ error: 'server_error', detail: err.message });
  }
});

/* -------------------------
   Endpoint: /mpesa/callback
   - receives Safaricom callback after STK push or B2C
   - verify structure, log, update AppSheet accordingly
   -------------------------*/
app.post('/mpesa/callback', async (req, res) => {
  try {
    const body = req.body || {};
    logger.info('MPesa callback received: ' + JSON.stringify(body));

    // Example of handling typical STK callback:
    // body.Body.stkCallback.ResultCode, Body.stkCallback.CheckoutRequestID, etc.
    // Validate and map to RequestID (we suggested using AccountReference=RequestID)

    // Extract checkout request and result
    const stk = body?.Body?.stkCallback;
    if (stk) {
      const checkoutRequestID = stk.CheckoutRequestID;
      const resultCode = stk.ResultCode;
      // Search your storage for AccountReference mapping (if you saved it on STK response)
      // For this sample, we assume AccountReference == RequestID, which your MPesa provider must include in callback's metadata.
      // Parse metadata (if present)
      const callbackMetadata = stk?.CallbackMetadata;
      let requestId = null;
      if (callbackMetadata && callbackMetadata.Item) {
        // Try to find account reference in metadata items
        const acct = callbackMetadata.Item.find(i => i.Name === 'AccountReference' || i.Name === 'Account No' || i.Name === 'BillRefNumber');
        if (acct) requestId = acct.Value;
      }
      // Fallback: you might store mapping from CheckoutRequestID -> RequestID in DB earlier.
      // Update AppSheet accordingly
      const status = (resultCode === 0) ? 'Paid' : 'Payment Failed';
      const paidDate = new Date().toISOString();
      const rowUpdate = requestId ? { ID: requestId, Status: status, PaidDate: paidDate, AuditNotes: `M-Pesa callback: ${JSON.stringify(stk)}` } : null;

      if (rowUpdate) {
        try {
          await appsheetEditRow('Withdrawals', rowUpdate);
          logger.info('AppSheet updated after MPesa callback for ' + requestId);
        } catch (e) {
          logger.error('Failed to update AppSheet after MPesa callback: ' + e.message);
        }
      } else {
        logger.warn('Could not determine RequestID from MPesa callback. Save record for manual resolution.');
      }
      // respond 200 to Safaricom quickly
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    // If unknown format
    return res.status(400).json({ error: 'unknown mpesa callback format' });
  } catch (err) {
    logger.error('MPesa callback handler error: ' + err.stack);
    return res.status(500).json({ error: 'server_error' });
  }
});

/* -------------------------
   Health check & root
   -------------------------*/
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));
app.get('/', (req, res) => res.send('Travel Approval Webhook Service'));

/* -------------------------
   Graceful shutdown
   -------------------------*/
const server = app.listen(PORT, () => {
  logger.info(`Webhook server listening on port ${PORT}`);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received: shutting down');
  server.close(() => process.exit(0));
});
process.on('SIGTERM', () => {
  logger.info('SIGTERM received: shutting down');
  server.close(() => process.exit(0));
});

/* -------------------------
   Unit test stubs (Jest) - save as webhook_server.test.js in __tests__ folder
   (Not run here; provided as helper)
   -------------------------*/

/*
Example Jest test file (not executed here):

// __tests__/webhook_server.test.js
const request = require('supertest');
const app = require('../webhook_server_sample'); // export app if you refactor

describe('Webhook endpoints', () => {
  test('health check', async () => {
    const res = await request(app).get('/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe('ok');
  });

  test('unauthorized webhook', async () => {
    const res = await request(app)
      .post('/webhook/withdrawal')
      .send({ RequestID: 'TST1', User: 'a@b.com', TotalCost: 100, Status: 'Submitted', SecurityHash: 'x' });
    expect(res.statusCode).toBe(401);
  });
});

To run tests:
npm i --save-dev jest supertest
Add to package.json: "test": "jest"
*//**
 * functions/index.js
 * Firebase Cloud Functions (Node.js)
 *
 * Sandbox mode: set process.env.SANDBOX_MODE = "true" (or via firebase functions:config)
 * - no Daraja STK calls will be made
 * - withdrawals marked "pending_manual_payout"
 * - admin can call approveWithdrawal to mark as completed (simulate callback)
 *
 * Required env / config keys (use firebase functions:config:set or env):
 * MPESA_ENV, MPESA_SHORTCODE, MPESA_PASSKEY, MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET,
 * AT_USERNAME, AT_APIKEY, AT_FROM, SANDBOX_MODE (true/false)
 *
 * Dependencies: firebase-admin, firebase-functions, axios, bcryptjs, africastalking, crypto
 */

require('dotenv').config();
const functions = require('firebase-functions');
const admin = require('firebase-admin');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Africa's Talking SMS
const AfricasTalking = require('africastalking');

admin.initializeApp();
const db = admin.firestore();

// ----------------- Config -----------------
const SANDBOX_MODE = (process.env.SANDBOX_MODE || 'true') === 'true';
const MPESA_SHORTCODE = process.env.MPESA_SHORTCODE || '174379';
const MPESA_PASSKEY = process.env.MPESA_PASSKEY || '';
const MPESA_CONSUMER_KEY = process.env.MPESA_CONSUMER_KEY || '';
const MPESA_CONSUMER_SECRET = process.env.MPESA_CONSUMER_SECRET || '';
const MPESA_CALLBACK_URL = process.env.MPESA_CALLBACK_URL || ''; // still useful for production later

const AT_USERNAME = process.env.AT_USERNAME || '';
const AT_APIKEY = process.env.AT_APIKEY || '';
const AT_FROM = process.env.AT_FROM || undefined;

const at = AfricasTalking({ username: AT_USERNAME, apiKey: AT_APIKEY });
const smsService = at.SMS;

// ---------- Helpers ----------
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function genOtp() { return Math.floor(100000 + Math.random()*900000).toString(); }

async function sendSmsAT(to, message) {
  if (!AT_USERNAME || !AT_APIKEY) {
    console.warn('Africa\'s Talking not configured — SMS will be logged only.');
    console.log(`(SMS LOG) to=${to} msg=${message}`);
    return null;
  }
  try {
    const resp = await smsService.send({ to: [to], message, from: AT_FROM });
    console.log('AT SMS response', resp);
    return resp;
  } catch (err) {
    console.error('AT SMS error', err);
    throw err;
  }
}

// optional: stubbed Daraja token & STK (only used if SANDBOX_MODE=false)
// We'll keep getDarajaToken & stkPush helpers for when you switch to production
let cachedToken = null; let tokenExpires = 0;
async function getDarajaToken() {
  if (cachedToken && Date.now() < tokenExpires - 60000) return cachedToken;
  const base = process.env.MPESA_ENV === 'production' ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke';
  const oauth = `${base}/oauth/v1/generate?grant_type=client_credentials`;
  const auth = Buffer.from(`${MPESA_CONSUMER_KEY}:${MPESA_CONSUMER_SECRET}`).toString('base64');
  const r = await axios.get(oauth, { headers: { Authorization: `Basic ${auth}` } });
  cachedToken = r.data.access_token;
  tokenExpires = Date.now() + (r.data.expires_in || 3600) * 1000;
  return cachedToken;
}
function timestamp() {
  const d = new Date();
  return d.getFullYear().toString()
    + String(d.getMonth()+1).padStart(2,'0')
    + String(d.getDate()).padStart(2,'0')
    + String(d.getHours()).padStart(2,'0')
    + String(d.getMinutes()).padStart(2,'0')
    + String(d.getSeconds()).padStart(2,'0');
}
function generatePassword(shortcode, passkey, ts) {
  return Buffer.from(shortcode + passkey + ts).toString('base64');
}

// -------------- Cloud Functions --------------

// 1) setPin (already provided earlier) - store hashed PIN in users/{uid}
exports.setPin = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated','Auth required');
  const uid = context.auth.uid;
  const { pin, currentPin } = data;
  if (!pin || typeof pin !== 'string' || pin.length < 4) throw new functions.https.HttpsError('invalid-argument','PIN must be at least 4 digits');

  const userRef = db.collection('users').doc(uid);
  const userSnap = await userRef.get();
  const userData = userSnap.exists ? userSnap.data() : {};

  if (userData.pinHash) {
    if (!currentPin) throw new functions.https.HttpsError('permission-denied','Current PIN required to change PIN');
    const matches = await bcrypt.compare(currentPin, userData.pinHash);
    if (!matches) throw new functions.https.HttpsError('permission-denied','Current PIN incorrect');
  }

  const saltRounds = 12;
  const hash = await bcrypt.hash(pin, saltRounds);
  await userRef.set({ pinHash: hash, pinUpdatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });

  await db.collection('securityLogs').add({ userId: uid, type: 'pin_set', createdAt: admin.firestore.FieldValue.serverTimestamp() });
  return { message: 'PIN set' };
});

// 2) requestWithdraw: create withdrawal + send OTP
exports.requestWithdraw = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated','Auth required');
  const uid = context.auth.uid;
  const { amount, phone } = data;

  if (!amount || amount < 100) throw new functions.https.HttpsError('invalid-argument','Amount >= 100 required');
  if (!phone) throw new functions.https.HttpsError('invalid-argument','Phone required');

  // server-side balance check (you must implement your own balances collection)
  const balSnap = await db.collection('balances').doc(uid).get();
  const balance = (balSnap.exists && balSnap.data().balance) || 0;
  if (amount > balance) throw new functions.https.HttpsError('failed-precondition','Insufficient balance');

  // create withdrawal doc
  const wdRef = db.collection('withdrawals').doc();
  const wd = {
    id: wdRef.id,
    userId: uid,
    amount,
    currency: 'KES',
    phone,
    destination: { type: 'm-pesa-paybill', identifier: MPESA_SHORTCODE }, // placeholder
    status: 'otp_pending',
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  };
  await wdRef.set(wd);

  // generate & store OTP
  const otp = genOtp();
  const otpHash = sha256(otp);
  const otpDoc = {
    withdrawalId: wd.id,
    otpHash,
    attempts: 0,
    expiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + 5*60*1000) // 5 minutes
  };
  await db.collection('otps').doc(wd.id).set(otpDoc);

  // send OTP (Africa's Talking if configured; otherwise log)
  try {
    await sendSmsAT(phone, `Your OTP for withdrawal ${wd.id} is ${otp}. Expires in 5 minutes.`);
  } catch (err) {
    console.warn('SMS send failed (sandbox continues):', err.message || err);
  }

  // audit log
  await db.collection('securityLogs').add({ userId: uid, type: 'withdraw_request', withdrawalId: wd.id, amount, createdAt: admin.firestore.FieldValue.serverTimestamp() });

  return { wdId: wd.id, message: 'OTP sent' };
});

// 3) verifyOtpAndPush: verify OTP + PIN. In SANDBOX -> mark pending_manual_payout.
// If SANDBOX_MODE=false, this logic will attempt real STK push.
exports.verifyOtpAndPush = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated','Auth required');
  const uid = context.auth.uid;
  const { wdId, otp, pin } = data;
  if (!wdId || !otp || !pin) throw new functions.https.HttpsError('invalid-argument','wdId, otp, pin required');

  const wdRef = db.collection('withdrawals').doc(wdId);
  const wdSnap = await wdRef.get();
  if (!wdSnap.exists) throw new functions.https.HttpsError('not-found','Withdrawal not found');
  const wd = wdSnap.data();
  if (wd.userId !== uid) throw new functions.https.HttpsError('permission-denied','Not your withdrawal');
  if (wd.status !== 'otp_pending') throw new functions.https.HttpsError('failed-precondition','Invalid status');

  // OTP doc
  const otpRef = db.collection('otps').doc(wdId);
  const otpSnap = await otpRef.get();
  if (!otpSnap.exists) throw new functions.https.HttpsError('not-found','OTP not found');
  const otpDoc = otpSnap.data();
  if (otpDoc.attempts >= 5) throw new functions.https.HttpsError('permission-denied','Too many attempts');
  if (otpDoc.expiresAt.toMillis() < Date.now()) throw new functions.https.HttpsError('deadline-exceeded','OTP expired');

  if (sha256(otp) !== otpDoc.otpHash) {
    await otpRef.update({ attempts: admin.firestore.FieldValue.increment(1) });
    throw new functions.https.HttpsError('invalid-argument','Invalid OTP');
  }

  // verify PIN
  const userRef = db.collection('users').doc(uid);
  const userSnap = await userRef.get();
  const userData = userSnap.exists ? userSnap.data() : {};
  if (!userData.pinHash) throw new functions.https.HttpsError('failed-precondition','PIN not setup');
  const pinOk = await bcrypt.compare(pin, userData.pinHash);
  if (!pinOk) throw new functions.https.HttpsError('permission-denied','Invalid PIN');

  // mark OTP verified
  await otpRef.update({ verifiedAt: admin.firestore.FieldValue.serverTimestamp() });
  await wdRef.update({ status: 'otp_verified', updatedAt: admin.firestore.FieldValue.serverTimestamp() });

  // Risk check (simple example; customize)
  const limitDaily = (userData.dailyLimit || 20000);
  if (wd.amount > limitDaily) {
    await wdRef.update({ status: 'manual_review', reason: 'exceeds_daily_limit', updatedAt: admin.firestore.FieldValue.serverTimestamp() });
    return { status: 'manual_review', message: 'Withdrawal flagged for manual review' };
  }

  // If sandbox mode: do NOT call Daraja; mark pending_manual_payout
  if (SANDBOX_MODE) {
    await wdRef.update({
      status: 'pending_manual_payout',
      note: 'Sandbox mode — await manual payout from admin',
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    await db.collection('securityLogs').add({ userId: uid, type: 'stk_simulated', withdrawalId: wd.id, createdAt: admin.firestore.FieldValue.serverTimestamp() });
    return { status: 'pending_manual_payout', message: 'Sandbox: withdrawal marked pending manual payout' };
  }

  // ---------- Production branch (not executed in sandbox)
  try {
    const token = await getDarajaToken();
    const ts = timestamp();
    const password = generatePassword(MPESA_SHORTCODE, MPESA_PASSKEY, ts);
    const phone254 = wd.phone.replace('+','');

    const body = {
      BusinessShortCode: MPESA_SHORTCODE,
      Password: password,
      Timestamp: ts,
      TransactionType: "CustomerPayBillOnline",
      Amount: wd.amount,
      PartyA: phone254,
      PartyB: MPESA_SHORTCODE,
      PhoneNumber: phone254,
      CallBackURL: MPESA_CALLBACK_URL,
      AccountReference: `WD-${wd.id}`,
      TransactionDesc: `Withdrawal ${wd.id}`
    };

    const base = process.env.MPESA_ENV === 'production' ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke';
    const stkUrl = `${base}/mpesa/stkpush/v1/processrequest`;
    const stkRes = await axios.post(stkUrl, body, { headers: { Authorization: `Bearer ${token}` } });

    await wdRef.update({
      status: 'stk_sent',
      stkResponse: stkRes.data,
      checkoutRequestID: stkRes.data.CheckoutRequestID || null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    return { status: 'stk_sent', data: stkRes.data };
  } catch (err) {
    console.error('STK push error', err?.response?.data || err.message || err);
    await wdRef.update({ status: 'stk_error', error: err?.response?.data || String(err), updatedAt: admin.firestore.FieldValue.serverTimestamp() });
    throw new functions.https.HttpsError('internal','STK push failed');
  }
});

// 4) mpesaCallback (retain stub, but in sandbox it won't be called)
exports.mpesaCallback = functions.https.onRequest(async (req, res) => {
  try {
    const body = req.body;
    const checkoutId = body.Body?.stkCallback?.CheckoutRequestID;
    const resultCode = body.Body?.stkCallback?.ResultCode;
    // find withdrawal
    const q = await db.collection('withdrawals').where('checkoutRequestID','==', checkoutId).limit(1).get();
    if (!q.empty) {
      const wdRef = q.docs[0].ref;
      if (resultCode === 0) {
        const md = body.Body.stkCallback.CallbackMetadata?.Item?.reduce((acc,cur)=>{ acc[cur.Name]=cur.Value; return acc },{});
        await wdRef.update({
          status: 'completed',
          mpesaReceiptNumber: md?.MpesaReceiptNumber || null,
          mpesaResponse: body,
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
      } else {
        await wdRef.update({ status: 'failed', mpesaResponse: body, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      }
    } else {
      console.warn('mpesaCallback: no matching withdrawal for checkoutId', checkoutId);
    }
    return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  } catch (err) {
    console.error('mpesaCallback error', err);
    return res.json({ ResultCode: 1, ResultDesc: 'Error' });
  }
});

// 5) Admin: approveWithdrawal (callable by admin user only) — used in sandbox to simulate a successful payout
exports.approveWithdrawal = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated','Auth required');
  const requester = context.auth.token || {};
  if (!requester.admin) throw new functions.https.HttpsError('permission-denied','Admin only');

  const { wdId, mpesaReceiptNumber } = data;
  if (!wdId) throw new functions.https.HttpsError('invalid-argument','wdId required');

  const wdRef = db.collection('withdrawals').doc(wdId);
  const wdSnap = await wdRef.get();
  if (!wdSnap.exists) throw new functions.https.HttpsError('not-found','Withdrawal not found');
  const wd = wdSnap.data();

  // Mark completed and set a fake mpesa receipt if not provided
  const receipt = mpesaReceiptNumber || `SIM-${Date.now()}`;
  await wdRef.update({
    status: 'completed',
    mpesaReceiptNumber: receipt,
    mpesaResponse: { sandbox_simulation: true, simulatedBy: context.auth.uid, timestamp: admin.firestore.FieldValue.serverTimestamp() },
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  });

  await db.collection('securityLogs').add({ userId: wd.userId, type: 'manual_payout_approved', withdrawalId: wdId, adminUid: context.auth.uid, createdAt: admin.firestore.FieldValue.serverTimestamp() });

  return { message: 'Withdrawal approved (sandbox)', wdId, receipt };
});

// 6) Admin: rejectWithdrawal (optional)
exports.rejectWithdrawal = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated','Auth required');
  const requester = context.auth.token || {};
  if (!requester.admin) throw new functions.https.HttpsError('permission-denied','Admin only');

  const { wdId, reason } = data;
  if (!wdId) throw new functions.https.HttpsError('invalid-argument','wdId required');

  const wdRef = db.collection('withdrawals').doc(wdId);
  const wdSnap = await wdRef.get();
  if (!wdSnap.exists) throw new functions.https.HttpsError('not-found','Withdrawal not found');

  await wdRef.update({
    status: 'rejected',
    rejectionReason: reason || 'rejected_by_admin',
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  });

  await db.collection('securityLogs').add({ userId: wdSnap.data().userId, type: 'manual_payout_rejected', withdrawalId: wdId, adminUid: context.auth.uid, createdAt: admin.firestore.FieldValue.serverTimestamp() });

  return { message: 'Withdrawal rejected', wdId };
});<button class="finance-office-btn">
  FINANCE OFFICE 🚀
</button><button class="finance-office-btn"
        onclick="location.href='finance.html'">
  FINANCE OFFICE 🚀
</button>───────────────
 G.A.S PRIVATE PASS
───────────────
ID: BRICK-001
RANK: FOUNDER 👑
STATUS: ACTIVE
───────────────
Purpose. Profit. Power.<section style="background:black; color:white; padding:40px; text-align:center; font-family:Arial, sans-serif;">
  <h1 style="color:gold; font-size:42px; margin-bottom:10px;">Dollar DeLaRue™</h1>
  <h3 style="font-size:20px; color:white; margin-bottom:20px;">
    Where Digital Wealth Gets Minted 💸
  </h3>
  <p style="font-size:16px; max-width:600px; margin:auto; line-height:1.6;">
    We turn creativity into income. From digital asset packs to smart shopping rewards, 
    every click is another step towards financial freedom. Join the new wave of earners 
    who build wealth from anywhere.
  </p>
  <a href="#shop" style="background:gold; color:black; padding:14px 28px; display:inline-block; 
  font-size:18px; font-weight:bold; border-radius:5px; margin-top:20px; text-decoration:none;">
    Start Earning
  </a>
</section>
