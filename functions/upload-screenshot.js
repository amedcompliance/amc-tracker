// Cloudflare Pages Function: /functions/upload-screenshot.js
// Handles screenshot uploads to R2 from the AMC Tracker frontend
// Credentials stored as Pages environment variables (not in code)

export async function onRequestPost(context) {
  const { request, env } = context;

  // CORS headers
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  try {
    const body = await request.json();
    const { imageData, userId, sessionId, timestamp } = body;

    if (!imageData || !imageData.startsWith('data:image/')) {
      return new Response(JSON.stringify({ error: 'Invalid image data' }), {
        status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Convert base64 dataUrl to binary
    const base64 = imageData.split(',')[1];
    const binaryStr = atob(base64);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);

    // Generate unique filename
    const ts = timestamp || Date.now();
    const fileName = `screenshots/uid_${userId || 'unknown'}/${sessionId || 'sess'}_${ts}.jpg`;

    // R2 credentials from environment variables
    const R2_ACCOUNT_ID = env.R2_ACCOUNT_ID;
    const R2_ACCESS_KEY_ID = env.R2_ACCESS_KEY_ID;
    const R2_SECRET_ACCESS_KEY = env.R2_SECRET_ACCESS_KEY;
    const R2_BUCKET = env.R2_BUCKET || 'amc-screenshots';
    const R2_PUBLIC_URL = env.R2_PUBLIC_URL || 'https://pub-a4e2d07f3868410181b72afe397c0020.r2.dev';

    const endpoint = `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
    const url = `${endpoint}/${R2_BUCKET}/${fileName}`;

    // AWS Signature V4 for R2 (S3-compatible)
    const method = 'PUT';
    const region = 'auto';
    const service = 's3';
    const now = new Date();
    const dateStr = now.toISOString().replace(/[:\-]|\..*/g, '').substring(0, 8);
    const datetimeStr = now.toISOString().replace(/[:\-]|\..*/g, '').substring(0, 15) + 'Z';

    const contentType = 'image/jpeg';
    const payloadHash = await sha256Hex(bytes);

    const canonicalHeaders = `content-type:${contentType}\nhost:${R2_ACCOUNT_ID}.r2.cloudflarestorage.com\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${datetimeStr}\n`;
    const signedHeaders = 'content-type;host;x-amz-content-sha256;x-amz-date';
    const canonicalRequest = [method, `/${R2_BUCKET}/${encodeURIComponent(fileName).replace(/%2F/g, '/')}`, '', canonicalHeaders, signedHeaders, payloadHash].join('\n');

    const credentialScope = `${dateStr}/${region}/${service}/aws4_request`;
    const stringToSign = `AWS4-HMAC-SHA256\n${datetimeStr}\n${credentialScope}\n${await sha256Hex(canonicalRequest)}`;

    const signingKey = await getSigningKey(R2_SECRET_ACCESS_KEY, dateStr, region, service);
    const signature = await hmacHex(signingKey, stringToSign);

    const authHeader = `AWS4-HMAC-SHA256 Credential=${R2_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const uploadResponse = await fetch(url, {
      method,
      headers: {
        'Authorization': authHeader,
        'Content-Type': contentType,
        'x-amz-content-sha256': payloadHash,
        'x-amz-date': datetimeStr,
      },
      body: bytes,
    });

    if (!uploadResponse.ok) {
      const errText = await uploadResponse.text();
      return new Response(JSON.stringify({ error: 'R2 upload failed', details: errText }), {
        status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const publicUrl = `${R2_PUBLIC_URL}/${fileName}`;
    return new Response(JSON.stringify({ url: publicUrl }), {
      status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });

  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

export async function onRequestOptions() {
  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    }
  });
}

// ── Crypto helpers ──────────────────────────────────────────────────
async function sha256Hex(data) {
  const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacHex(key, data) {
  const k = key instanceof CryptoKey ? key : await crypto.subtle.importKey('raw', typeof key === 'string' ? new TextEncoder().encode(key) : key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacKey(key, data) {
  const k = await crypto.subtle.importKey('raw', typeof key === 'string' ? new TextEncoder().encode(key) : key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const raw = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(data));
  return new Uint8Array(raw);
}

async function getSigningKey(secretKey, dateStr, region, service) {
  const kDate = await hmacKey('AWS4' + secretKey, dateStr);
  const kRegion = await hmacKey(kDate, region);
  const kService = await hmacKey(kRegion, service);
  const kSigning = await hmacKey(kService, 'aws4_request');
  return kSigning;
}
