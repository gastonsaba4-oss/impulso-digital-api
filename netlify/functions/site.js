const { getStore, connectLambda } = require('@netlify/blobs');
const crypto = require('crypto');

const INDEX_KEY = '__index__';

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-admin-key',
    'Content-Type': 'application/json'
  };
}

function makeSalt() {
  return crypto.randomBytes(16).toString('hex');
}

function hashPass(pass, salt) {
  return crypto.scryptSync(String(pass || ''), salt, 64).toString('hex');
}

function safeEqual(a, b) {
  const bufA = Buffer.from(a || '', 'utf8');
  const bufB = Buffer.from(b || '', 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function checkAdmin(event) {
  const adminKey = event.headers['x-admin-key'] || event.headers['X-Admin-Key'];
  return !!process.env.ADMIN_KEY && adminKey === process.env.ADMIN_KEY;
}

exports.handler = async (event) => {
  connectLambda(event);
  const store = getStore('impulso-sites');

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: corsHeaders(), body: '' };
  }

  // ---------- GET ----------
  if (event.httpMethod === 'GET') {
    const qs = event.queryStringParameters || {};

    // listado de clientes, protegido con la clave admin (lo usa el panel)
    if (qs.list === '1') {
      if (!checkAdmin(event)) {
        return { statusCode: 401, headers: corsHeaders(), body: JSON.stringify({ error: 'No autorizado' }) };
      }
      const index = (await store.get(INDEX_KEY, { type: 'json' })) || [];
      return { statusCode: 200, headers: corsHeaders(), body: JSON.stringify({ clients: index }) };
    }

    // datos públicos de una página (lo usa page.html)
    const id = qs.id;
    if (!id) {
      return { statusCode: 400, headers: corsHeaders(), body: JSON.stringify({ error: 'Falta id' }) };
    }
    const record = await store.get(id, { type: 'json' });
    if (!record) {
      return { statusCode: 200, headers: corsHeaders(), body: JSON.stringify({ found: false }) };
    }
    return { statusCode: 200, headers: corsHeaders(), body: JSON.stringify({ found: true, data: record.data || {} }) };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: corsHeaders(), body: JSON.stringify({ error: 'Método no permitido' }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch (e) {
    return { statusCode: 400, headers: corsHeaders(), body: JSON.stringify({ error: 'JSON inválido' }) };
  }

  const { id, action } = body;
  if (!id || !action) {
    return { statusCode: 400, headers: corsHeaders(), body: JSON.stringify({ error: 'Faltan datos' }) };
  }

  // ---------- CREAR / ACTUALIZAR una página (la llama el panel) ----------
  if (action === 'create') {
    if (!checkAdmin(event)) {
      return { statusCode: 401, headers: corsHeaders(), body: JSON.stringify({ error: 'No autorizado' }) };
    }
    const existing = await store.get(id, { type: 'json' });
    const salt = existing ? existing.salt : makeSalt();
    const record = {
      user: body.user || (existing && existing.user) || 'cliente',
      salt: salt,
      passHash: body.pass ? hashPass(body.pass, salt) : (existing ? existing.passHash : hashPass('clave123', salt)),
      data: Object.assign({}, existing ? existing.data : {}, body.data || {})
    };
    await store.setJSON(id, record);

    // actualizamos el índice para que el panel pueda listar clientes
    const index = (await store.get(INDEX_KEY, { type: 'json' })) || [];
    const i = index.findIndex(function (c) { return c.id === id; });
    const entry = {
      id: id,
      businessName: record.data.businessName || '',
      template: record.data.template || 1,
      pageType: record.data.pageType || 'producto'
    };
    if (i >= 0) { index[i] = entry; } else { index.push(entry); }
    await store.setJSON(INDEX_KEY, index);

    return { statusCode: 200, headers: corsHeaders(), body: JSON.stringify({ ok: true }) };
  }

  // ---------- ELIMINAR una página (la llama el panel) ----------
  if (action === 'delete') {
    if (!checkAdmin(event)) {
      return { statusCode: 401, headers: corsHeaders(), body: JSON.stringify({ error: 'No autorizado' }) };
    }
    await store.delete(id);
    const index = (await store.get(INDEX_KEY, { type: 'json' })) || [];
    await store.setJSON(INDEX_KEY, index.filter(function (c) { return c.id !== id; }));
    return { statusCode: 200, headers: corsHeaders(), body: JSON.stringify({ ok: true }) };
  }

  // ---------- LOGIN / GUARDAR (las llama la página del cliente) ----------
  if (action === 'login' || action === 'save') {
    const record = await store.get(id, { type: 'json' });
    if (!record) {
      return { statusCode: 404, headers: corsHeaders(), body: JSON.stringify({ error: 'No existe esa página' }) };
    }
    const okUser = body.user === record.user;
    const okPass = safeEqual(hashPass(body.pass, record.salt), record.passHash);
    if (!okUser || !okPass) {
      return { statusCode: 401, headers: corsHeaders(), body: JSON.stringify({ ok: false, error: 'Usuario o contraseña incorrectos' }) };
    }
    if (action === 'login') {
      return { statusCode: 200, headers: corsHeaders(), body: JSON.stringify({ ok: true, data: record.data || {} }) };
    }
    record.data = Object.assign({}, record.data, body.data || {});
    await store.setJSON(id, record);

    // si cambió el nombre del negocio, reflejarlo en el índice
    if (body.data && body.data.businessName !== undefined) {
      const index = (await store.get(INDEX_KEY, { type: 'json' })) || [];
      const i = index.findIndex(function (c) { return c.id === id; });
      if (i >= 0) { index[i].businessName = body.data.businessName; await store.setJSON(INDEX_KEY, index); }
    }

    return { statusCode: 200, headers: corsHeaders(), body: JSON.stringify({ ok: true }) };
  }

  return { statusCode: 400, headers: corsHeaders(), body: JSON.stringify({ error: 'Acción inválida' }) };
};
