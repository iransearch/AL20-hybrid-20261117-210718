import assert from 'node:assert/strict';
import {spawn, execFileSync} from 'node:child_process';
import {createHash, randomBytes} from 'node:crypto';
import {once} from 'node:events';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {setTimeout as delay} from 'node:timers/promises';
import {fileURLToPath} from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const renderHost = 'gateway-test.onrender.com';
const customHost = 'vpn.example.test';

function request(port, host, url = '/', body = undefined) {
  return new Promise((resolve, reject) => {
    const req = http.request({hostname: '127.0.0.1', port, path: url,
      method: body === undefined ? 'GET' : 'POST', agent: false,
      headers: {host, ...(body === undefined ? {} : {'content-length': Buffer.byteLength(body)})}}, res => {
      let data = '';
      res.setEncoding('utf8'); res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolve({status: res.statusCode, body: data}));
      res.on('error', reject);
    });
    req.setTimeout(2000, () => req.destroy(new Error('HTTP test timeout')));
    req.on('error', reject); req.end(body);
  });
}

function websocket(port, host) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from('render-alias-ping');
    const req = http.request({hostname: '127.0.0.1', port, path: '/', agent: false,
      headers: {host, connection: 'Upgrade', upgrade: 'websocket',
        'sec-websocket-version': '13', 'sec-websocket-key': randomBytes(16).toString('base64')}});
    req.setTimeout(2000, () => req.destroy(new Error('Upgrade test timeout')));
    req.on('error', reject);
    req.on('response', res => { res.resume(); res.on('end', () => resolve({status: res.statusCode})); });
    req.on('upgrade', (res, socket, head) => {
      let buffered = head;
      socket.setTimeout(2000, () => socket.destroy(new Error('Pong test timeout')));
      socket.on('error', reject);
      socket.on('data', data => {
        buffered = Buffer.concat([buffered, data]);
        if (buffered.length < payload.length + 2) return;
        try {
          assert.equal(buffered[0], 0x8a);
          assert.equal(buffered[1], payload.length);
          assert.deepEqual(buffered.subarray(2, payload.length + 2), payload);
          resolve({status: res.statusCode, pong: true});
        } catch (error) { reject(error); }
        finally { socket.destroy(); }
      });
      const mask = randomBytes(4);
      socket.write(Buffer.concat([Buffer.from([0x89, 0x80 | payload.length]), mask,
        Buffer.from(payload.map((value, index) => value ^ mask[index % 4]))]));
    });
    req.end();
  });
}

test('Render hostname routing through real HTTP and TLS WebSocket relays', {timeout: 30000}, async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ren-render-host-test-'));
  const cert = path.join(dir, 'origin.pem'), key = path.join(dir, 'origin.key');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=origin.test', '-addext', 'subjectAltName=DNS:origin.test',
    '-keyout', key, '-out', cert], {stdio: 'ignore'});
  const origins = [], children = [];
  t.after(async () => {
    for (const child of children) {
      if (child.exitCode !== null || child.signalCode !== null) continue;
      const exited = once(child, 'exit'); child.kill('SIGTERM');
      const killer = setTimeout(() => child.kill('SIGKILL'), 2000).unref();
      await exited; clearTimeout(killer);
    }
    for (const origin of origins) {
      for (const socket of origin.sockets) socket.destroy();
      await new Promise(resolve => origin.server.close(resolve));
    }
    fs.rmSync(dir, {recursive: true, force: true});
  });

  async function origin(name) {
    const calls = [], sockets = new Set();
    const server = https.createServer({key: fs.readFileSync(key), cert: fs.readFileSync(cert)}, (req, res) => {
      let body = '';
      req.on('data', data => { body += data; });
      req.on('end', () => {
        const result = {name, host: req.headers.host, sni: req.socket.servername,
          method: req.method, path: req.url, body};
        calls.push(result);
        res.writeHead(200, {'content-type': 'application/json'}); res.end(JSON.stringify(result));
      });
    });
    server.on('upgrade', (req, socket) => {
      calls.push({name, websocket: true, host: req.headers.host, sni: req.socket.servername});
      const accept = createHash('sha1').update(req.headers['sec-websocket-key'] +
        '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
      socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
      let buffered = Buffer.alloc(0);
      socket.on('data', data => {
        buffered = Buffer.concat([buffered, data]);
        if (buffered.length < 6) return;
        const length = buffered[1] & 127;
        if (buffered.length < 6 + length) return;
        const mask = buffered.subarray(2, 6), payload = buffered.subarray(6, 6 + length);
        const clear = Buffer.from(payload.map((value, index) => value ^ mask[index % 4]));
        socket.write(Buffer.concat([Buffer.from([0x8a, clear.length]), clear]));
        buffered = buffered.subarray(6 + length);
      });
      socket.on('error', () => {});
    });
    server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const result = {server, sockets, calls, port: server.address().port}; origins.push(result); return result;
  }

  const first = await origin('first'), second = await origin('second');
  const route = (domain, target = first) => ({domain, origin_ip: '127.0.0.1',
    origin_sni: 'origin.test', origin_port: target.port});
  async function gateway(routes, external = renderHost, {legacy = false, workers = 1} = {}) {
    const reserved = net.createServer(); reserved.listen(0, '127.0.0.1'); await once(reserved, 'listening');
    const port = reserved.address().port; await new Promise(resolve => reserved.close(resolve));
    const configPath = path.join(dir, `settings-${port}.json`);
    fs.writeFileSync(configPath, JSON.stringify({routes, legacy, port, ca_file: cert, metrics_port: 9,
      origin_enabled: true, max_concurrent: 0, connect_timeout: 2, http_read_timeout: 3,
      ws_handshake_timeout: 3, tunnel_idle_timeout: 3, stats_interval: 60, error_logs: false,
      workers, ready_file: path.join(dir, `ready-${port}`)}));
    const child = spawn(process.execPath, [path.join(root, workers === 1 ? 'node_runtime.mjs' : 'node_cluster.mjs'), configPath],
      {env: {...process.env, RENDER_EXTERNAL_HOSTNAME: external, REN_NODE_CLUSTER: '0'}, stdio: ['ignore', 'ignore', 'pipe']});
    children.push(child); let errors = '';
    child.stderr.on('data', data => { errors = (errors + data).slice(-8192); });
    for (let attempt = 0; attempt < 100; attempt++) {
      if (child.exitCode !== null) throw new Error(`Gateway exited: ${errors}`);
      try { if ((await request(port, 'health.test', '/_ren/health')).status === 200) return port; } catch {}
      await delay(20);
    }
    throw new Error(`Gateway readiness timeout: ${errors}`);
  }

  const single = await gateway([route(customHost)]);
  await t.test('official hostname forwards POST, encoded path and body with verified origin SNI', async () => {
    const result = await request(single, renderHost.toUpperCase() + '.:443', '/a%2Fb?x=a%2Bb', 'test payload');
    assert.equal(result.status, 200);
    assert.deepEqual(JSON.parse(result.body), {name: 'first', host: `origin.test:${first.port}`,
      sni: 'origin.test', method: 'POST', path: '/a%2Fb?x=a%2Bb', body: 'test payload'});
  });
  await t.test('official hostname upgrades and passes WebSocket ping/pong', async () => {
    assert.deepEqual(await websocket(single, renderHost), {status: 101, pong: true});
  });
  await t.test('configured custom hostname continues to work for HTTP and WebSocket', async () => {
    assert.equal((await request(single, customHost)).status, 200);
    assert.deepEqual(await websocket(single, customHost), {status: 101, pong: true});
  });
  await t.test('unrelated hostnames stay rejected before any origin request', async () => {
    const before = first.calls.length;
    for (const host of ['other.onrender.com', `${renderHost}.attacker.test`, 'unknown.example.test']) {
      assert.equal((await request(single, host)).status, 421);
      assert.equal((await websocket(single, host)).status, 421);
    }
    assert.equal(first.calls.length, before);
  });
  await t.test('multiple configured destinations require explicit custom hostnames', async () => {
    const port = await gateway([route(customHost), route('second.example.test', second)]);
    assert.equal((await request(port, renderHost)).status, 421);
    assert.equal((await websocket(port, renderHost)).status, 421);
    assert.equal(JSON.parse((await request(port, customHost)).body).name, 'first');
    assert.equal(JSON.parse((await request(port, 'second.example.test')).body).name, 'second');
    assert.deepEqual(await websocket(port, 'second.example.test'), {status: 101, pong: true});
  });
  await t.test('missing Render hostname does not enable a wildcard default', async () => {
    const port = await gateway([route(customHost)], '');
    assert.equal((await request(port, renderHost)).status, 421);
    assert.equal((await websocket(port, renderHost)).status, 421);
    assert.equal((await request(port, customHost)).status, 200);
  });
  await t.test('legacy single-origin routing is preserved', async () => {
    const port = await gateway([route('_')], renderHost, {legacy: true});
    assert.equal((await request(port, 'legacy.example.test')).status, 200);
    assert.deepEqual(await websocket(port, 'legacy.example.test'), {status: 101, pong: true});
  });
  await t.test('cluster workers inherit the official hostname alias', async () => {
    const port = await gateway([route(customHost)], renderHost, {workers: 2});
    assert.equal((await request(port, renderHost)).status, 200);
    assert.deepEqual(await websocket(port, renderHost), {status: 101, pong: true});
  });
});
