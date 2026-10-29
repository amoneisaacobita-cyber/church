import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

test("Node backend serves frontend and preserves authenticated church workflows", async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "lfc-node-test-"));
  const port = 18000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, ["server.js"], {
    cwd: path.dirname(fileURLToPath(import.meta.url)),
    env: { ...process.env, LFC_PORT: String(port), LFC_DATA_DIR: dataDir, LFC_HOST: "127.0.0.1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk.toString(); });
  child.stderr.on("data", (chunk) => { output += chunk.toString(); });
  t.after(async () => {
    child.kill("SIGTERM");
    await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 3000))]);
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  const origin = `http://127.0.0.1:${port}`;
  let statusResponse;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Backend exited early:\n${output}`);
    try {
      statusResponse = await fetch(`${origin}/api/status`);
      break;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  assert.ok(statusResponse, `Backend did not start:\n${output}`);
  assert.equal(statusResponse.status, 200);
  assert.equal((await statusResponse.json()).setup_required, true);

  const html = await fetch(origin);
  assert.equal(html.status, 200);
  assert.match(await html.text(), /Life Fountain Church/);

  const setupCode = output.match(/First-time admin setup code .*: ([^\r\n]+)/)?.[1];
  assert.ok(setupCode, `Setup code not printed:\n${output}`);
  const setup = await fetch(`${origin}/api/setup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      setup_code: setupCode,
      name: "Test Admin",
      email: "admin@example.test",
      password: "A-secure-test-password",
    }),
  });
  assert.equal(setup.status, 201);
  const adminUser = (await setup.json()).user;
  const sessionCookie = setup.headers.getSetCookie().find((cookie) => cookie.startsWith("lfc_session="));
  assert.ok(sessionCookie);
  const cookie = sessionCookie.split(";", 1)[0];

  const pastor = await fetch(`${origin}/api/pastors`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({
      name: "Test Pastor",
      email: "pastor@example.test",
      password: "A-secure-pastor-password",
    }),
  });
  assert.equal(pastor.status, 201);
  assert.equal((await pastor.json()).role, "pastor");

  const profileUpdate = await fetch(`${origin}/api/church-profile`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({
      name: "Life Fountain Church",
      leader: "Test Leader",
      phone: "",
      email: "",
      address: "",
      about: "",
      latitude: "",
      longitude: "",
    }),
  });
  assert.equal(profileUpdate.status, 200);

  const upload = await fetch(`${origin}/api/sermon-uploads`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({
      filename: "short-test.mp4",
      mime_type: "video/mp4",
      file_size: 3,
      title: "Short test sermon",
    }),
  });
  assert.equal(upload.status, 201);
  const uploadState = await upload.json();
  const chunk = await fetch(`${origin}/api/sermon-uploads/${uploadState.id}/chunk`, {
    method: "POST",
    headers: {
      "Content-Type": "video/mp4",
      "X-Upload-Offset": "0",
      Cookie: cookie,
    },
    body: Buffer.from([1, 2, 3]),
  });
  assert.equal(chunk.status, 200);
  assert.equal((await chunk.json()).uploaded_bytes, 3);

  const staleChunk = await fetch(`${origin}/api/sermon-uploads/${uploadState.id}/chunk`, {
    method: "POST",
    headers: {
      "Content-Type": "video/mp4",
      "X-Upload-Offset": "0",
      Cookie: cookie,
    },
    body: Buffer.from([1, 2, 3]),
  });
  assert.equal(staleChunk.status, 409);

  const verses = await fetch(`${origin}/api/verses`);
  assert.equal(verses.status, 200);
  assert.deepEqual(await verses.json(), []);
  assert.equal(adminUser.role, "admin");
});
