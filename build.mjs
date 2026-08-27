#!/usr/bin/env node
// 여행 일정표 HTML을 AES-256-GCM으로 암호화해 index.html(비밀번호 게이트)로 빌드한다.
// 사용법: TRIP_PASSWORD='비밀번호' node build.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { randomBytes, pbkdf2Sync, createCipheriv } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const ITERATIONS = 300000;

const password = process.env.TRIP_PASSWORD;
if (!password) {
  console.error("TRIP_PASSWORD 환경변수가 필요합니다.  예) TRIP_PASSWORD='...' node build.mjs");
  process.exit(1);
}

const plaintext = readFileSync(join(ROOT, "source/trip.html"));
const salt = randomBytes(16);
const iv = randomBytes(12);
const key = pbkdf2Sync(Buffer.from(password, "utf8"), salt, ITERATIONS, 32, "sha256");

const cipher = createCipheriv("aes-256-gcm", key, iv);
const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

const payload = {
  v: 1,
  iterations: ITERATIONS,
  salt: salt.toString("base64"),
  iv: iv.toString("base64"),
  ct: ct.toString("base64"),
};

const template = readFileSync(join(ROOT, "gate.template.html"), "utf8");
const out = template.replace("__PAYLOAD__", JSON.stringify(payload));
if (out === template) throw new Error("템플릿에 __PAYLOAD__ 자리표시자가 없습니다.");

writeFileSync(join(ROOT, "index.html"), out);
console.log(`index.html 생성 완료 · 원본 ${plaintext.length}B → 암호문 ${ct.length}B · 총 ${out.length}B`);
