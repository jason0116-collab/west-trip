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

// 빌드 시점 환율을 폴백 값으로 굽는다. 브라우저에서 API 조회에 실패했을 때만 쓰인다.
async function fetchUsdKrw() {
  const sources = [
    ["https://open.er-api.com/v6/latest/USD", (j) => j?.rates?.KRW],
    ["https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/usd.json", (j) => j?.usd?.krw],
  ];
  for (const [url, pick] of sources) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
      if (!res.ok) continue;
      const rate = pick(await res.json());
      if (rate > 500 && rate < 3000) return Math.round(rate * 100) / 100;
    } catch {}
  }
  return null;
}

let source = readFileSync(join(ROOT, "source/trip.html"), "utf8");
const fxAnchor = /const FX_FALLBACK='[\d.]+',FX_FALLBACK_DATE='[^']*';/;
if (!fxAnchor.test(source)) throw new Error("source/trip.html 에서 FX_FALLBACK 앵커를 찾지 못했습니다.");

const rate = process.env.SKIP_FX ? null : await fetchUsdKrw();
if (rate) {
  const today = new Date().toISOString().slice(0, 10);
  source = source.replace(fxAnchor, `const FX_FALLBACK='${rate}',FX_FALLBACK_DATE='${today}';`);
  console.log(`폴백 환율 갱신 · 1 USD = ${rate.toLocaleString("ko-KR")}원 (${today})`);
} else {
  console.warn("환율 조회 실패 · source/trip.html 의 기존 폴백 값을 그대로 사용합니다.");
}

const plaintext = Buffer.from(source, "utf8");
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
