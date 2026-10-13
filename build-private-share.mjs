import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

const root = process.cwd();
const outputDirectory = path.join(root, 'birthday-wish-encrypted');
const iterations = 600_000;
const imageFiles = [
  'WhatsApp Image 2026-10-12 at 11.15.34 PM (1).jpeg',
  'WhatsApp Image 2026-10-12 at 11.15.34 PM.jpeg',
  'WhatsApp Image 2026-10-12 at 11.15.35 PM (1).jpeg',
  'WhatsApp Image 2026-10-12 at 11.15.35 PM.jpeg',
];

function readHidden(prompt) {
  return new Promise((resolve, reject) => {
    const input = process.stdin;
    if (!input.isTTY) {
      reject(new Error('Run this builder from an interactive terminal.'));
      return;
    }

    let value = '';
    process.stderr.write(prompt);
    input.setRawMode(true);
    input.resume();
    const onData = (chunk) => {
      for (const character of chunk.toString()) {
        if (character === '\u0003') {
          input.setRawMode(false);
          input.pause();
          input.off('data', onData);
          reject(new Error('Passphrase entry cancelled.'));
          return;
        }
        if (character === '\r' || character === '\n') {
          input.setRawMode(false);
          input.pause();
          input.off('data', onData);
          process.stderr.write('\n');
          resolve(value);
          return;
        }
        if (character === '\u007f' || character === '\b') {
          value = value.slice(0, -1);
          continue;
        }
        value += character;
      }
    };
    input.on('data', onData);
  });
}

const passphrase = await readHidden('Enter a strong passphrase (at least 20 characters; input is hidden): ');
const confirmation = await readHidden('Enter it again to confirm: ');
if (passphrase !== confirmation) throw new Error('The passphrases did not match.');
if (passphrase.length < 20) throw new Error('Use a passphrase of at least 20 characters.');

let html = await readFile(path.join(root, 'birthday_gift_website(2).html'), 'utf8');
html = html.replaceAll('encodeURI(photo.file)', 'photo.file');
for (const file of imageFiles) {
  const image = await readFile(path.join(root, file));
  const dataUrl = `data:image/jpeg;base64,${image.toString('base64')}`;
  html = html.replaceAll(encodeURI(file), dataUrl).replaceAll(file, dataUrl);
}

const salt = randomBytes(16);
const iv = randomBytes(12);
const key = pbkdf2Sync(passphrase, salt, iterations, 32, 'sha256');
const cipher = createCipheriv('aes-256-gcm', key, iv);
const encrypted = Buffer.concat([
  cipher.update(JSON.stringify({ html }), 'utf8'),
  cipher.final(),
  cipher.getAuthTag(),
]);
const payload = {
  version: 1,
  iterations,
  salt: salt.toString('base64'),
  iv: iv.toString('base64'),
  ciphertext: encrypted.toString('base64'),
};

const unlockPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>A Birthday Surprise</title>
<style>
*{box-sizing:border-box}body{min-height:100svh;margin:0;display:grid;place-items:center;padding:24px;background:radial-gradient(ellipse at 50% 0%,#342455,#17122f 55%,#100d27);color:#fff9f4;font:16px/1.6 system-ui,sans-serif}.gate{width:min(440px,100%);padding:36px;border:1px solid #ffffff30;border-radius:22px;background:#ffffff0c;box-shadow:0 24px 80px #06041280;text-align:center}.mark{font-size:2.5rem;color:#ffe4a3}h1{margin:10px 0;font-family:Georgia,serif;font-size:2rem}p{color:#c6bfdc}form{display:grid;gap:12px;margin-top:24px;text-align:left}label{font-size:.9rem}input,button{min-height:48px;border-radius:10px;font:inherit}input{width:100%;padding:10px 13px;border:1px solid #ffffff40;background:#100d27;color:#fff9f4}input:focus-visible,button:focus-visible{outline:3px solid #ffe4a3;outline-offset:3px}button{border:0;background:linear-gradient(105deg,#ffe4a3,#ffb9d0);color:#271a3b;font-weight:700;cursor:pointer}button:disabled{opacity:.65;cursor:wait}#status{min-height:26px;margin:14px 0 0;color:#ffe4a3;font-size:.9rem}
</style>
</head>
<body>
<main class="gate">
<div class="mark" aria-hidden="true">✦</div>
<h1>A birthday surprise</h1>
<p>This private gift is waiting for you. Enter the passphrase Deepak shared with you.</p>
<form id="unlock-form">
<label for="passphrase">Passphrase</label>
<input id="passphrase" type="password" autocomplete="current-password" required autofocus>
<button id="unlock" type="submit">Unlock the surprise</button>
</form>
<p id="status" role="status" aria-live="polite"></p>
</main>
<script>
const decode=value=>Uint8Array.from(atob(value),character=>character.charCodeAt(0));
document.getElementById('unlock-form').addEventListener('submit',async event=>{
 event.preventDefault();
 const input=document.getElementById('passphrase');
 const button=document.getElementById('unlock');
 const status=document.getElementById('status');
 button.disabled=true;status.textContent='Unlocking your surprise…';
 try{
  const payload=await fetch('./payload.enc',{cache:'no-store'}).then(response=>{if(!response.ok)throw new Error('The gift is temporarily unavailable.');return response.json()});
  const keyMaterial=await crypto.subtle.importKey('raw',new TextEncoder().encode(input.value),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:decode(payload.salt),iterations:payload.iterations,hash:'SHA-256'},keyMaterial,{name:'AES-GCM',length:256},false,['decrypt']);
  const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:decode(payload.iv),tagLength:128},key,decode(payload.ciphertext));
  const content=JSON.parse(new TextDecoder().decode(plain));
  document.open();document.write(content.html);document.close();
 }catch(error){status.textContent=error.name==='OperationError'?'That passphrase did not unlock the surprise. Try again.':error.message;input.value='';input.focus();button.disabled=false;}
});
</script>
</body>
</html>`;

await mkdir(outputDirectory, { recursive: true });
await writeFile(path.join(outputDirectory, 'index.html'), unlockPage, { mode: 0o644 });
await writeFile(path.join(outputDirectory, 'payload.enc'), JSON.stringify(payload), { mode: 0o644 });
process.stdout.write(`Encrypted site generated in ${path.basename(outputDirectory)}.\n`);
process.stdout.write('Only index.html and payload.enc belong in the public deployment repository.\n');
process.stdout.write('Share the passphrase with your friend separately; it was not saved by this builder.\n');
