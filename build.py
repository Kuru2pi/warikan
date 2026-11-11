import os, sys, base64, json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
src, out, pw = sys.argv[1], sys.argv[2], sys.argv[3]
html = open(src, 'rb').read()
# ソルトは固定（salt.txt）。変えると鍵が変わり、端末に記憶したパスワードと同期先の部屋がリセットされる
salt_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'salt.txt')
if not os.path.exists(salt_file):
    open(salt_file, 'w').write(base64.b64encode(os.urandom(16)).decode())
salt, iv, it = base64.b64decode(open(salt_file).read().strip()), os.urandom(12), 600000
key = PBKDF2HMAC(hashes.SHA256(), 32, salt, it).derive(pw.encode())
ct = AESGCM(key).encrypt(iv, html, None)
b = lambda x: base64.b64encode(x).decode()
payload = json.dumps({"s": b(salt), "i": b(iv), "n": it, "c": b(ct)})
page = '''<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0f312c">
<meta name="robots" content="noindex,nofollow">
<title>ワリカン帳</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#10372f;color:#fff;font:16px/1.6 -apple-system,BlinkMacSystemFont,"Hiragino Sans",sans-serif;padding:16px;box-sizing:border-box}
form{background:#fff;color:#16302b;border-radius:19px;padding:24px;width:min(360px,100%);box-sizing:border-box;box-shadow:0 15px 60px #0004}
h1{font-size:22px;margin:0 0 4px}p{font-size:13px;color:#65746d;margin:0 0 16px}
input[type=password]{width:100%;box-sizing:border-box;font:inherit;font-size:16px;padding:11px 12px;border:1px solid #d5e0d8;border-radius:10px;min-height:46px}
label.rem{display:flex;gap:8px;align-items:center;font-size:13px;color:#65746d;margin:12px 0 0}
button{margin-top:14px;width:100%;min-height:46px;border:0;border-radius:12px;background:#1b6955;color:#fff;font:inherit;font-weight:700}
.err{color:#ba4f44;font-size:13px;min-height:20px;margin-top:8px}
</style>
</head>
<body>
<form id="f"><h1>ワリカン帳</h1><p>パスワードを入力してください</p>
<input type="password" id="pw" autocomplete="current-password" required autofocus>
<label class="rem"><input type="checkbox" id="rem" checked>この端末で記憶する</label>
<button type="submit" id="go">開く</button><div class="err" id="err"></div></form>
<script>
const P=__PAYLOAD__,K='warikan_gate_key';
const d=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function open_(raw){const key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);
 window.__WARIKAN_KEY=raw;try{sessionStorage.setItem('warikan_key',btoa(String.fromCharCode(...raw)))}catch(e){}
 const buf=await crypto.subtle.decrypt({name:'AES-GCM',iv:d(P.i)},key,d(P.c));
 const html=new TextDecoder().decode(buf);document.open();document.write(html);document.close();}
async function derive(pw){const base=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveBits']);
 return new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt:d(P.s),iterations:P.n,hash:'SHA-256'},base,256));}
(async()=>{let saved=null;try{saved=localStorage.getItem(K)}catch(e){}
 if(saved){try{await open_(d(saved));return}catch(e){try{localStorage.removeItem(K)}catch(_){}}}})();
document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();const go=document.getElementById('go'),err=document.getElementById('err');
 go.disabled=true;go.textContent='確認中…';err.textContent='';
 try{const raw=await derive(document.getElementById('pw').value);
  const rem=document.getElementById('rem').checked;
  await crypto.subtle.decrypt({name:'AES-GCM',iv:d(P.i)},await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']),d(P.c));
  if(rem){try{localStorage.setItem(K,btoa(String.fromCharCode(...raw)))}catch(_){}}
  await open_(raw);
 }catch(x){err.textContent='パスワードが違います';go.disabled=false;go.textContent='開く'}});
</script>
</body>
</html>
'''.replace('__PAYLOAD__', payload)
open(out, 'w').write(page)
print(len(page))
