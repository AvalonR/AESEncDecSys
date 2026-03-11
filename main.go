package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// ── Key derivation ────────────────────────────────────────────────────────────

func deriveKey(password string, keyBytes int) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:keyBytes]
}

// ── PKCS#7 padding ────────────────────────────────────────────────────────────

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	padding := make([]byte, pad)
	for i := range padding {
		padding[i] = byte(pad)
	}
	return append(data, padding...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	n := len(data)
	if n == 0 || n%blockSize != 0 {
		return nil, errors.New("invalid padded data length")
	}
	pad := int(data[n-1])
	if pad == 0 || pad > blockSize {
		return nil, errors.New("invalid padding value")
	}
	for _, b := range data[n-pad:] {
		if int(b) != pad {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}
	return data[:n-pad], nil
}

// ── ECB (omitted from stdlib intentionally — implement manually) ──────────────

func ecbEncrypt(block cipher.Block, src []byte) []byte {
	bs := block.BlockSize()
	dst := make([]byte, len(src))
	for i := 0; i < len(src); i += bs {
		block.Encrypt(dst[i:i+bs], src[i:i+bs])
	}
	return dst
}

func ecbDecrypt(block cipher.Block, src []byte) []byte {
	bs := block.BlockSize()
	dst := make([]byte, len(src))
	for i := 0; i < len(src); i += bs {
		block.Decrypt(dst[i:i+bs], src[i:i+bs])
	}
	return dst
}

// ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

type encryptResult struct {
	Ciphertext []byte
	IV         []byte // nil for ECB
}

func encrypt(plaintext, key []byte, mode string) (*encryptResult, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	switch mode {
	case "ECB":
		padded := pkcs7Pad(plaintext, aes.BlockSize)
		return &encryptResult{Ciphertext: ecbEncrypt(block, padded)}, nil
	case "CBC":
		padded := pkcs7Pad(plaintext, aes.BlockSize)
		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		ct := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
		return &encryptResult{Ciphertext: ct, IV: iv}, nil
	case "CFB":
		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		ct := make([]byte, len(plaintext))
		cipher.NewCFBEncrypter(block, iv).XORKeyStream(ct, plaintext)
		return &encryptResult{Ciphertext: ct, IV: iv}, nil
	default:
		return nil, errors.New("unsupported mode: " + mode)
	}
}

func decrypt(ciphertext, key, iv []byte, mode string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	switch mode {
	case "ECB":
		if len(ciphertext)%aes.BlockSize != 0 {
			return nil, errors.New("ciphertext must be a multiple of 16 bytes")
		}
		pt := ecbDecrypt(block, ciphertext)
		return pkcs7Unpad(pt, aes.BlockSize)
	case "CBC":
		if len(ciphertext)%aes.BlockSize != 0 {
			return nil, errors.New("ciphertext must be a multiple of 16 bytes")
		}
		if len(iv) != aes.BlockSize {
			return nil, errors.New("CBC requires a 16-byte IV")
		}
		pt := make([]byte, len(ciphertext))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ciphertext)
		return pkcs7Unpad(pt, aes.BlockSize)
	case "CFB":
		if len(iv) != aes.BlockSize {
			return nil, errors.New("CFB requires a 16-byte IV")
		}
		pt := make([]byte, len(ciphertext))
		cipher.NewCFBDecrypter(block, iv).XORKeyStream(pt, ciphertext)
		return pt, nil
	default:
		return nil, errors.New("unsupported mode: " + mode)
	}
}

// ── Ciphertext file format ────────────────────────────────────────────────────

// ciphertextFile is written to / read from the .txt file.
// Embedding mode and key_size means decryption only ever needs the key.
type ciphertextFile struct {
	Mode       string `json:"mode"`
	KeySize    int    `json:"key_size"`
	IV         string `json:"iv,omitempty"`
	Ciphertext string `json:"ciphertext"`
}

// ── Page model ────────────────────────────────────────────────────────────────

type PageData struct {
	// Which tab is active
	Operation string // "encrypt" | "decrypt"

	// Shared inputs (always visible)
	Key string

	// Encrypt-side inputs
	Plaintext string
	Mode      string
	KeySize   string

	// Decrypt-side source toggle
	DecryptSource string // "paste" | "manual" | "file"
	PastedCipher  string // paste tab: full JSON

	// Manual decrypt inputs
	ManualMode       string // ECB | CBC | CFB
	ManualKeySize    string // 128 | 192 | 256
	ManualCiphertext string // base64 ciphertext
	ManualIV         string // base64 IV (CBC/CFB only)

	// Decode metadata shown after successful decrypt
	DecodedMode    string
	DecodedKeySize string

	// Output
	Result          string
	DownloadPayload string // base64 JSON for /download
	Error           string
}

// ── Template ──────────────────────────────────────────────────────────────────

var indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>AES Encryption Tool</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg:#0f1117; --surface:#1a1d27; --surface2:#20243a; --border:#2e3146;
      --accent:#5c6ef8; --accent-h:#7080fa; --text:#e2e4f0; --muted:#7a7f9a;
      --err-bg:#2d1a1a; --err-b:#7f2f2f; --err-t:#f87171;
      --ok-bg:#1a2d22; --ok-b:#2f7f50; --ok-t:#6ee7a0;
    }
    body { background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; font-size:15px; line-height:1.6; padding:2rem 1rem 4rem; }
    .container { max-width:800px; margin:0 auto; display:flex; flex-direction:column; gap:1.25rem; }

    /* header */
    header { text-align:center; padding:1rem 0 0.5rem; }
    header h1 { font-size:1.9rem; font-weight:700; letter-spacing:-0.5px; }
    .subtitle { color:var(--muted); font-size:0.9rem; margin-top:0.3rem; }

    /* cards */
    .card { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:1.25rem 1.5rem; }
    .card h2 { font-size:0.75rem; text-transform:uppercase; letter-spacing:0.08em; color:var(--muted); margin-bottom:0.8rem; }

    /* operation tabs */
    .op-tabs { display:flex; gap:0; border:1px solid var(--border); border-radius:10px; overflow:hidden; }
    .op-tab { flex:1; padding:0.75rem 1rem; text-align:center; font-size:0.95rem; font-weight:600; cursor:pointer; background:var(--surface); color:var(--muted); border:none; transition:background 0.15s, color 0.15s; }
    .op-tab.active { background:var(--accent); color:#fff; }
    .op-tab:first-child { border-right:1px solid var(--border); }

    /* radio pills */
    .radio-group { display:flex; gap:0.5rem; flex-wrap:wrap; }
    .radio-pill { display:inline-flex; align-items:center; padding:0.4rem 1rem; border-radius:999px; border:1px solid var(--border); cursor:pointer; font-size:0.9rem; transition:border-color 0.15s, background 0.15s, color 0.15s; user-select:none; }
    .radio-pill input[type="radio"] { display:none; }
    .radio-pill:hover { border-color:var(--accent); color:var(--accent); }
    .radio-pill.active { background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600; }

    /* settings row */
    .settings-row { display:flex; gap:2rem; flex-wrap:wrap; }
    .setting-group { flex:1; min-width:180px; }

    /* inputs */
    input[type="text"], textarea {
      width:100%; background:#12141e; border:1px solid var(--border); border-radius:6px;
      color:var(--text); font-family:inherit; font-size:0.95rem;
      padding:0.6rem 0.85rem; outline:none; resize:vertical; transition:border-color 0.15s;
    }
    input[type="text"]:focus, textarea:focus { border-color:var(--accent); }
    textarea { min-height:130px; }
    textarea[readonly] {
      background:#0d0f17; color:#a0f0c0;
      font-family:'Cascadia Code','Fira Mono',monospace; font-size:0.85rem; min-height:180px;
    }
    .hint { color:var(--muted); font-size:0.8rem; margin-top:0.45rem; }

    /* source toggle (paste vs file) */
    .source-tabs { display:flex; gap:0; border:1px solid var(--border); border-radius:8px; overflow:hidden; margin-bottom:0.85rem; width:fit-content; }
    .source-tab { padding:0.35rem 1rem; font-size:0.85rem; font-weight:600; cursor:pointer; background:var(--surface); color:var(--muted); border:none; transition:background 0.15s, color 0.15s; }
    .source-tab.active { background:var(--accent); color:#fff; }
    .source-tab:not(:last-child) { border-right:1px solid var(--border); }

    /* file drop zone */
    .drop-zone {
      border:2px dashed var(--border); border-radius:8px; padding:2.5rem 1rem;
      min-height:140px; display:flex; flex-direction:column; align-items:center; justify-content:center;
      text-align:center; cursor:pointer; transition:border-color 0.15s, background 0.15s;
      color:var(--muted); font-size:0.9rem;
    }
    .drop-zone:hover, .drop-zone.dragover { border-color:var(--accent); background:#14162a; color:var(--accent); }
    .drop-zone input[type="file"] { display:none; }
    .drop-zone .file-icon { font-size:2rem; display:block; margin-bottom:0.4rem; }
    .drop-zone .file-name { margin-top:0.5rem; font-size:0.85rem; color:var(--ok-t); font-weight:600; }

    /* decoded badge */
    .badge-row { display:flex; gap:0.5rem; flex-wrap:wrap; margin-bottom:0.75rem; }
    .badge { display:inline-block; padding:0.2rem 0.65rem; border-radius:999px; font-size:0.78rem; font-weight:600; background:var(--surface2); border:1px solid var(--border); color:var(--muted); }

    /* buttons */
    .btn-primary { width:100%; border:none; border-radius:8px; cursor:pointer; font-size:1rem; font-weight:600; padding:0.7rem 2rem; background:var(--accent); color:#fff; transition:background 0.15s; }
    .btn-primary:hover { background:var(--accent-h); }
    .btn-secondary { display:inline-block; border:1px solid var(--accent); border-radius:8px; cursor:pointer; font-size:0.9rem; font-weight:600; padding:0.5rem 1.25rem; background:transparent; color:var(--accent); margin-top:0.75rem; transition:background 0.15s; }
    .btn-secondary:hover { background:var(--accent); color:#fff; }

    /* alert */
    .alert { padding:0.85rem 1.25rem; border-radius:10px; font-size:0.9rem; }
    .alert.error { background:var(--err-bg); border:1px solid var(--err-b); color:var(--err-t); }

    /* info panel */
    details { background:var(--surface); border:1px solid var(--border); border-radius:10px; }
    details summary { padding:1rem 1.5rem; cursor:pointer; font-size:0.9rem; color:var(--muted); user-select:none; list-style:none; }
    details summary::before { content:'▶  '; font-size:0.7rem; }
    details[open] summary::before { content:'▼  '; }
    .info-body { padding:0 1.5rem 1.25rem; display:flex; flex-direction:column; gap:1rem; }
    .info-body h3 { font-size:0.95rem; color:var(--accent); margin-bottom:0.2rem; }
    .info-body p, .info-body dd { color:var(--muted); font-size:0.88rem; }
    .info-body ul, .info-body dl { padding-left:1.1rem; }
    .info-body li { color:var(--muted); font-size:0.88rem; margin-bottom:0.15rem; }
    .info-body dt { font-weight:600; margin-top:0.5rem; font-size:0.9rem; }
    .info-body dd { margin-left:1rem; }

    /* hidden */
    .hidden { display:none !important; }
  </style>
</head>
<body>
<div class="container">
  <header>
    <h1>AES Encryption &amp; Decryption</h1>
    <p class="subtitle">AES-128 / 192 / 256 &nbsp;·&nbsp; ECB / CBC / CFB</p>
  </header>

  <form id="mainForm" method="POST" action="/process" enctype="multipart/form-data">

    <!-- ── Operation tabs ───────────────────────────────────────────── -->
    <div class="op-tabs" style="margin-bottom:1.25rem">
      <button type="button" class="op-tab {{if eq .Operation "encrypt"}}active{{end}}" data-op="encrypt">🔒 Encrypt</button>
      <button type="button" class="op-tab {{if eq .Operation "decrypt"}}active{{end}}" data-op="decrypt">🔓 Decrypt</button>
    </div>
    <input type="hidden" name="operation" id="operationInput" value="{{.Operation}}" />

    <!-- ── Secret key (always visible) ─────────────────────────────── -->
    <div class="card" style="margin-bottom:1.25rem">
      <h2>Secret Key</h2>
      <input type="text" name="key" id="keyInput"
        placeholder="Enter your secret key / password"
        value="{{.Key}}" autocomplete="off" required />
      <p class="hint">Hashed with SHA-256 and trimmed to the required AES key size.</p>
    </div>

    <!-- ══════════════════════════════════════════════════════════════ -->
    <!-- ENCRYPT PANEL                                                  -->
    <!-- ══════════════════════════════════════════════════════════════ -->
    <div id="encryptPanel" class="{{if eq .Operation "decrypt"}}hidden{{end}}">

      <!-- Mode + Key length -->
      <div class="card settings-row" style="margin-bottom:1.25rem">
        <div class="setting-group">
          <h2>Mode</h2>
          <div class="radio-group">
            <label class="radio-pill {{if eq .Mode "ECB"}}active{{end}}">
              <input type="radio" name="mode" value="ECB" {{if eq .Mode "ECB"}}checked{{end}} />ECB
            </label>
            <label class="radio-pill {{if eq .Mode "CBC"}}active{{end}}">
              <input type="radio" name="mode" value="CBC" {{if eq .Mode "CBC"}}checked{{end}} />CBC
            </label>
            <label class="radio-pill {{if eq .Mode "CFB"}}active{{end}}">
              <input type="radio" name="mode" value="CFB" {{if eq .Mode "CFB"}}checked{{end}} />CFB
            </label>
          </div>
        </div>
        <div class="setting-group">
          <h2>Key Length</h2>
          <div class="radio-group">
            <label class="radio-pill {{if eq .KeySize "128"}}active{{end}}">
              <input type="radio" name="keysize" value="128" {{if eq .KeySize "128"}}checked{{end}} />128-bit
            </label>
            <label class="radio-pill {{if eq .KeySize "192"}}active{{end}}">
              <input type="radio" name="keysize" value="192" {{if eq .KeySize "192"}}checked{{end}} />192-bit
            </label>
            <label class="radio-pill {{if eq .KeySize "256"}}active{{end}}">
              <input type="radio" name="keysize" value="256" {{if eq .KeySize "256"}}checked{{end}} />256-bit
            </label>
          </div>
        </div>
      </div>

      <!-- Plaintext input -->
      <div class="card" style="margin-bottom:1.25rem">
        <h2>Plaintext</h2>
        <textarea name="plaintext" placeholder="Type or paste the message to encrypt…">{{.Plaintext}}</textarea>
      </div>
    </div>

    <!-- ══════════════════════════════════════════════════════════════ -->
    <!-- DECRYPT PANEL                                                  -->
    <!-- ══════════════════════════════════════════════════════════════ -->
    <div id="decryptPanel" class="{{if eq .Operation "encrypt"}}hidden{{end}}">
      <div class="card" style="margin-bottom:1.25rem">
        <h2>Ciphertext source</h2>

        <!-- Source toggle: three tabs -->
        <div class="source-tabs">
          <button type="button" class="source-tab {{if eq .DecryptSource "paste"}}active{{end}}{{if eq .DecryptSource ""}}active{{end}}" data-src="paste">Paste JSON</button>
          <button type="button" class="source-tab {{if eq .DecryptSource "manual"}}active{{end}}" data-src="manual">Manual</button>
          <button type="button" class="source-tab {{if eq .DecryptSource "file"}}active{{end}}"   data-src="file">Upload .txt</button>
        </div>
        <input type="hidden" name="decrypt_source" id="decryptSourceInput" value="{{if eq .DecryptSource "file"}}file{{else if eq .DecryptSource "manual"}}manual{{else}}paste{{end}}" />

        <!-- Paste JSON area -->
        <div id="pasteArea" class="{{if or (eq .DecryptSource "manual") (eq .DecryptSource "file")}}hidden{{end}}">
          <textarea name="pasted_cipher"
            placeholder="Paste the full JSON block produced during encryption…">{{.PastedCipher}}</textarea>
          <p class="hint">Mode and key length are read from the JSON — no need to select them.</p>
        </div>

        <!-- Manual area -->
        <div id="manualArea" class="{{if ne .DecryptSource "manual"}}hidden{{end}}">
          <div class="settings-row" style="margin-bottom:1rem">
            <div class="setting-group">
              <h2>Mode</h2>
              <div class="radio-group" id="manualModeGroup">
                <label class="radio-pill {{if eq .ManualMode "ECB"}}active{{end}}"><input type="radio" name="manual_mode" value="ECB" {{if eq .ManualMode "ECB"}}checked{{end}} />ECB</label>
                <label class="radio-pill {{if eq .ManualMode "CBC"}}active{{end}}"><input type="radio" name="manual_mode" value="CBC" {{if eq .ManualMode "CBC"}}checked{{end}} />CBC</label>
                <label class="radio-pill {{if eq .ManualMode "CFB"}}active{{end}}"><input type="radio" name="manual_mode" value="CFB" {{if eq .ManualMode "CFB"}}checked{{end}} />CFB</label>
              </div>
            </div>
            <div class="setting-group">
              <h2>Key Length</h2>
              <div class="radio-group">
                <label class="radio-pill {{if eq .ManualKeySize "128"}}active{{end}}"><input type="radio" name="manual_keysize" value="128" {{if eq .ManualKeySize "128"}}checked{{end}} />128-bit</label>
                <label class="radio-pill {{if eq .ManualKeySize "192"}}active{{end}}"><input type="radio" name="manual_keysize" value="192" {{if eq .ManualKeySize "192"}}checked{{end}} />192-bit</label>
                <label class="radio-pill {{if eq .ManualKeySize "256"}}active{{end}}"><input type="radio" name="manual_keysize" value="256" {{if eq .ManualKeySize "256"}}checked{{end}} />256-bit</label>
              </div>
            </div>
          </div>

          <div style="margin-bottom:0.85rem">
            <h2 style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.08em;color:var(--muted);margin-bottom:0.5rem">Ciphertext (base64)</h2>
            <textarea name="manual_ciphertext" rows="3"
              placeholder="Paste the base64-encoded ciphertext…">{{.ManualCiphertext}}</textarea>
          </div>

          <div id="ivField" class="{{if eq .ManualMode "ECB"}}hidden{{end}}">
            <h2 style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.08em;color:var(--muted);margin-bottom:0.5rem">IV (base64)</h2>
            <input type="text" name="manual_iv"
              placeholder="Paste the base64-encoded IV…"
              value="{{.ManualIV}}" autocomplete="off" />
            <p class="hint">Required for CBC and CFB modes.</p>
          </div>
        </div>

        <!-- File drop zone -->
        <div id="fileArea" class="{{if ne .DecryptSource "file"}}hidden{{end}}">
          <label class="drop-zone" id="dropZone">
            <span class="file-icon">📂</span>
            <span id="dropLabel">Drop your ciphertext.txt here, or click to browse</span>
            <span class="file-name hidden" id="fileName"></span>
            <input type="file" name="cipher_file" id="cipherFileInput" accept=".txt" />
          </label>
          <p class="hint" style="margin-top:0.5rem">Only .txt files produced by this tool are accepted.</p>
        </div>
      </div>

      <p id="autoHint" class="hint" style="margin-bottom:1.25rem {{if eq .DecryptSource "manual"}}display:none{{end}}">
        ℹ️ Mode and key length are read from the file — no need to select them manually.
      </p>
    </div>

    <button type="submit" class="btn-primary">Process</button>
  </form>

  <!-- ── Error ──────────────────────────────────────────────────────── -->
  {{if .Error}}
  <div class="alert error">{{.Error}}</div>
  {{end}}

  <!-- ── Result ─────────────────────────────────────────────────────── -->
  {{if .Result}}
  <div class="card">
    <h2>Result</h2>

    {{if and .DecodedMode .DecodedKeySize}}
    <div class="badge-row">
      <span class="badge">Mode: {{.DecodedMode}}</span>
      <span class="badge">Key: {{.DecodedKeySize}}-bit</span>
    </div>
    {{end}}

    <textarea readonly>{{.Result}}</textarea>

    {{if .DownloadPayload}}
    <form method="POST" action="/download">
      <input type="hidden" name="payload" value="{{.DownloadPayload}}" />
      <button type="submit" class="btn-secondary">⬇ Download as ciphertext.txt</button>
    </form>
    {{end}}
  </div>
  {{end}}

  <!-- ── Info panel ─────────────────────────────────────────────────── -->
  <details>
    <summary>How AES works (overview)</summary>
    <div class="info-body">
      <div>
        <h3>What is AES?</h3>
        <p>AES is a symmetric block cipher operating on fixed 128-bit (16-byte) blocks. The number of rounds depends on key size:</p>
        <ul>
          <li><strong>AES-128</strong> — 10 rounds</li>
          <li><strong>AES-192</strong> — 12 rounds</li>
          <li><strong>AES-256</strong> — 14 rounds</li>
        </ul>
        <p style="margin-top:0.5rem">Longer key = more rounds = exponentially harder brute-force.</p>
      </div>
      <div>
        <h3>Modes of Operation</h3>
        <dl>
          <dt>ECB — Electronic Codebook</dt>
          <dd>Each block encrypted independently. Simple but weak — identical plaintext blocks produce identical ciphertext blocks, leaking patterns.</dd>
          <dt>CBC — Cipher Block Chaining</dt>
          <dd>Each block XOR-ed with the previous ciphertext block before encryption. Uses a random IV. Identical plaintexts produce different ciphertexts every run.</dd>
          <dt>CFB — Cipher Feedback</dt>
          <dd>Turns AES into a stream-like cipher. Uses IV. No block padding needed. Errors propagate only a limited number of blocks.</dd>
        </dl>
      </div>
      <div>
        <h3>Key Derivation</h3>
        <p>Your password is hashed with SHA-256 (32 bytes), then truncated: 16 bytes for AES-128, 24 for AES-192, 32 for AES-256. Same password + key length always produces the same AES key.</p>
      </div>
    </div>
  </details>

</div>

<script>
  // ── Operation tab switching ──────────────────────────────────────────
  const opInput = document.getElementById('operationInput');
  const encPanel = document.getElementById('encryptPanel');
  const decPanel = document.getElementById('decryptPanel');

  document.querySelectorAll('.op-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const op = tab.dataset.op;
      opInput.value = op;
      document.querySelectorAll('.op-tab').forEach(t => t.classList.toggle('active', t === tab));
      encPanel.classList.toggle('hidden', op !== 'encrypt');
      decPanel.classList.toggle('hidden', op !== 'decrypt');
    });
  });

  // ── Radio pill highlight ─────────────────────────────────────────────
  document.querySelectorAll('.radio-group').forEach(g => {
    g.addEventListener('change', () => {
      g.querySelectorAll('.radio-pill').forEach(p => {
        p.classList.toggle('active', p.querySelector('input').checked);
      });
    });
  });

  // ── Decrypt source toggle (paste / manual / file) ──────────────────
  const srcInput   = document.getElementById('decryptSourceInput');
  const pasteArea  = document.getElementById('pasteArea');
  const manualArea = document.getElementById('manualArea');
  const fileArea   = document.getElementById('fileArea');
  const autoHint   = document.getElementById('autoHint');

  function showSource(src) {
    srcInput.value = src;
    pasteArea.classList.toggle('hidden',  src !== 'paste');
    manualArea.classList.toggle('hidden', src !== 'manual');
    fileArea.classList.toggle('hidden',   src !== 'file');
    if (autoHint) autoHint.style.display = src === 'manual' ? 'none' : '';
    document.querySelectorAll('.source-tab').forEach(t =>
      t.classList.toggle('active', t.dataset.src === src));
  }

  document.querySelectorAll('.source-tab').forEach(tab => {
    tab.addEventListener('click', () => showSource(tab.dataset.src));
  });

  // ── IV field visibility based on manual mode selection ──────────────
  const ivField = document.getElementById('ivField');

  function updateIVField() {
    const checked = document.querySelector('input[name="manual_mode"]:checked');
    const mode = checked ? checked.value : '';
    ivField.classList.toggle('hidden', mode === 'ECB' || mode === '');
  }

  document.getElementById('manualModeGroup').addEventListener('change', updateIVField);
  updateIVField(); // run on page load to match server-rendered state

  // ── File drop zone ───────────────────────────────────────────────────
  const dropZone  = document.getElementById('dropZone');
  const fileInput = document.getElementById('cipherFileInput');
  const fileName  = document.getElementById('fileName');
  const dropLabel = document.getElementById('dropLabel');

  function showFile(name) {
    dropLabel.classList.add('hidden');
    fileName.textContent = '📄 ' + name;
    fileName.classList.remove('hidden');
  }

  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) showFile(fileInput.files[0].name);
  });

  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) {
      const dt = new DataTransfer();
      dt.items.add(file);
      fileInput.files = dt.files;
      showFile(file.name);
    }
  });

  // ── Form validation before submit ───────────────────────────────────
  document.getElementById('mainForm').addEventListener('submit', e => {
    const op  = opInput.value;
    const key = document.getElementById('keyInput').value.trim();

    if (!key) {
      e.preventDefault();
      alert('Please enter a secret key.');
      return;
    }

    if (op === 'encrypt') {
      const pt = document.querySelector('textarea[name="plaintext"]').value.trim();
      if (!pt) { e.preventDefault(); alert('Please enter plaintext to encrypt.'); return; }
      // Ensure decrypt-only fields don't submit noise
      document.querySelector('textarea[name="pasted_cipher"]').value = '';
    }

    if (op === 'decrypt') {
      const src = srcInput.value;
      if (src === 'paste') {
        const pc = document.querySelector('textarea[name="pasted_cipher"]').value.trim();
        if (!pc) { e.preventDefault(); alert('Please paste the ciphertext JSON.'); return; }
      } else if (src === 'manual') {
        const mode = document.querySelector('input[name="manual_mode"]:checked');
        const ks   = document.querySelector('input[name="manual_keysize"]:checked');
        const ct   = document.querySelector('textarea[name="manual_ciphertext"]').value.trim();
        if (!mode) { e.preventDefault(); alert('Please select a mode.'); return; }
        if (!ks)   { e.preventDefault(); alert('Please select a key length.'); return; }
        if (!ct)   { e.preventDefault(); alert('Please enter the ciphertext.'); return; }
        if (mode.value !== 'ECB') {
          const iv = document.querySelector('input[name="manual_iv"]').value.trim();
          if (!iv) { e.preventDefault(); alert(mode.value + ' requires an IV.'); return; }
        }
      } else { // file
        if (!fileInput.files || !fileInput.files[0]) {
          e.preventDefault(); alert('Please select a .txt ciphertext file.'); return;
        }
      }
      // Encrypt-only fields should not interfere
      document.querySelector('textarea[name="plaintext"]').value = '';
    }
  });
</script>
</body>
</html>`

// ── Template + rendering ──────────────────────────────────────────────────────

var tmpl = template.Must(template.New("index").Parse(indexHTML))

func render(w http.ResponseWriter, data PageData) {
	if data.Operation == "" {
		data.Operation = "encrypt"
	}
	if data.Mode == "" {
		data.Mode = "CBC"
	}
	if data.KeySize == "" {
		data.KeySize = "256"
	}
	// Only default decrypt source when we're actually on the decrypt tab.
	// On the encrypt tab, leaving it empty is fine — the panel is hidden.
	if data.Operation == "decrypt" && data.DecryptSource == "" {
		data.DecryptSource = "paste"
	}
	if err := tmpl.Execute(w, data); err != nil {
		log.Println("template error:", err)
	}
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	render(w, PageData{})
}

func processHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		r.ParseForm()
	}

	op := strings.TrimSpace(r.FormValue("operation"))
	key := strings.TrimSpace(r.FormValue("key"))

	// Base page state — always echo back what the user had selected.
	data := PageData{
		Operation:        op,
		Key:              key,
		Mode:             r.FormValue("mode"),
		KeySize:          r.FormValue("keysize"),
		DecryptSource:    r.FormValue("decrypt_source"),
		PastedCipher:     r.FormValue("pasted_cipher"),
		Plaintext:        r.FormValue("plaintext"),
		ManualMode:       r.FormValue("manual_mode"),
		ManualKeySize:    r.FormValue("manual_keysize"),
		ManualCiphertext: r.FormValue("manual_ciphertext"),
		ManualIV:         r.FormValue("manual_iv"),
	}

	if key == "" {
		data.Error = "Secret key must not be empty."
		render(w, data)
		return
	}

	switch op {
	case "encrypt":
		handleEncrypt(w, r, &data)
	case "decrypt":
		handleDecrypt(w, r, &data)
	default:
		data.Error = "Unknown operation."
		render(w, data)
	}
}

func handleEncrypt(w http.ResponseWriter, _ *http.Request, data *PageData) {
	plaintext := strings.TrimSpace(data.Plaintext)
	if plaintext == "" {
		data.Error = "Plaintext must not be empty."
		render(w, *data)
		return
	}

	keyBits, err := strconv.Atoi(data.KeySize)
	if err != nil || (keyBits != 128 && keyBits != 192 && keyBits != 256) {
		data.Error = "Invalid key size selected."
		render(w, *data)
		return
	}

	if data.Mode != "ECB" && data.Mode != "CBC" && data.Mode != "CFB" {
		data.Error = "Invalid mode selected."
		render(w, *data)
		return
	}

	aesKey := deriveKey(data.Key, keyBits/8)
	result, err := encrypt([]byte(plaintext), aesKey, data.Mode)
	if err != nil {
		data.Error = "Encryption failed: " + err.Error()
		render(w, *data)
		return
	}

	payload := ciphertextFile{
		Mode:       data.Mode,
		KeySize:    keyBits,
		Ciphertext: base64.StdEncoding.EncodeToString(result.Ciphertext),
	}
	if result.IV != nil {
		payload.IV = base64.StdEncoding.EncodeToString(result.IV)
	}

	jsonBytes, _ := json.MarshalIndent(payload, "", "  ")
	data.Result = string(jsonBytes)
	data.DownloadPayload = base64.StdEncoding.EncodeToString(jsonBytes)
	render(w, *data)
}

func handleDecrypt(w http.ResponseWriter, r *http.Request, data *PageData) {
	switch data.DecryptSource {
	case "manual":
		handleDecryptManual(w, data)
	case "file":
		handleDecryptJSON(w, r, data, "")
	default: // "paste"
		rawJSON := strings.TrimSpace(data.PastedCipher)
		if rawJSON == "" {
			data.Error = "Please paste the ciphertext JSON."
			render(w, *data)
			return
		}
		handleDecryptJSON(w, r, data, rawJSON)
	}
}

// handleDecryptManual decrypts using fields the user filled in manually —
// no JSON wrapper, just raw base64 ciphertext + optional IV.
func handleDecryptManual(w http.ResponseWriter, data *PageData) {
	mode := data.ManualMode
	if mode != "ECB" && mode != "CBC" && mode != "CFB" {
		data.Error = "Please select a mode."
		render(w, *data)
		return
	}

	keyBits, err := strconv.Atoi(data.ManualKeySize)
	if err != nil || (keyBits != 128 && keyBits != 192 && keyBits != 256) {
		data.Error = "Please select a key length."
		render(w, *data)
		return
	}

	rawCT := strings.TrimSpace(data.ManualCiphertext)
	if rawCT == "" {
		data.Error = "Ciphertext must not be empty."
		render(w, *data)
		return
	}

	ct, err := base64.StdEncoding.DecodeString(rawCT)
	if err != nil {
		data.Error = "Ciphertext is not valid base64: " + err.Error()
		render(w, *data)
		return
	}

	var iv []byte
	if mode == "CBC" || mode == "CFB" {
		rawIV := strings.TrimSpace(data.ManualIV)
		if rawIV == "" {
			data.Error = mode + " mode requires an IV."
			render(w, *data)
			return
		}
		if iv, err = base64.StdEncoding.DecodeString(rawIV); err != nil {
			data.Error = "IV is not valid base64: " + err.Error()
			render(w, *data)
			return
		}
	}

	aesKey := deriveKey(data.Key, keyBits/8)
	pt, err := decrypt(ct, aesKey, iv, mode)
	if err != nil {
		data.Error = "Decryption failed — wrong key, IV, or corrupted data."
		render(w, *data)
		return
	}

	data.Result = string(pt)
	data.DecodedMode = mode
	data.DecodedKeySize = strconv.Itoa(keyBits)
	render(w, *data)
}

// handleDecryptJSON decrypts from a self-describing JSON blob (paste or file).
func handleDecryptJSON(w http.ResponseWriter, r *http.Request, data *PageData, rawJSON string) {
	// If rawJSON is empty we need to read from the uploaded file.
	if rawJSON == "" {
		file, _, err := r.FormFile("cipher_file")
		if err != nil {
			data.Error = "No file received. Please upload a ciphertext .txt file."
			render(w, *data)
			return
		}
		defer file.Close()
		b, err := io.ReadAll(file)
		if err != nil {
			data.Error = "Failed to read uploaded file."
			render(w, *data)
			return
		}
		rawJSON = string(b)
	}

	var payload ciphertextFile
	if err := json.Unmarshal([]byte(rawJSON), &payload); err != nil {
		data.Error = "Not valid ciphertext JSON. Make sure you are using content produced by this tool."
		render(w, *data)
		return
	}

	ct, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		data.Error = "Failed to decode ciphertext: " + err.Error()
		render(w, *data)
		return
	}

	var iv []byte
	if payload.IV != "" {
		if iv, err = base64.StdEncoding.DecodeString(payload.IV); err != nil {
			data.Error = "Failed to decode IV: " + err.Error()
			render(w, *data)
			return
		}
	}

	aesKey := deriveKey(data.Key, payload.KeySize/8)
	pt, err := decrypt(ct, aesKey, iv, payload.Mode)
	if err != nil {
		data.Error = "Decryption failed — wrong key or corrupted data."
		render(w, *data)
		return
	}

	data.Result = string(pt)
	data.DecodedMode = payload.Mode
	data.DecodedKeySize = strconv.Itoa(payload.KeySize)
	render(w, *data)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	raw, err := base64.StdEncoding.DecodeString(r.FormValue("payload"))
	if err != nil || len(raw) == 0 {
		http.Error(w, "Nothing to download.", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="ciphertext.txt"`)
	w.Write(raw)
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/process", processHandler)
	http.HandleFunc("/download", downloadHandler)
	log.Println("Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
