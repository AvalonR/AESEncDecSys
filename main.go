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
)

// ── Key derivation ────────────────────────────────────────────────────────────

// deriveKey hashes the user password with SHA-256, then truncates to the
// required AES key size (16 / 24 / 32 bytes).
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

// ── ECB (not in stdlib — implement manually) ──────────────────────────────────

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

type ciphertextFile struct {
	Mode       string `json:"mode"`
	KeySize    int    `json:"key_size"`
	IV         string `json:"iv,omitempty"`
	Ciphertext string `json:"ciphertext"`
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

type PageData struct {
	Result    string
	Error     string
	Input     string
	Key       string
	Operation string
	Mode      string
	KeySize   string
}

var indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AES Encryption Tool</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #0f1117; --surface: #1a1d27; --border: #2e3146;
      --accent: #5c6ef8; --text: #e2e4f0; --muted: #7a7f9a;
    }
    body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 15px; padding: 2rem 1rem 4rem; }
    .container { max-width: 780px; margin: 0 auto; display: flex; flex-direction: column; gap: 1.25rem; }
    header { text-align: center; padding: 1rem 0 0.5rem; }
    header h1 { font-size: 1.9rem; font-weight: 700; }
    .subtitle { color: var(--muted); font-size: 0.9rem; margin-top: 0.3rem; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem 1.5rem; }
    .card h2 { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin-bottom: 0.75rem; }
    .settings-row { display: flex; gap: 2.5rem; flex-wrap: wrap; }
    .setting-group { flex: 1; min-width: 180px; }
    .radio-group { display: flex; gap: 0.5rem; flex-wrap: wrap; }
    .radio-pill { display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.4rem 1rem; border-radius: 999px; border: 1px solid var(--border); cursor: pointer; font-size: 0.9rem; transition: border-color 0.15s, background 0.15s; user-select: none; }
    .radio-pill input[type="radio"] { display: none; }
    .radio-pill:hover { border-color: var(--accent); color: var(--accent); }
    .radio-pill.active { background: var(--accent); border-color: var(--accent); color: #fff; font-weight: 600; }
    input[type="text"], textarea { width: 100%; background: #12141e; border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-family: inherit; font-size: 0.95rem; padding: 0.6rem 0.85rem; outline: none; resize: vertical; transition: border-color 0.15s; }
    input[type="text"]:focus, textarea:focus { border-color: var(--accent); }
    .hint { color: var(--muted); font-size: 0.8rem; margin-top: 0.45rem; }
    .btn-primary { display: block; width: 100%; border: none; border-radius: 8px; cursor: pointer; font-size: 1rem; font-weight: 600; padding: 0.7rem 2rem; background: var(--accent); color: #fff; transition: opacity 0.15s; }
    .btn-primary:hover { opacity: 0.88; }
    .alert { padding: 0.85rem 1.25rem; border-radius: 10px; font-size: 0.9rem; }
    .alert.error { background: #2d1a1a; border: 1px solid #7f2f2f; color: #f87171; }
    .result-area { width: 100%; background: #0d0f17; border: 1px solid var(--border); border-radius: 6px; color: #a0f0c0; font-family: 'Cascadia Code', 'Fira Mono', monospace; font-size: 0.85rem; padding: 0.6rem 0.85rem; min-height: 160px; resize: vertical; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>AES Encryption &amp; Decryption</h1>
      <p class="subtitle">AES-128 / 192 / 256 &nbsp;·&nbsp; ECB / CBC / CFB</p>
    </header>

    <form method="POST" action="/process">

      <section class="card" style="margin-bottom:1.25rem">
        <h2>Operation</h2>
        <div class="radio-group">
          <label class="radio-pill {{if eq .Operation "encrypt"}}active{{end}}">
            <input type="radio" name="operation" value="encrypt" {{if eq .Operation "encrypt"}}checked{{end}} required />Encrypt
          </label>
          <label class="radio-pill {{if eq .Operation "decrypt"}}active{{end}}">
            <input type="radio" name="operation" value="decrypt" {{if eq .Operation "decrypt"}}checked{{end}} />Decrypt
          </label>
        </div>
      </section>

      <section class="card settings-row" style="margin-bottom:1.25rem">
        <div class="setting-group">
          <h2>Mode</h2>
          <div class="radio-group">
            <label class="radio-pill {{if eq .Mode "ECB"}}active{{end}}"><input type="radio" name="mode" value="ECB" {{if eq .Mode "ECB"}}checked{{end}} required />ECB</label>
            <label class="radio-pill {{if eq .Mode "CBC"}}active{{end}}"><input type="radio" name="mode" value="CBC" {{if eq .Mode "CBC"}}checked{{end}} />CBC</label>
            <label class="radio-pill {{if eq .Mode "CFB"}}active{{end}}"><input type="radio" name="mode" value="CFB" {{if eq .Mode "CFB"}}checked{{end}} />CFB</label>
          </div>
        </div>
        <div class="setting-group">
          <h2>Key Length</h2>
          <div class="radio-group">
            <label class="radio-pill {{if eq .KeySize "128"}}active{{end}}"><input type="radio" name="keysize" value="128" {{if eq .KeySize "128"}}checked{{end}} required />128-bit</label>
            <label class="radio-pill {{if eq .KeySize "192"}}active{{end}}"><input type="radio" name="keysize" value="192" {{if eq .KeySize "192"}}checked{{end}} />192-bit</label>
            <label class="radio-pill {{if eq .KeySize "256"}}active{{end}}"><input type="radio" name="keysize" value="256" {{if eq .KeySize "256"}}checked{{end}} />256-bit</label>
          </div>
        </div>
      </section>

      <section class="card" style="margin-bottom:1.25rem">
        <h2>Secret Key</h2>
        <input type="text" name="key" placeholder="Enter your secret key / password" value="{{.Key}}" autocomplete="off" required />
        <p class="hint">Your key is hashed with SHA-256 and trimmed to the required AES key size.</p>
      </section>

      <section class="card" style="margin-bottom:1.25rem">
        <h2>Input</h2>
        <textarea name="text" rows="6" placeholder="Plaintext to encrypt, or paste ciphertext JSON to decrypt…">{{.Input}}</textarea>
      </section>

      <button type="submit" class="btn-primary">Process</button>
    </form>

    {{if .Error}}<div class="alert error" style="margin-top:1.25rem">{{.Error}}</div>{{end}}

    {{if .Result}}
    <section class="card" style="margin-top:1.25rem">
      <h2>Result</h2>
      <textarea class="result-area" readonly>{{.Result}}</textarea>
    </section>
    {{end}}
  </div>

  <script>
    document.querySelectorAll('.radio-group').forEach(g => {
      g.addEventListener('change', () => {
        g.querySelectorAll('.radio-pill').forEach(p => {
          p.classList.toggle('active', p.querySelector('input').checked);
        });
      });
    });
  </script>
</body>
</html>`

var tmpl = template.Must(template.New("index").Parse(indexHTML))

func render(w http.ResponseWriter, data PageData) {
	if err := tmpl.Execute(w, data); err != nil {
		log.Println("template error:", err)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	render(w, PageData{Operation: "encrypt", Mode: "CBC", KeySize: "256"})
}

func processHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	r.ParseForm()

	data := PageData{
		Operation: r.FormValue("operation"),
		Mode:      r.FormValue("mode"),
		KeySize:   r.FormValue("keysize"),
		Key:       r.FormValue("key"),
		Input:     r.FormValue("text"),
	}

	if data.Key == "" {
		data.Error = "Secret key must not be empty."
		render(w, data)
		return
	}

	keyBits, err := strconv.Atoi(data.KeySize)
	if err != nil || (keyBits != 128 && keyBits != 192 && keyBits != 256) {
		data.Error = "Invalid key size."
		render(w, data)
		return
	}

	aesKey := deriveKey(data.Key, keyBits/8)

	switch data.Operation {
	case "encrypt":
		result, err := encrypt([]byte(data.Input), aesKey, data.Mode)
		if err != nil {
			data.Error = "Encryption failed: " + err.Error()
			render(w, data)
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

	case "decrypt":
		var payload ciphertextFile
		if err := json.Unmarshal([]byte(data.Input), &payload); err != nil {
			data.Error = "Input is not valid ciphertext JSON."
			render(w, data)
			return
		}
		ct, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
		if err != nil {
			data.Error = "Failed to decode ciphertext."
			render(w, data)
			return
		}
		var iv []byte
		if payload.IV != "" {
			if iv, err = base64.StdEncoding.DecodeString(payload.IV); err != nil {
				data.Error = "Failed to decode IV."
				render(w, data)
				return
			}
		}
		// Use mode and key size from the file, not the form selectors.
		aesKey = deriveKey(data.Key, payload.KeySize/8)
		pt, err := decrypt(ct, aesKey, iv, payload.Mode)
		if err != nil {
			data.Error = "Decryption failed: " + err.Error()
			render(w, data)
			return
		}
		data.Result = string(pt)
		data.Mode = payload.Mode
		data.KeySize = strconv.Itoa(payload.KeySize)

	default:
		data.Error = "Unknown operation."
	}

	render(w, data)
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/process", processHandler)
	log.Println("Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
