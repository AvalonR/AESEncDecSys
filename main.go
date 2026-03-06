package main

import (
	"html/template"
	"log"
	"net/http"
)

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
        <p class="hint">Your key will be hashed with SHA-256 and trimmed to the required AES key size.</p>
      </section>

      <section class="card" style="margin-bottom:1.25rem">
        <h2>Input</h2>
        <textarea name="text" rows="6" placeholder="Plaintext to encrypt, or ciphertext JSON to decrypt…">{{.Input}}</textarea>
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

// processHandler is a stub — crypto will be wired in the next commit.
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
		Error:     "Crypto not implemented yet — coming in next commit.",
	}
	render(w, data)
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/process", processHandler)
	log.Println("Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
