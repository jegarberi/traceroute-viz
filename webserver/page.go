package main

// Page shell: filters header, summary cards and the tab bar (CSS and JS are inline).

import "html/template"

const pageCSS = `
:root{--bg:#fafaf7;--fg:#1d1d1b;--muted:#6b6b66;--card:#ffffff;--line:#e4e2dc;--accent:#4e79a7}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#15161a;--fg:#e8e6e1;--muted:#9a9891;--card:#1d1f25;--line:#2e3038;--accent:#7fa7d6}}
:root[data-theme="dark"]{--bg:#15161a;--fg:#e8e6e1;--muted:#9a9891;--card:#1d1f25;--line:#2e3038;--accent:#7fa7d6}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif}
main{padding:16px;max-width:1100px;margin:0 auto}
h1{font-size:22px;margin:8px 0 2px}
.muted{color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-top:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.card b{display:block;font-size:22px}
.filters{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin-top:14px;display:flex;flex-wrap:wrap;gap:8px 18px;align-items:center;font-size:13px}
.filters select,.filters button,.filters .btn{font:inherit;padding:3px 8px;border-radius:6px;border:1px solid var(--line);background:var(--bg);color:var(--fg)}
.filters .btn{text-decoration:none;display:inline-block}
.error{color:#c0392b}
.tabs{display:flex;flex-wrap:wrap;gap:4px;margin-top:18px;border-bottom:1px solid var(--line)}
.tabs button{font:inherit;padding:6px 12px;border:1px solid transparent;border-bottom:none;border-radius:6px 6px 0 0;background:none;color:var(--muted);cursor:pointer}
.tabs button[aria-selected="true"]{background:var(--card);border-color:var(--line);color:var(--fg);margin-bottom:-1px}
.tabpanel{margin-top:14px}
.tabpanel p{margin:0 0 10px}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px}
svg{width:100%;height:auto;display:block;min-width:600px}
svg text{fill:var(--fg);font-size:11px}
svg .grid{stroke:var(--line)}
svg .muted-txt{fill:var(--muted);font-size:10px}
svg .attrib{fill:#222;font-size:10px;paint-order:stroke;stroke:#fff;stroke-width:3px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{white-space:nowrap;color:var(--muted);font-weight:600}
.route{font-family:ui-monospace,monospace;font-size:12px;word-break:break-word}
.swatch{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:middle}
`

const pageJS = `
(function(){
  document.querySelectorAll('.filters select').forEach(function(s){
    s.addEventListener('change', function(){ s.form.submit(); });
  });
  var tabs = [].slice.call(document.querySelectorAll('[data-tab]'));
  if (!tabs.length) return;
  function show(id){
    tabs.forEach(function(b){
      var on = b.dataset.tab === id;
      b.setAttribute('aria-selected', on);
    });
    document.querySelectorAll('.tabpanel').forEach(function(p){ p.hidden = p.id !== id; });
  }
  tabs.forEach(function(b){
    b.addEventListener('click', function(){
      show(b.dataset.tab);
      history.replaceState(null, '', '#' + b.dataset.tab);
    });
  });
  var h = location.hash.slice(1);
  show(tabs.some(function(b){ return b.dataset.tab === h; }) ? h : tabs[0].dataset.tab);
})();
`

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Traceroute report</title>
<style>{{.CSS}}</style></head><body><main>
<h1>Traceroute report</h1>
<p class="muted">Source: {{.Source}} · generated {{.Generated}}</p>

<form class="filters" method="get" action="/">
 <label>Destination <select name="dest">{{range .DestOpts}}<option value="{{.Value}}"{{if .Selected}} selected{{end}}>{{.Label}}</option>{{end}}</select></label>
 <label>Window <select name="window">{{range .WindowOpts}}<option value="{{.Value}}"{{if .Selected}} selected{{end}}>{{.Label}}</option>{{end}}</select></label>
 <label>Unknown hops <select name="unk">{{range .UnkOpts}}<option value="{{.Value}}"{{if .Selected}} selected{{end}}>{{.Label}}</option>{{end}}</select></label>
 <button type="submit">Apply</button>
 <a class="btn" href="">Reload database</a>
</form>

<p class="muted">{{.Status}}</p>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}

{{if .Cards}}<div class="cards">{{range .Cards}}<div class="card"><span class="muted">{{.Label}}</span><b>{{.Value}}</b></div>{{end}}</div>{{end}}

{{if .Tabs}}
<nav class="tabs" role="tablist">{{range .Tabs}}<button type="button" role="tab" data-tab="{{.ID}}">{{.Title}}</button>{{end}}</nav>
{{range .Tabs}}<section class="tabpanel" id="{{.ID}}" role="tabpanel">{{.Body}}</section>{{end}}
{{end}}
</main>
<script>{{.JS}}</script>
</body></html>`))
