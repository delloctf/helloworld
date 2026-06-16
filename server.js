const express = require("express");
const { exec } = require("child_process");

const app = express();
app.use(express.urlencoded({ extended: false }));

const PORT = process.env.PORT || 5000;

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

function page(host, output) {
  const result =
    output === null ? "" : `<h2>Result</h2><pre>${escapeHtml(output)}</pre>`;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetDiag &mdash; Connectivity Checker</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 640px;
           margin: 48px auto; padding: 0 16px; color: #1a1a1a; }
    h1 { font-size: 1.3rem; } h2 { font-size: 1rem; }
    .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; }
    label { display: block; margin-bottom: 6px; font-weight: 600; }
    input[type=text] { width: 100%; padding: 8px; box-sizing: border-box; font-size: 1rem; }
    button { margin-top: 12px; padding: 8px 16px; font-size: 1rem; cursor: pointer; }
    pre { background: #111; color: #0f0; padding: 12px; border-radius: 6px;
          overflow-x: auto; white-space: pre-wrap; }
  </style>
</head>
<body>
  <h1>NetDiag &mdash; Connectivity Checker</h1>
  <p>Enter a host or IP and we'll ping it for you.</p>
  <div class="card">
    <form method="post" action="/ping">
      <label for="host">Host or IP address</label>
      <input type="text" id="host" name="host" value="${escapeHtml(host)}" placeholder="e.g. 8.8.8.8">
      <button type="submit">Ping</button>
    </form>
    ${result}
  </div>
</body>
</html>`;
}

app.get("/", (req, res) => {
  res.send(page("", null));
});

app.post("/ping", (req, res) => {
  const host = req.body.host || "";

  // --- INTENTIONALLY VULNERABLE (challenge by design) ----------------
  // The user-supplied host is concatenated straight into a shell command
  // and run with exec(), which executes it via /bin/sh -c. This is the
  // command-injection bug participants are meant to find. The HTML
  // escaping elsewhere is for display only; the command uses the raw
  // input on purpose. Do NOT "fix" this in the challenge.
  const cmd = `ping -c 1 ${host}`;
  // -------------------------------------------------------------------

  exec(cmd, { timeout: 5000 }, (err, stdout, stderr) => {
    let output = (stdout || "") + (stderr || "");
    if (!output.trim()) output = "(no output)";
    res.send(page(host, output));
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`NetDiag listening on :${PORT}`);
});
