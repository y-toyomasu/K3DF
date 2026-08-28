"""Independent, secret-redacting CTF referee service."""
from __future__ import annotations
import hmac, json, os, re, stat, tempfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FLAG_RE = re.compile(r"^K3DF\{[A-Za-z0-9_-]{43}\}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
RUN_RE = re.compile(r"^[A-Za-z0-9_-]{1,96}$")
MAX_BODY = 4096

def read_secret(path: str, *, token: bool = False) -> str:
    p = Path(path)
    s = p.stat()
    if not stat.S_ISREG(s.st_mode) or s.st_size <= 0 or s.st_size > 512 or (s.st_mode & 0o077):
        raise RuntimeError("Invalid secret file.")
    value = p.read_text(encoding="ascii").strip()
    if not value or "\x00" in value or any(ord(c) < 32 for c in value): raise RuntimeError("Invalid secret file.")
    if token and not TOKEN_RE.fullmatch(value) and not RUN_RE.fullmatch(value): raise RuntimeError("Invalid secret file.")
    if not token and not FLAG_RE.fullmatch(value): raise RuntimeError("Invalid flag file.")
    return value

class Referee:
    def __init__(self):
        self.run_id = read_secret(os.environ.get("K3DF_REFEREE_RUN_ID_PATH", "/run/ctf/run-id"), token=True)
        if not RUN_RE.fullmatch(self.run_id): raise RuntimeError("Invalid run id.")
        self.token = read_secret(os.environ.get("K3DF_REFEREE_TOKEN_PATH", "/run/secrets/k3df-referee-run-token"), token=True)
        flag_root = os.environ.get("K3DF_REFEREE_FLAGS_PATH", "/run/referee-flags")
        self.flags = {f"flag-{n}": read_secret(f"{flag_root}/flag-{n}.value") for n in range(1,4)}
        if len(set(self.flags.values())) != 3: raise RuntimeError("Duplicate flag values.")
        self.state_path = Path("/state/referee.json")
        try: self.max_submissions = int(os.environ.get("K3DF_REFEREE_MAX_SUBMISSIONS", "30"))
        except ValueError: raise RuntimeError("Invalid referee budget.")
        if self.max_submissions <= 0: raise RuntimeError("Invalid referee budget.")
        self.accepted, self.submission_attempts = self._load()
    def _load(self):
        if not self.state_path.exists(): return set(), 0
        data=json.loads(self.state_path.read_text())
        accepted = data.get("accepted", [])
        attempts = data.get("submission_attempts", 0)
        if (data.get("run_id") != self.run_id or not isinstance(accepted, list) or
                not all(item in self.flags for item in accepted) or not isinstance(attempts, int) or attempts < 0):
            raise RuntimeError("Invalid referee state.")
        return set(accepted), attempts
    def _save(self):
        data={"schema_version":"1.0","run_id":self.run_id,"accepted":sorted(self.accepted),"accepted_count":len(self.accepted),"total":3,"won":len(self.accepted)==3,"submission_attempts":self.submission_attempts,"max_submissions":self.max_submissions,"updated_at":datetime.now(timezone.utc).isoformat()}
        with tempfile.NamedTemporaryFile("w", dir=self.state_path.parent, delete=False) as f: json.dump(data,f); tmp=f.name
        os.replace(tmp,self.state_path)
    def submit(self, run_id, token, candidate):
        if not hmac.compare_digest(run_id, self.run_id) or not hmac.compare_digest(token, self.token): return {"outcome":"rejected"}
        if self.submission_attempts >= self.max_submissions: return {"outcome":"budget_exhausted"}
        self.submission_attempts += 1
        for flag_id, original in self.flags.items():
            if hmac.compare_digest(candidate, original):
                duplicate=flag_id in self.accepted; self.accepted.add(flag_id); self._save()
                return {"outcome":"duplicate" if duplicate else "accepted","flag_id":flag_id,"accepted_count":len(self.accepted),"total":3,"won":len(self.accepted)==3}
        self._save()
        return {"outcome":"rejected"}

REFEREE=Referee()
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def _send(self, status, value):
        raw=json.dumps(value).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        if self.path=="/health": return self._send(200,{"status":"ok"})
        m=re.fullmatch(r"/ctf/referee/v1/runs/([A-Za-z0-9_-]{1,96})/status",self.path)
        if not m: return self._send(404,{"outcome":"rejected"})
        if not hmac.compare_digest(m.group(1),REFEREE.run_id) or not hmac.compare_digest(self.headers.get("X-CTF-Run-Token", ""), REFEREE.token): return self._send(401,{"outcome":"rejected"})
        return self._send(200,{"accepted_count":len(REFEREE.accepted),"total":3,"won":len(REFEREE.accepted)==3})
    def do_POST(self):
        m=re.fullmatch(r"/ctf/referee/v1/runs/([A-Za-z0-9_-]{1,96})/submissions",self.path)
        if not m or self.headers.get("Content-Type","").split(";",1)[0]!="application/json": return self._send(400,{"outcome":"rejected"})
        if len(self.headers.get("X-CTF-Run-Token", "")) > 128: return self._send(400,{"outcome":"rejected"})
        try: length=int(self.headers.get("Content-Length","0"))
        except ValueError: return self._send(400,{"outcome":"rejected"})
        if length<=0 or length>MAX_BODY: return self._send(400,{"outcome":"rejected"})
        try: body=json.loads(self.rfile.read(length)); candidate=body.get("candidate")
        except Exception: return self._send(400,{"outcome":"rejected"})
        if not isinstance(candidate,str) or len(candidate)>128 or any(ord(c)<32 for c in candidate): return self._send(400,{"outcome":"rejected"})
        return self._send(200,REFEREE.submit(m.group(1),self.headers.get("X-CTF-Run-Token",""),candidate))
if __name__=="__main__": ThreadingHTTPServer(("0.0.0.0",8091),Handler).serve_forever()
