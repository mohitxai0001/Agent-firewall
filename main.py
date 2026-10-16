import os
import json
import hashlib
import secrets
from fastapi import FastAPI, Request, HTTPException, status, Depends
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
)
from pydantic import BaseModel
from sqlalchemy.orm import Session
from litellm import completion, completion_cost

from database import SessionLocal, SessionRecord, Project, ApiKey, generate_api_key, init_db

app = FastAPI(title="Agent Firewall")

# Ensure tables exist
init_db()

# Bearer auth for agent proxy calls
security = HTTPBearer()

# --- Basic Auth Setup for Admin Dashboard ---
security_basic = HTTPBasic()
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "firewall_secret_2026")

def authenticate_admin(credentials: HTTPBasicCredentials = Depends(security_basic)):
    is_correct_username = secrets.compare_digest(credentials.username, ADMIN_USERNAME)
    is_correct_password = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Pydantic Schemas ---
class ProjectCreate(BaseModel):
    name: str
    budget_limit: float = 0.005000  # Default $0.005
    max_steps_per_session: int = 3   # Default 3 calls before loop kill


# --- Administrative Endpoints ---

@app.post("/v1/projects")
def create_project(data: ProjectCreate, db: Session = Depends(get_db)):
    """Create a new project and auto-generate its first Agent Firewall API Key"""
    project = Project(
        name=data.name,
        budget_limit=data.budget_limit,
        max_steps_per_session=data.max_steps_per_session
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    # Generate API key
    raw_key = generate_api_key()
    api_key_entry = ApiKey(key=raw_key, project_id=project.id)
    db.add(api_key_entry)
    db.commit()

    return {
        "project_id": project.id,
        "project_name": project.name,
        "api_key": raw_key,
        "budget_limit": project.budget_limit,
        "max_steps_per_session": project.max_steps_per_session
    }


@app.get("/v1/projects")
def list_projects(
    db: Session = Depends(get_db),
    admin: str = Depends(authenticate_admin)
):
    """List all projects and their active keys (Admin only)"""
    projects = db.query(Project).all()
    result = []
    for p in projects:
        result.append({
            "id": p.id,
            "name": p.name,
            "budget_limit": p.budget_limit,
            "max_steps": p.max_steps_per_session,
            "keys": [k.key for k in p.keys if k.is_active],
            "total_sessions": len(p.sessions),
            "total_spend": sum(s.spend for s in p.sessions)
        })
    return result


@app.get("/v1/sessions")
def list_sessions(
    db: Session = Depends(get_db),
    admin: str = Depends(authenticate_admin)
):
    """List session records (Admin only)"""
    return db.query(SessionRecord).all()


# --- Core Proxy with Bearer Auth ---
def detect_tool_call_loop(messages: list, threshold: int = 3):
    """
    Scans the message history in reverse for repeated identical tool calls.
    Normalizes JSON arguments so whitespace differences don't break the hash.
    """
    consecutive_count = 0
    last_hash = None
    last_tool_name = None
    
    # Extract only assistant turns that actually made tool calls
    tool_call_messages = [m for m in messages if m.get("role") == "assistant" and m.get("tool_calls")]
    
    for msg in reversed(tool_call_messages):
        try:
            # Look at the first tool called in this turn
            tool = msg["tool_calls"][0]["function"]
            t_name = tool.get("name", "")
            t_args_str = tool.get("arguments", "{}")
            
            # Normalize arguments (sort keys, remove extra whitespace)
            t_args_dict = json.loads(t_args_str)
            normalized_args = json.dumps(t_args_dict, sort_keys=True)
            
            # Create a deterministic hash of the tool name + arguments
            current_hash = hashlib.md5(f"{t_name}:{normalized_args}".encode()).hexdigest()
            
            if last_hash is None:
                last_hash = current_hash
                last_tool_name = t_name
                consecutive_count = 1
            elif current_hash == last_hash:
                consecutive_count += 1
                if consecutive_count >= threshold:
                    return {
                        "tool_name": last_tool_name,
                        "count": consecutive_count
                    }
            else:
                break  # The sequence of identical calls was broken
        except Exception:
            break
            
    return None



@app.post("/v1/chat/completions")
async def proxy_chat_completions(
    request: Request,
    auth: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = auth.credentials

    # 1. Authenticate API Key
    key_record = db.query(ApiKey).filter(ApiKey.key == token, ApiKey.is_active == True).first()
    if not key_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or deactivated Agent Firewall API Key."
        )

    project = key_record.project
    session_id = request.headers.get("X-Session-ID", "default-session")

    # 2. Get or create session bound to this project
    session_entry = db.query(SessionRecord).filter(
        SessionRecord.session_id == session_id,
        SessionRecord.project_id == project.id
    ).first()

    if not session_entry:
        session_entry = SessionRecord(
            session_id=session_id,
            project_id=project.id,
            budget=project.budget_limit,
            max_steps=project.max_steps_per_session
        )
        db.add(session_entry)
        db.commit()
        db.refresh(session_entry)

    # 3. Pre-flight Guardrails
    if session_entry.steps >= session_entry.max_steps:
        session_entry.status = "BLOCKED_LOOPS"
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "Agent Firewall Blocked: Max loop/step limit reached.",
                "session_id": session_id,
                "steps": session_entry.steps,
                "max_steps": session_entry.max_steps
            }
        )

    if session_entry.spend >= session_entry.budget:
        session_entry.status = "BLOCKED_BUDGET"
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "Agent Firewall Blocked: Budget limit exceeded.",
                "session_id": session_id,
                "current_spend": f"${session_entry.spend:.6f}",
                "budget_limit": f"${session_entry.budget:.6f}"
            }
        )

    # 4. Proxy to LLM
    # 4. Proxy to LLM
    try:
        body = await request.json()
        
        # Ensure we have a default model if the agent doesn't provide one
        if "model" not in body:
            body["model"] = "gemini/gemini-3.1-flash-lite"
            
        is_stream = body.get("stream", False)
        messages = body.get("messages", [])

        # Pass the ENTIRE body (including tools, temperature, etc.) to LiteLLM
        # --- NEW: Deterministic Loop Detection ---
        loop_data = detect_tool_call_loop(messages, threshold=3)
        if loop_data:
            session_entry.status = "BLOCKED_TOOL_LOOP"
            db.commit()
            print(f"[Loop Intercepted] Tool '{loop_data['tool_name']}' repeated {loop_data['count']} times.")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Agent Firewall Circuit Breaker: Repeated Tool Call Loop Detected.",
                    "incident": f"Tool '{loop_data['tool_name']}' was called {loop_data['count']} times consecutively with identical arguments.",
                    "action_required": "Review tool execution logic or adjust loop threshold.",
                    "session_id": session_id
                }
            )

        # Pass the ENTIRE body to LiteLLM
        response = completion(**body)
        
        

        if is_stream:
          
            async def generate_chunks():
                full_completion_text = ""
                
                for chunk in response:
                    delta = chunk.get("choices", [{}])[0].get("delta", {})
                    content = delta.get("content") or ""
                    full_completion_text += content
                    
                    yield f"data: {chunk.model_dump_json()}\n\n"
                
                # Calculate final cost
                cost = float(completion_cost(model=model, prompt=str(messages), completion=full_completion_text))
                
                # Open a fresh DB session for the background commit
                bg_db = SessionLocal()
                try:
                    bg_session = bg_db.query(SessionRecord).filter(SessionRecord.session_id == session_id).first()
                    if bg_session:
                        bg_session.spend += cost
                        bg_session.steps += 1
                        bg_db.commit()
                        print(f"[Streaming Finished] Turn {bg_session.steps} | Spend: ${bg_session.spend:.6f}")
                finally:
                    bg_db.close()
                
                yield "data: [DONE]\n\n"

            return StreamingResponse(generate_chunks(), media_type="text/event-stream")
        
        else:
            cost = float(completion_cost(completion_response=response))
            session_entry.spend += cost
            session_entry.steps += 1
            db.commit()
            print(f"\n[Project: {project.name} | Session: {session_id}] Turn {session_entry.steps}/{session_entry.max_steps} | Spend: ${session_entry.spend:.6f}")
            return response.model_dump()

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Public & Admin UI Routes ---

@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(admin: str = Depends(authenticate_admin)):
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Agent Firewall - Control Plane</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-8 font-sans">
  <div class="max-w-6xl mx-auto space-y-8">
    
    <!-- Header -->
    <header class="flex justify-between items-center border-b border-slate-800 pb-6">
      <div>
        <h1 class="text-3xl font-bold tracking-tight text-white flex items-center gap-2">
          🛡️ Agent Firewall
        </h1>
        <p class="text-slate-400 text-sm mt-1">Autonomous Agent Runtime Protection</p>
      </div>
      <button onclick="fetchData()" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-sm font-semibold transition">
        Refresh Metrics
      </button>
    </header>

    <!-- Top KPI Cards -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
      <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl">
        <p class="text-slate-400 text-xs uppercase tracking-wider font-semibold">Tracked Projects</p>
        <p id="stat-projects" class="text-3xl font-bold text-white mt-2">-</p>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl">
        <p class="text-slate-400 text-xs uppercase tracking-wider font-semibold">Total Sessions</p>
        <p id="stat-sessions" class="text-3xl font-bold text-white mt-2">-</p>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl">
        <p class="text-slate-400 text-xs uppercase tracking-wider font-semibold">Interventions</p>
        <p id="stat-blocks" class="text-3xl font-bold text-rose-500 mt-2">-</p>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl">
        <p class="text-slate-400 text-xs uppercase tracking-wider font-semibold">Total Spend</p>
        <p id="stat-spend" class="text-3xl font-bold text-emerald-400 mt-2">$0.0000</p>
      </div>
    </div>

    <!-- Layout Grid for Tables -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
      
      <!-- Left Column (Projects & Sessions) -->
      <div class="lg:col-span-2 space-y-8">
        
        <!-- Live Agent Sessions -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <h2 class="text-lg font-semibold text-white mb-4">Live Agent Runs</h2>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="text-xs uppercase bg-slate-800/60 text-slate-400 border-b border-slate-800">
                <tr>
                  <th class="py-3 px-4">Run ID</th>
                  <th class="py-3 px-4">Steps</th>
                  <th class="py-3 px-4">Spend</th>
                  <th class="py-3 px-4">Status</th>
                </tr>
              </thead>
              <tbody id="sessions-table" class="divide-y divide-slate-800">
                <tr><td colspan="4" class="py-4 text-center text-slate-500">Loading runs...</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Active Projects -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <h2 class="text-lg font-semibold text-white mb-4">Project Policies</h2>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="text-xs uppercase bg-slate-800/60 text-slate-400 border-b border-slate-800">
                <tr>
                  <th class="py-3 px-4">Project</th>
                  <th class="py-3 px-4">Budget Cap</th>
                  <th class="py-3 px-4">Max Steps</th>
                  <th class="py-3 px-4">Total Spend</th>
                </tr>
              </thead>
              <tbody id="projects-table" class="divide-y divide-slate-800">
                <tr><td colspan="4" class="py-4 text-center text-slate-500">Loading projects...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Right Column (Intervention Feed) -->
      <div class="bg-slate-900 border border-rose-900/50 rounded-xl p-6 relative overflow-hidden">
        <!-- Background subtle glow -->
        <div class="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-rose-500 to-amber-500"></div>
        
        <h2 class="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <span class="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
          Incident Log
        </h2>
        
        <div id="incidents-feed" class="space-y-4 max-h-[600px] overflow-y-auto pr-2">
          <!-- Incidents will be injected here -->
          <p class="text-sm text-slate-500 text-center mt-10">No interventions yet.</p>
        </div>
      </div>

    </div>
  </div>

  <script>
    async function fetchData() {
      try {
        const [projRes, sessRes] = await Promise.all([
          fetch('/v1/projects'),
          fetch('/v1/sessions')
        ]);
        const projects = await projRes.json();
        const sessions = await sessRes.json();

        // 1. Update KPI Stats
        document.getElementById('stat-projects').innerText = projects.length;
        document.getElementById('stat-sessions').innerText = sessions.length;
        
        const totalSpend = sessions.reduce((acc, s) => acc + (s.spend || 0), 0);
        document.getElementById('stat-spend').innerText = '$' + totalSpend.toFixed(4);

        const blockedSessions = sessions.filter(s => s.status && s.status.includes('BLOCKED'));
        document.getElementById('stat-blocks').innerText = blockedSessions.length;

        // 2. Populate Projects Table
        const projBody = document.getElementById('projects-table');
        projBody.innerHTML = projects.map(p => `
          <tr class="hover:bg-slate-800/30">
            <td class="py-3 px-4 font-medium text-white">${p.name}</td>
            <td class="py-3 px-4">$${p.budget_limit.toFixed(4)}</td>
            <td class="py-3 px-4">${p.max_steps}</td>
            <td class="py-3 px-4 text-emerald-400 font-mono">$${(p.total_spend || 0).toFixed(4)}</td>
          </tr>
        `).join('');

        // 3. Populate Live Sessions Table
        const sessBody = document.getElementById('sessions-table');
        sessBody.innerHTML = sessions.map(s => {
          let badgeClass = "bg-emerald-950 text-emerald-400 border border-emerald-800";
          if (s.status.includes('BLOCKED')) {
            badgeClass = "bg-rose-950 text-rose-400 border border-rose-800";
          }
          return `
            <tr class="hover:bg-slate-800/30">
              <td class="py-3 px-4 font-mono text-xs text-slate-200">${s.session_id.substring(0,18)}...</td>
              <td class="py-3 px-4">${s.steps} / ${s.max_steps}</td>
              <td class="py-3 px-4 font-mono text-emerald-400">$${s.spend.toFixed(6)}</td>
              <td class="py-3 px-4">
                <span class="px-2 py-0.5 rounded text-xs font-semibold ${badgeClass}">
                  ${s.status}
                </span>
              </td>
            </tr>
          `;
        }).join('');

        // 4. Populate Intervention Log (Right Panel)
        const incidentsFeed = document.getElementById('incidents-feed');
        if (blockedSessions.length === 0) {
            incidentsFeed.innerHTML = '<p class="text-sm text-slate-500 text-center mt-10">No interventions yet.</p>';
        } else {
            // Sort to show newest first (assuming higher ID = newer)
            const sortedBlocks = blockedSessions.sort((a, b) => b.id - a.id);
            incidentsFeed.innerHTML = sortedBlocks.map(s => {
                
                // Determine icon and description based on block type
                let icon = '🛑';
                let desc = 'Execution halted by firewall policy.';
                
                if (s.status === 'BLOCKED_TOOL_LOOP') {
                    icon = '🔄';
                    desc = 'Runaway tool execution loop detected. Agent called identical tool arguments repeatedly.';
                } else if (s.status === 'BLOCKED_BUDGET') {
                    icon = '💸';
                    desc = `Session exceeded strict budget cap of $${s.budget.toFixed(4)}.`;
                } else if (s.status === 'BLOCKED_LOOPS') {
                    icon = '🚧';
                    desc = `Agent exceeded maximum allowed execution steps (${s.max_steps}).`;
                }

                return `
                <div class="p-4 bg-slate-950 border border-slate-800 rounded-lg">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-xs font-mono text-rose-400 bg-rose-950/50 px-2 py-1 rounded border border-rose-900">${s.status}</span>
                        <span class="text-xs text-slate-500">${new Date(s.updated_at).toLocaleTimeString()}</span>
                    </div>
                    <p class="text-sm text-slate-300 leading-relaxed">
                        ${icon} ${desc}
                    </p>
                    <div class="mt-3 pt-3 border-t border-slate-800 flex justify-between text-xs text-slate-400">
                        <span class="font-mono">ID: ${s.session_id.substring(0, 12)}...</span>
                        <span>Spend at kill: $${s.spend.toFixed(4)}</span>
                    </div>
                </div>
                `;
            }).join('');
        }

      } catch (err) {
        console.error("Dashboard fetch error:", err);
      }
    }

    fetchData();
    setInterval(fetchData, 3000); // Auto-refresh every 3s
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def get_landing_page():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Agent Firewall | Protect Your LLM Budget</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-white font-sans selection:bg-indigo-500/30">
  
  <!-- Navigation -->
  <nav class="border-b border-slate-800 bg-slate-950/50 backdrop-blur-md fixed top-0 w-full z-50">
    <div class="max-w-6xl mx-auto px-6 py-4 flex justify-between items-center">
      <div class="flex items-center gap-2">
        <span class="text-2xl">🛡️</span>
        <span class="font-bold tracking-tight text-lg">Agent Firewall</span>
      </div>
      <a href="/dashboard" class="text-sm font-semibold text-slate-300 hover:text-white transition">Developer Console &rarr;</a>
    </div>
  </nav>

  <!-- Hero Section -->
  <main class="pt-32 pb-20 px-6 text-center max-w-4xl mx-auto">
    <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 text-indigo-400 text-xs font-semibold mb-6 border border-indigo-500/20">
      <span class="w-2 h-2 rounded-full bg-indigo-500 animate-pulse"></span>
      v1.0 Live for Indie Hackers
    </div>
    
    <h1 class="text-5xl md:text-7xl font-extrabold tracking-tight mb-6 leading-tight">
      Stop Infinite AI Loops. <br>
      <span class="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">
        Protect Your API Budget.
      </span>
    </h1>
    
    <p class="text-lg text-slate-400 mb-10 max-w-2xl mx-auto leading-relaxed">
      A drop-in proxy for autonomous agents. Set hard budget caps, intercept runaway loops, and monitor live agent spend before the LLM provider bills you.
    </p>

    <div class="flex flex-col sm:flex-row justify-center gap-4">
      <a href="/dashboard" class="px-8 py-3.5 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-lg transition shadow-lg shadow-indigo-500/20">
        Start Tracking Free
      </a>
      <a href="https://github.com/mohitxai0001/Agent-firewall" target="_blank" class="px-8 py-3.5 bg-slate-800 hover:bg-slate-700 text-white font-semibold rounded-lg transition border border-slate-700">
        View on GitHub
      </a>
    </div>
  </main>

  <!-- Code Preview Section -->
  <section class="max-w-4xl mx-auto px-6 pb-24">
    <div class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
      <div class="bg-slate-800/50 px-4 py-3 border-b border-slate-800 flex items-center gap-2">
        <div class="w-3 h-3 rounded-full bg-rose-500"></div>
        <div class="w-3 h-3 rounded-full bg-amber-500"></div>
        <div class="w-3 h-3 rounded-full bg-emerald-500"></div>
        <span class="text-xs text-slate-400 ml-2 font-mono">agent.py</span>
      </div>
      <div class="p-6 overflow-x-auto">
        <pre class="text-sm font-mono text-slate-300 leading-relaxed"><code><span class="text-slate-500"># Drop-in replacement for any OpenAI-compatible SDK</span>
from openai import OpenAI

client = OpenAI(
    api_key=<span class="text-emerald-400">"fw-live_your_project_key"</span>,
    base_url=<span class="text-indigo-400">"https://agent-firewall-v9ft.onrender.com/v1"</span>
)

<span class="text-slate-500"># Your agent runs normally. If it hits an infinite loop, </span>
<span class="text-slate-500"># our proxy intercepts it with a 429 before you get billed.</span>
response = client.chat.completions.create(
    model="gemini/gemini-3.1-flash-lite",
    messages=[{"role": "user", "content": "Start autonomous run"}],
    extra_headers={"X-Session-ID": "agent-session-1"}
)</code></pre>
      </div>
    </div>
  </section>

</body>
</html>
    """