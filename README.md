# CyberShield Flow Analyzer

A graph-based cyber network analyzer that models infrastructure as a directed flow network. It computes maximum flow, minimum cut, shortest routes, bottlenecks, structural criticality and resilience under failures or cyber attacks.

The application is **backend-driven**: the browser is the editor and dashboard, while every analysis result shown in the UI is computed by the Flask + NetworkX service. Opening `frontend/index.html` directly is intentionally unsupported; the page performs a `/health` check and refuses to start without the backend.

## Architecture

```text
Browser (frontend/index.html)
        |
        |  same-origin JSON API (synchronous bridge in the current UI)
        v
Flask (backend/app.py)
        |
        v
NetworkX engine (backend/network_graph.py)
        |
        v
Compatibility mapper (backend/ui_adapter.py)
```

Why the adapter exists: the original UI was built around a JavaScript engine with field names such as `bottleneck`, `background` and `available`. `ui_adapter.py` converts the browser topology into the Python engine format, runs the real NetworkX analysis, and maps the result back to the shape the UI already renders. This keeps the backend authoritative without rewriting the whole dashboard.

The local JavaScript engine is still present for:

- topology validation and normalisation,
- sample topologies,
- reversible scenario mutation,
- the built-in self-tests.

It is **not** used for the analysis shown in the Results, Algorithms or Compare panels.

## Project structure

```text
cybershield_analyzer/
├── backend/
│   ├── app.py                 # Flask routes, health gate, static frontend
│   ├── network_graph.py       # NetworkX reference engine + self-tests
│   ├── ui_adapter.py          # Browser <-> NetworkX compatibility layer
│   └── topologies/
│       └── default.json       # Default topology used by /api/topology
├── frontend/
│   └── index.html             # Single-file dashboard (no build step)
├── Procfile                   # Generic WSGI process definition
├── render.yaml                # Render Blueprint (free web service)
├── requirements.txt
└── README.md
```

## Run locally

1. Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Start the Flask service:

```bash
python3 backend/app.py
```

4. Open:

```text
http://localhost:5000
```

Flask serves both the API and `frontend/index.html` on the same origin. There is no separate static server and no CORS configuration to maintain.

> Do not open `frontend/index.html` with `file://`. The startup gate will report that the backend is unreachable, because analysis requires the Flask service.

### Quick verification

```bash
curl http://localhost:5000/health
```

Expected response:

```json
{"engine":"networkx","service":"cybershield-flow-analyzer","status":"ok"}
```

## API

All analysis endpoints accept JSON and return JSON.

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Backend readiness check used by the UI boot gate |
| `GET` | `/api/topology` | Default topology JSON |
| `POST` | `/api/maxflow` | Maximum flow, augmenting paths, min cut |
| `POST` | `/api/shortest` | Dijkstra + k-shortest simple paths |
| `POST` | `/api/analyze` | Full analysis: flow, cut, routes, reachability, bottlenecks, criticality, recommendations |
| `POST` | `/api/resilience` | Mean surviving-flow resilience score |
| `POST` | `/api/standard` | Report §8.3 standard-scenario table |

Common request fields:

```json
{
  "topology": { "nodes": [], "edges": [] },
  "source": "C1",
  "destination": "SV1",
  "threshold": 75
}
```

`/api/maxflow` additionally accepts `opts.skipNode` and `opts.skipEdge`; `/api/shortest` accepts `maxPaths`; `/api/standard` accepts `targets`.

## Deploy on Render (recommended free option)

The repository includes `render.yaml` and a `Procfile`.

1. Push the repository to GitHub.
2. In Render, choose **New > Blueprint** and select the repository, or create a Web Service manually.
3. Use:

```text
Build command: pip install -r requirements.txt
Start command: gunicorn --chdir backend app:app --bind 0.0.0.0:$PORT
Health check path: /health
```

4. Deploy and open the generated `onrender.com` URL.

The Blueprint sets `plan: free`, so the service will sleep after 15 minutes without inbound traffic and may take roughly a minute to wake. For a demo or viva, open the URL a minute or two before presenting, or use a small uptime pinger.

### Other hosting options considered

| Host | Free option | Important limitation |
| --- | --- | --- |
| Render | Free web service | Sleeps after 15 minutes; cold start |
| Koyeb | Free instance | Scales to zero after about 1 hour; free instance cannot disable it |
| PythonAnywhere | Free account | 100 CPU seconds/day, one web app, free account expires after one month |
| Fly.io | No free tier for new organizations | Paid only (small trial for new accounts) |
| Google Cloud Run | Free tier quota | Requires a billing account/credit card; scale-to-zero |

Render is the simplest fit for this Flask app because it can build from `requirements.txt`, run Gunicorn, serve the static frontend from the same origin, and use `/health` for checks. If the service must stay warm, Render's paid Starter plan removes the idle sleep; otherwise Koyeb or Cloud Run are reasonable alternatives.

## Verification status

- JavaScript engine self-tests: **51 / 51 passed**
- Python/NetworkX reference self-tests: **26 / 26 passed**
- Flask API smoke tests: `/health`, `/api/maxflow`, `/api/shortest`, `/api/analyze`, `/api/resilience`, `/api/standard` all return `200`
- Browser smoke test with Selenium: initial dashboard shows `600 Mbps`, `8 ms`, cut `L10 + L11`, resilience `75.98 / 100`; disabling `L10` changes `Fmax` from `600` to `400`; the standard-scenario modal renders live backend rows

## Known limitations

- The current UI bridge uses synchronous `XMLHttpRequest` because the original dashboard calls its engine synchronously. The Flask service is authoritative, but a future refactor should make the bridge fully asynchronous.
- The dashboard loads Cytoscape and Font Awesome from CDNs, so the first load requires internet access.
- The enterprise and compact topologies are illustrative teaching samples, not measurements from a real organisation.
- Free-tier hosting can cold-start after inactivity; this is a hosting limitation, not an analysis correctness issue.

## License

This project is intended for academic and demo use. Add an appropriate license if it will be shared publicly on GitHub.
