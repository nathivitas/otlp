# OTLP Audit Logs PoC — Grafana Alloy (River)

This PoC shows how to ingest **JSON audit logs** with **Grafana Alloy**, normalize them into **OTLP** (OpenTelemetry Logs) shape, and forward them to:
- an **OTLP endpoint** (e.g., another collector/gateway), and/or
- **Loki** (optional), while keeping Alloy’s web UI available for quick validation.

It includes:
- Local, containerized setup (Podman) for rapid iteration.
- River configs for a **sender** (filelog → OTLP) and a **receiver** (OTLP ingest).
- A **Kubernetes integration** pattern that plugs into an existing Alloy deployment (via ConfigMap patch), including discovery-based file tailing.
- Field mapping to OTLP (resource attributes, log attributes, body, severity, timestamp, trace/span correlation).

---

## Goals

1. **Only audit**: read JSON audit entries (multi-line safe), and filter to keep audit traffic only.
2. **Make logs “OTLP-like”**: 
   - Put “who/where” into **`resource.attributes.*`** (service, k8s metadata),
   - keep per-record details in **`attributes.*`**,
   - put the human-friendly text into **`body`**,
   - set **`timestamp`** and **`severity`**, and
   - (optionally) promote **trace/span IDs** for correlation.
3. **Forward to your OTLP endpoint** (and/or Loki), validating live with **Alloy UI**.
4. **Provide a drop‑in** Kubernetes pattern to add filelog→OTLP to an existing Alloy stack.

---

## Architecture

### Mermaid diagram (rendered on GitHub/GitLab/VS Code)

```mermaid
flowchart LR
  A[JSON Audit Logs\n(/data/app.log or k8s container logs)] 
    -- filelog --> B[Alloy Sender\n(filelog → time, severity, mapping)]
  B -->|OTLP gRPC 4317| C[Alloy Receiver\n(otlp receiver)]
  B -->|Optional Loki| L[(Loki)]
  C -->|debug.pretty| U[Alloy UI\nhttp://localhost:12345]
```

### ASCII sketch

```
[ JSON audit logs ] --filelog--> [ Alloy (sender) ] --OTLP:4317--> [ Alloy (receiver) ]
                                           \--> (optional) Loki
                     Alloy UI (debug.pretty) available at http://<host>:12345
```

---

## Field Mapping to OTLP

Source JSON (example):
```json
{
  "timestamp": "2025-09-18T12:34:56.789Z",
  "severity": "INFO",
  "message": "user alice updated policy X",
  "log.type": "audit",
  "resource": {
    "service.name": "iam-api",
    "service.namespace": "security",
    "host.name": "node-1"
  },
  "attributes": {
    "actor.id": "alice",
    "request.id": "c8d3...",
    "trace_id": "1f2c...",
    "span_id":  "aa33..."
  }
}
```

Resulting OTLP record (conceptual):
- `timestamp` ← `timestamp`
- `severity_text` ← `severity`
- `body` ← `message`
- `resource.attributes.*` ← `resource.*`
- `attributes.*` ← `attributes.*` (plus any residual fields)
- `trace_id` / `span_id` (optional) from `attributes.trace_id` / `attributes.span_id` if available

---

## Local (Podman) Setup

We use two Alloy containers in a pod:
- **sender**: reads `/data/app.log`, shapes logs, exports via OTLP to `receiver`.
- **receiver**: accepts OTLP on 4317/4318; exposes Alloy UI (HTTP) on **12345** and prints logs with `debug.pretty` for quick inspection.

Your PowerShell script (`scripts/up.ps1`) already:
- Creates volumes for config/data,
- Preloads `sender.river` and `receiver.river`,
- Publishes receiver’s UI on `:12345` and OTLP ports `4317/4318`.

### Sender River (filelog → OTLP)

> Save as `alloy/sender.river`

```hcl
// Read only audit logs and emit OTLP logs to the receiver
otelcol.receiver.filelog "audit_only" {
  include  = ["/data/app.log"]
  start_at = "beginning"

  // Handle pretty-printed / multi-line JSON (new record begins on a line that starts with '{')
  multiline {
    line_start_pattern = "^\\s*\\{"
  }

  operators = [
    // 0) Early filter on raw body. 'filter' DROPS when expr == true,
    // so we negate the "is audit" match to keep only audit lines.
    {
      type     = "filter",
      expr     = "!(body matches \"(?s)\\\"log\\.type\\\"\\s*:\\s*\\\"audit\\\"\")",
      on_error = "send",
    },

    // 1) Parse JSON (turn the raw body string into a structured object)
    { type = "json_parser", parse_from = "body", on_error = "send" },

    // 2) Parse event time -> record timestamp
    {
      type        = "time_parser",
      parse_from  = "body.timestamp",
      layout_type = "strptime",
      layout      = "%Y-%m-%dT%H:%M:%S.%fZ",   // e.g. 2025-09-18T12:34:56.789Z
      location    = "UTC",
      on_error    = "send",
    },

    // 3) Map severity if present (INFO/WARN/ERROR/etc.)
    { type = "severity_parser", parse_from = "body.severity", on_error = "send" },

    // 4) Lift nested structures to proper OTLP locations
    { type = "move", from = "body.resource",   to = "resource"   },
    { type = "move", from = "body.attributes", to = "attributes" },

    // 5) Prefer the human-readable message as the log body if present
    { type = "move", from = "body.message", to = "body", on_error = "send" },
  ]

  output { logs = [otelcol.processor.batch.default.input] }
}

otelcol.processor.batch "default" {
  output { logs = [otelcol.exporter.otlp.to_receiver.input] }
}

otelcol.exporter.otlp "to_receiver" {
  client {
    endpoint = "receiver:4317"
    tls { insecure = true }
  }
}
```

### Receiver River (OTLP ingest + UI)

> Save as `alloy/receiver.river`

```hcl
// Minimal receiver with debug output and UI
otelcol.receiver.otlp "default" {
  http {}
  grpc {}
  // Nothing to configure here; the Alloy process is started with:
  //   --server.http.listen-addr=0.0.0.0:12345
  // so UI is served on :12345
}

otelcol.processor.batch "default" {
  output { logs = [otelcol.exporter.debug.pretty.input] }
}

otelcol.exporter.debug "pretty" {
  verbosity = "basic"
}
```

> **UI:** Browse to `http://localhost:12345` → “Status → Components” and “Logs → Debug Exporter” to verify shaped entries.

### Common local errors & fixes

- **`missing required configuration parameter layout`**  
  Add `layout_type="strptime"` and a `layout` that matches your timestamp (`%Y-%m-%dT%H:%M:%S.%fZ`, or `...%z` if you have offsets).

- **Backticks / quotes**  
  River only supports **double-quoted** strings. Replace backticks with `"`.

- **Multi-line JSON**  
  Prefer `multiline { line_start_pattern = "^\\s*\\{" }`. For pretty-printed logs with standalone `}{` glue lines, the advanced `recombine` operator can be used, but isn’t required in this PoC.

- **Duplicating output to Loki**  
  If you already ship to Loki with `loki.source.kubernetes`, don’t also export OTLP → Loki unless you dedupe.

---

## Kubernetes Integration (attach OTLP logs to existing Alloy)

Below is a **patch-style** addition for your current `ConfigMap` (River syntax). It plugs into your already working Kubernetes discovery → relabel flow, and adds an **OTLP logs pipeline** driven by the **filelog** receiver. This lets you:
- Parse JSON application logs,
- Normalize into OTLP shape (time, severity, resource attrs),
- Export to **an external OTLP gateway** (e.g., `crowdstrike-otel-gateway`), and (optionally) to **Loki**.

> ⚠️ **Namespacing:** Use unique component names to avoid clashing with existing blocks (`k8s`, `default`, `to_cs`, `to_loki`).  
> ⚠️ **One batch per fan‑out:** We add a dedicated `batch` that fans out to multiple exporters.

```hcl
// === NEW: filelog receiver driven by discovery.relabel targets ===
otelcol.receiver.filelog "k8s" {
  // feed file paths from your relabel pipeline; each target must set __path__
  targets = discovery.relabel.pod_logs.output

  multiline {
    line_start_pattern = "^\\s*\\{"
  }

  operators = [
    // Parse JSON body
    { type = "json_parser",   parse_from = "body",           on_error = "send" },

    // Timestamp (RFC3339 w/ Z)
    { type = "time_parser",   parse_from = "body.timestamp", layout_type = "strptime", layout = "%Y-%m-%dT%H:%M:%S.%fZ", location = "UTC", on_error = "send" },

    // Severity
    { type = "severity_parser", parse_from = "body.severity", on_error = "send" },

    // Map useful k8s discovery labels into resource.*
    { type = "add", field = "resource.service.name",       value = "EXPR(string(attributes[\"service_name\"]))" },
    { type = "add", field = "resource.service.namespace",  value = "EXPR(string(attributes[\"service_namespace\"]))" },
    { type = "add", field = "resource.k8s.namespace.name", value = "EXPR(string(attributes[\"namespace\"]))" },
    { type = "add", field = "resource.k8s.pod.name",       value = "EXPR(string(attributes[\"pod\"]))" },
    { type = "add", field = "resource.k8s.container.name", value = "EXPR(string(attributes[\"container\"]))" },

    // Promote trace/span IDs if present in the payload
    { type = "move", from = "body.traceid", to = "attributes.trace_id", on_error = "send" },
    { type = "move", from = "body.spanid",  to = "attributes.span_id",  on_error = "send" },

    // Prefer message to body if available
    { type = "move", from = "body.message", to = "body", on_error = "send" },
  ]

  output { logs = [otelcol.processor.batch.default.input] }
}

// === NEW: batch processor with fan-out ===
otelcol.processor.batch "default" {
  output {
    logs = [
      otelcol.exporter.otlp.to_cs.input,
      otelcol.exporter.loki.to_loki.input, // remove this line if you don’t want Loki
    ]
  }
}

// === NEW: OTLP gRPC exporter (adjust endpoint/TLS/headers) ===
otelcol.exporter.otlp "to_cs" {
  client {
    endpoint = "crowdstrike-otel-gateway.grafana-stack-qa.svc:4317"
    tls { insecure = true }
    // headers = { "authorization" = "Bearer ${env.CROWDSTRIKE_OTEL_TOKEN}" }
  }
}

// === NEW: Optional — export shaped OTLP logs to Loki ===
otelcol.exporter.loki "to_loki" {
  endpoint {
    url = "https://loki-aks-devqa.apap.com.do/loki/api/v1/push"
    tls { insecure_skip_verify = true }
  }
  labels = {
    "service_name"        = "resource.service.name",
    "service_namespace"   = "resource.service.namespace",
    "k8s_namespace_name"  = "resource.k8s.namespace.name",
    "k8s_pod_name"        = "resource.k8s.pod.name",
    "k8s_container_name"  = "resource.k8s.container.name",
    "level"               = "severity_text",
  }
}
```

### How to apply

1. **Edit the ConfigMap** that ships River to Alloy (your Helm release already manages it):
   ```bash
   kubectl -n grafana-stack-qa edit configmap apap-alloy
   ```
   Paste the **NEW** River blocks into the `data.config.alloy` section. Save & exit.

2. **Rollout restart** the Alloy workload so it reloads the config:
   ```bash
   kubectl -n grafana-stack-qa rollout restart deployment/apap-alloy
   ```

3. **Verify**:
   - Alloy UI (see next section) shows the new components **Up**,
   - OTLP exporter connects to your gateway,
   - (If enabled) Loki shows shaped entries with the added labels.

> **Avoid duplication**: If you already send pod logs to Loki via `loki.source.kubernetes`, shipping **again** through the new OTLP→Loki exporter will duplicate. Choose one path per log stream.

---

## Publishing the Alloy UI in Kubernetes

Alloy’s UI is exposed by the **process** itself; you enable it by starting the container with the flag:
```
--server.http.listen-addr=0.0.0.0:12345
```
Then expose **port 12345** with a Service (and optionally Ingress). Example:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: apap-alloy-ui
  namespace: grafana-stack-qa
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: alloy
    app.kubernetes.io/instance: apap-alloy
  ports:
    - name: http-ui
      port: 12345
      targetPort: 12345
```

If your Helm chart supports **extra args**, ensure the container starts Alloy like:
```yaml
args:
  - run
  - --stability.level=experimental
  - --server.http.listen-addr=0.0.0.0:12345
  - /etc/alloy/config.alloy
```

Then, to reach the UI:
- **Port-forward**: `kubectl -n grafana-stack-qa port-forward svc/apap-alloy-ui 12345:12345`
- Or publish via **Ingress** as appropriate for your cluster.

---

## Why River? Why these choices?

- **River is Alloy’s native config language**. It’s declarative, composable, and supports dynamic discovery → relabel → receiver pipelines. Using River avoids YAML-to-River translation pitfalls.
- **Multi-line JSON**: Many app logs pretty-print JSON; `multiline { line_start_pattern = "^\\s*\\{" }` ensures each record is reconstructed before parsing.
- **Time/severity normalization**: OTLP requires proper `timestamp` and `severity`. We set `layout_type="strptime"` and explicitly define the layout that matches your logs.
- **Resource vs. attributes**: OTLP expects **source properties** (service, k8s info) on **resource**, and **event properties** on **attributes**. We lift/move fields accordingly so your tools (Tempo/Grafana/Elastic/etc.) can filter and correlate consistently.
- **Batch fan-out**: One batch feeding multiple exporters keeps backpressure behavior and retry policies consistent across sinks.
- **Trace & span IDs**: When present, promoting to attributes (or to `trace_id`/`span_id` via a transform) enables **log ↔ trace** correlation across your observability stack.

---

## Safety, Scale & Ops Tips

- **PII/Secrets**: Consider a `filter`/`regex_parser` stage to redact sensitive values before export.
- **Retries/Backoff**: Tune exporter backoff in production (the examples keep defaults).
- **Perf**: `batch` greatly reduces per-record overhead. Add a memory/cpu limit to the pod per your cluster SLOs.
- **Validation**: Keep a `debug.pretty` exporter in non-prod to inspect final records in Alloy UI.

---

## Appendix A — Troubleshooting

- **`missing required attribute "context"` in transform**: OTTL `transform` blocks require an explicit context (`log_statements { context = "log" }`). In this PoC we avoided advanced OTTL to keep things simpler.
- **`ParseTraceID` undefined**: Some OTTL helper functions vary by distro/version. Prefer to **move** `traceid`/`spanid` as strings into attributes, or use exporters/ingesters that accept hex strings directly.
- **`missing required configuration parameter layout`**: Always pair `layout_type` with the correct `layout`, especially when using `strptime`.
- **Backticks**: River strings must be double-quoted; backticks cause parse errors.

---

## Appendix B — Minimal sample log

```
{"timestamp":"2025-09-18T12:34:56.789Z","severity":"INFO","message":"user alice updated policy X","log.type":"audit","resource":{"service.name":"iam-api","service.namespace":"security","host.name":"node-1"},"attributes":{"actor.id":"alice","request.id":"c8d3...","trace_id":"1f2c...","span_id":"aa33..."}}
```

Append to your local file and nudge the volume to refresh:
```powershell
Add-Content .\logs\audit_sample.log (Get-Content .\logs\audit_sample.log -Tail 1) # touch
```

---

**That’s it.** You can now run locally or deploy to Kubernetes to produce **OTLP-shaped** audit logs with Alloy.
