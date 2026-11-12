package dashboard

import (
	"bytes"
	"html/template"

	"reverseresearch/internal/collaboration"
	"reverseresearch/internal/job"
	"reverseresearch/internal/packregistry"
	"reverseresearch/internal/remoteagent"
	"reverseresearch/internal/reporting"
	"reverseresearch/internal/toolindex"
)

type Operations struct {
	Jobs         []job.Job
	Tools        []toolindex.Tool
	Agents       []remoteagent.FleetEntry
	PackRegistry *packregistry.RegistryState
	ReviewQueue  []collaboration.ReviewQueueItem
}
type View struct {
	Document      reporting.Document
	Collaboration *collaboration.Workspace
	Operations    Operations
}

const page = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Document.Title}} 闂?ReverseResearch</title>
<style>
:root{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;background:#f6f7f9;color:#17191c}
body{margin:0}.top{background:#111827;color:#fff;padding:18px 28px}.top h1{margin:0;font-size:22px}.meta{opacity:.8;margin-top:6px;font-size:13px}
main{padding:22px;max-width:1400px;margin:auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.card,section{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px;box-shadow:0 1px 2px #00000008}.card b{font-size:28px;display:block}
section{margin-top:16px}h2{font-size:18px;margin:0 0 12px}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px;border-bottom:1px solid #eee;vertical-align:top}th{color:#4b5563}
.badge{display:inline-block;padding:2px 7px;border-radius:999px;background:#eef2ff;font-size:12px}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}
.empty{color:#6b7280}details{margin:7px 0}summary{cursor:pointer;font-weight:600}
</style></head><body>
<div class="top"><h1>{{.Document.Title}}</h1><div class="meta">Case {{.Document.CaseID}} 闁?{{.Document.Route}} 闁?profile {{.Document.Profile}} 闁?{{.Document.Classification}} 闁?SHA-256 {{.Document.CaseSHA256}}</div></div>
<main>
<div class="grid">
<div class="card"><b>{{.Document.Summary.Targets}}</b>Targets</div>
<div class="card"><b>{{.Document.Summary.Artifacts}}</b>Artifacts</div>
<div class="card"><b>{{.Document.Summary.Hypotheses}}</b>Hypotheses</div>
<div class="card"><b>{{.Document.Summary.Findings}}</b>Findings</div>
<div class="card"><b>{{.Document.Summary.Evidence}}</b>Evidence</div>
<div class="card"><b>{{.Document.Summary.AttackPaths}}</b>Research paths</div>
<div class="card"><b>{{.Document.Summary.TTPs}}</b>ATT&CK / TTP</div>
<div class="card"><b>{{.Document.Summary.ValidatedDetections}}/{{.Document.Summary.Detections}}</b>Validated detections</div>
<div class="card"><b>{{.Document.Summary.Retests}}</b>Retests</div>
<div class="card"><b>{{.Document.Summary.OpenWorkItems}}</b>Open work items</div>
</div>
<section><h2>Targets</h2>{{if .Document.Targets}}<table><tr><th>ID</th><th>Kind</th><th>Identity</th><th>Label</th></tr>{{range .Document.Targets}}<tr><td class="mono">{{.ID}}</td><td>{{.Kind}}</td><td class="mono">{{.Identity}}</td><td>{{.Label}}</td></tr>{{end}}</table>{{else}}<div class="empty">No targets.</div>{{end}}</section>
<section><h2>Artifacts</h2>{{if .Document.Artifacts}}<table><tr><th>ID</th><th>Kind</th><th>Identity</th><th>SHA-256</th><th>Source</th></tr>{{range .Document.Artifacts}}<tr><td class="mono">{{.ID}}</td><td>{{.Kind}}</td><td class="mono">{{.Identity}}</td><td class="mono">{{.SHA256}}</td><td>{{.Source}}</td></tr>{{end}}</table>{{else}}<div class="empty">No artifacts.</div>{{end}}</section>
<section><h2>Observations & Hypotheses</h2>{{if .Document.Observations}}<h3>Observations</h3>{{range .Document.Observations}}<details><summary>{{.ID}} 闁?{{.CreatedUTC}}</summary><div>{{.Summary}}</div></details>{{end}}{{end}}{{if .Document.Hypotheses}}<h3>Hypotheses</h3><table><tr><th>ID</th><th>Status</th><th>Hypothesis</th><th>Required experiment</th><th>Rejected reason</th></tr>{{range .Document.Hypotheses}}<tr><td class="mono">{{.ID}}</td><td>{{.Status}}</td><td>{{.Hypothesis}}</td><td>{{.RequiredExperiment}}</td><td>{{.RejectedReason}}</td></tr>{{end}}</table>{{else}}<div class="empty">No hypotheses.</div>{{end}}</section>
<section><h2>Findings</h2>{{if .Document.Findings}}<table><tr><th>ID</th><th>Title</th><th>Strength</th><th>Severity</th><th>Affected asset</th><th>Conclusion</th></tr>{{range .Document.Findings}}<tr><td class="mono">{{.ID}}</td><td>{{.Title}}</td><td><span class="badge">{{.Strength}}</span></td><td>{{.Severity}}</td><td>{{.AffectedAsset}}</td><td>{{.Conclusion}}</td></tr>{{end}}</table>{{else}}<div class="empty">No findings.</div>{{end}}</section>
<section><h2>Evidence</h2>{{if .Document.Evidence}}<table><tr><th>ID</th><th>Kind</th><th>Summary</th><th>Source SHA-256</th></tr>{{range .Document.Evidence}}<tr><td class="mono">{{.ID}}</td><td>{{.Kind}}</td><td>{{.Summary}}</td><td class="mono">{{.SourceSHA256}}</td></tr>{{end}}</table>{{else}}<div class="empty">No evidence.</div>{{end}}</section>
<section><h2>Research Paths / Attack Paths</h2>{{if .Document.Paths}}<table><tr><th>ID</th><th>Title</th><th>Status</th><th>Finding IDs</th></tr>{{range .Document.Paths}}<tr><td class="mono">{{.ID}}</td><td>{{.Title}}</td><td>{{.Status}}</td><td>{{range .FindingIDs}}<span class="badge">{{.}}</span> {{end}}</td></tr>{{end}}</table>{{else}}<div class="empty">No research paths.</div>{{end}}</section>
<section><h2>ATT&CK / TTP</h2>{{if .Document.TTPs}}<table><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Findings</th></tr>{{range .Document.TTPs}}<tr><td class="mono">{{.ID}}</td><td>{{.Technique}}</td><td>{{.Tactic}}</td><td>{{range .FindingIDs}}<span class="badge">{{.}}</span> {{end}}</td></tr>{{end}}</table>{{else}}<div class="empty">No TTP mappings.</div>{{end}}</section>
<section><h2>Mitigations</h2>{{if .Document.Mitigations}}<table><tr><th>ID</th><th>Technique</th><th>Summary</th></tr>{{range .Document.Mitigations}}<tr><td class="mono">{{.ID}}</td><td>{{.Technique}}</td><td>{{.Summary}}</td></tr>{{end}}</table>{{else}}<div class="empty">No mitigations.</div>{{end}}</section>
<section><h2>Detection & Retest</h2>{{if .Document.Detections}}<table><tr><th>Name</th><th>Kind</th><th>Technique</th><th>Validated</th><th>Revision</th></tr>{{range .Document.Detections}}<tr><td>{{.Name}}</td><td>{{.Kind}}</td><td>{{.Technique}}</td><td>{{.Validated}}</td><td class="mono">{{.Revision}}</td></tr>{{end}}</table>{{else}}<div class="empty">No detections.</div>{{end}}</section>
<section><h2>Reports & Case Work</h2>{{if .Document.Reports}}<h3>Reports</h3><table><tr><th>ID</th><th>Kind</th><th>Format</th><th>Status</th><th>Revision</th></tr>{{range .Document.Reports}}<tr><td class="mono">{{.ID}}</td><td>{{.Kind}}</td><td>{{.Format}}</td><td>{{.Status}}</td><td class="mono">{{.Revision}}</td></tr>{{end}}</table>{{end}}{{if .Document.WorkItems}}<h3>Work items</h3><table><tr><th>ID</th><th>Title</th><th>Status</th><th>Owner</th></tr>{{range .Document.WorkItems}}<tr><td class="mono">{{.ID}}</td><td>{{.Title}}</td><td>{{.Status}}</td><td>{{.Owner}}</td></tr>{{end}}</table>{{else}}<div class="empty">No Case work items.</div>{{end}}</section>
<section><h2>Jobs</h2>{{if .Operations.Jobs}}<table><tr><th>Job</th><th>Operation</th><th>Target</th><th>Action</th><th>Effect</th><th>State</th></tr>{{range .Operations.Jobs}}<tr><td class="mono">{{.ID}}</td><td class="mono">{{.OperationID}}</td><td>{{.Target}}</td><td>{{.Action}}</td><td>{{.EffectClass}}</td><td>{{.State}}</td></tr>{{end}}</table>{{else}}<div class="empty">No Generic Jobs.</div>{{end}}</section>
<section><h2>Tools</h2>{{if .Operations.Tools}}<table><tr><th>Name</th><th>Available</th><th>Version</th><th>Trust</th><th>Health</th><th>Path</th></tr>{{range .Operations.Tools}}<tr><td>{{.Name}}</td><td>{{.Available}}</td><td>{{.Version}}</td><td>{{.TrustStatus}}</td><td>{{.HealthStatus}}</td><td class="mono">{{.Path}}</td></tr>{{end}}</table>{{else}}<div class="empty">No tool index entries.</div>{{end}}</section>
<section><h2>Remote Agent Fleet</h2>{{if .Operations.Agents}}<table><tr><th>Agent</th><th>State</th><th>Last seen</th><th>Version</th><th>Manifest revision</th><th>Capabilities</th><th>Queue</th><th>TLS certificate</th></tr>{{range .Operations.Agents}}<tr><td class="mono">{{.Registration.Manifest.AgentID}}</td><td><span class="badge">{{.State}}</span><br>manifest: {{.ManifestState}}</td><td>{{.LastSeenUTC}}</td><td>{{if .Status}}{{.Status.Status.AgentVersion}}{{else}}-{{end}}</td><td class="mono">{{.Registration.Revision}}</td><td>{{range .Registration.Manifest.Capabilities}}<span class="badge">{{.}}</span> {{end}}</td><td>{{if .Status}}running {{.Status.Status.Queue.RunningJobs}} / terminal {{.Status.Status.Queue.TerminalResults}}{{else}}unseen{{end}}</td><td>{{.CertificateState}}{{if .Status}} 鐠?{{.Status.Transport.ServerCertificateNotAfterUTC}}{{end}}</td></tr>{{end}}</table>{{else}}<div class="empty">No registered Remote Agents.</div>{{end}}</section>
<section><h2>Signed Pack Registry</h2>{{if .Operations.PackRegistry}}<div>Revision: <span class="mono">{{.Operations.PackRegistry.Revision}}</span> 鐠?trusted publishers {{len .Operations.PackRegistry.TrustedKeys}} 鐠?verification receipts {{len .Operations.PackRegistry.Receipts}}</div>{{if .Operations.PackRegistry.Packs}}<h3>Pack lifecycle</h3><table><tr><th>Receipt</th><th>Pack</th><th>Version</th><th>Status</th><th>Data-only</th><th>Requires adapter</th></tr>{{range $receipt,$pack := .Operations.PackRegistry.Packs}}<tr><td class="mono">{{$receipt}}</td><td>{{$pack.Manifest.ID}}</td><td>{{$pack.Manifest.PackVersion}}</td><td>{{$pack.Status}}</td><td>{{$pack.Policy.DataOnly}}</td><td>{{$pack.Policy.RequiresAdapter}}</td></tr>{{end}}</table>{{end}}{{if .Operations.PackRegistry.Receipts}}<h3>Verification receipts</h3><table><tr><th>Receipt</th><th>Pack</th><th>Version</th><th>Kind</th><th>Publisher</th><th>Verified</th></tr>{{range .Operations.PackRegistry.Receipts}}<tr><td class="mono">{{.ID}}</td><td>{{.PackID}}</td><td>{{.PackVersion}}</td><td>{{.Kind}}</td><td>{{.Publisher}}</td><td>{{.VerifiedUTC}}</td></tr>{{end}}</table>{{end}}{{else}}<div class="empty">Pack registry not initialized.</div>{{end}}</section><section><h2>Timeline</h2>{{if .Document.Timeline}}{{range .Document.Timeline}}<details><summary>{{.CreatedUTC}} 闁?{{.Kind}}</summary><div>{{.Summary}}</div></details>{{end}}{{else}}<div class="empty">No timeline entries.</div>{{end}}</section>
{{if .Collaboration}}<section><h2>Collaboration</h2><div>Owner: <b>{{.Collaboration.CaseOwner}}</b> 闁?revision <span class="mono">{{.Collaboration.Revision}}</span></div>
<h3>Participants</h3><table><tr><th>Subject</th><th>Role</th><th>Status</th></tr>{{range .Collaboration.Participants}}<tr><td>{{.Subject}}</td><td>{{.Role}}</td><td>{{.Status}}</td></tr>{{end}}</table>
<h3>Tasks</h3>{{if .Collaboration.Tasks}}<table><tr><th>ID</th><th>Title</th><th>Owner</th><th>Status</th></tr>{{range .Collaboration.Tasks}}<tr><td class="mono">{{.ID}}</td><td>{{.Title}}</td><td>{{.Owner}}</td><td>{{.Status}}</td></tr>{{end}}</table>{{else}}<div class="empty">No collaboration tasks.</div>{{end}}
<h3>Review queue</h3>{{if .Operations.ReviewQueue}}<table><tr><th>State</th><th>Kind</th><th>Subject</th><th>Requested by</th><th>Source revision</th><th>Review</th></tr>{{range .Operations.ReviewQueue}}<tr><td><span class="badge">{{.State}}</span></td><td>{{.Review.Kind}}</td><td class="mono">{{.Review.SubjectID}}</td><td>{{.Review.RequestedBy}}</td><td class="mono">{{.Review.SourceRevision}}</td><td class="mono">{{.Review.ID}}</td></tr>{{end}}</table>{{else}}<div class="empty">No current or stale review items.</div>{{end}}
<h3>Evidence locks</h3>{{if .Collaboration.EvidenceLocks}}<table><tr><th>Evidence</th><th>Locked by</th><th>Reason</th><th>Time</th></tr>{{range .Collaboration.EvidenceLocks}}<tr><td class="mono">{{.EvidenceID}}</td><td>{{.LockedBy}}</td><td>{{.Reason}}</td><td>{{.LockedUTC}}</td></tr>{{end}}</table>{{else}}<div class="empty">No evidence locks.</div>{{end}}
</section>{{end}}
</main></body></html>`

func Render(doc reporting.Document, workspace *collaboration.Workspace, operations Operations) ([]byte, error) {
	t, err := template.New("dashboard").Parse(page)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, View{Document: doc, Collaboration: workspace, Operations: operations}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
