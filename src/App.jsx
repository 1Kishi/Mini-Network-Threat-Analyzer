import { useState } from "react";
import { parseLogData } from "./utils/parseLogs";

const SERVICE_RULES = [
  { proto: "TCP", port: 20, name: "FTP", base: 2 },
  { proto: "TCP", port: 21, name: "FTP", base: 2 },
  { proto: "TCP", port: 22, name: "SSH", base: 1 },
  { proto: "TCP", port: 23, name: "Telnet", base: 2 },
  { proto: "TCP", port: 80, name: "HTTP", base: 1 },
  { proto: "TCP", port: 111, name: "RPC", base: 1 },
  { proto: "TCP", port: 445, name: "SMB", base: 2 },
  { proto: "TCP", port: 512, name: "Rexec", base: 2 },
  { proto: "TCP", port: 513, name: "Rlogin", base: 2 },
  { proto: "TCP", port: 514, name: "Rsh", base: 2 },
  { proto: "TCP", range: [5900, 5999], name: "VNC", base: 2 },
  { proto: "TCP", port: 3389, name: "RDP", base: 2 },
  { proto: "TCP", port: 5985, name: "WinRM", base: 2 },
  { proto: "TCP", port: 5986, name: "WinRM", base: 2 },
  { proto: "TCP", port: 2375, name: "Docker", base: 2 },
  { proto: "TCP", port: 1433, name: "MSSQL", base: 1 },
  { proto: "TCP", port: 3306, name: "MySQL", base: 1 },
  { proto: "TCP", port: 5432, name: "PostgreSQL", base: 1 },
  { proto: "TCP", port: 27017, name: "MongoDB", base: 1 },
  { proto: "TCP", port: 9200, name: "Elasticsearch", base: 1 },
  { proto: "TCP", port: 9300, name: "Elasticsearch", base: 1 },
  { proto: "TCP", port: 6379, name: "Redis", base: 1 },
  { proto: "TCP", port: 2049, name: "NFS", base: 1 },
  { proto: "TCP", port: 7547, name: "TR-069", base: 1 },
  { proto: "UDP", port: 69, name: "TFTP", base: 2 },
  { proto: "UDP", port: 123, name: "NTP", base: 1 },
  { proto: "UDP", port: 137, name: "NetBIOS", base: 1 },
  { proto: "UDP", port: 138, name: "NetBIOS", base: 1 },
  { proto: "UDP", port: 139, name: "NetBIOS", base: 1 },
  { proto: "UDP", port: 161, name: "SNMP", base: 1 },
  { proto: "UDP", port: 1900, name: "SSDP", base: 1 },
  { proto: "UDP", port: 5353, name: "mDNS", base: 1 },
  { proto: "UDP", port: 5355, name: "LLMNR", base: 1 }
];

function findService(entry) {
  const p = Number(entry.port);
  for (const r of SERVICE_RULES) {
    if (r.proto !== entry.proto) continue;
    if (r.port && r.port === p) return { name: r.name, base: r.base };
    if (r.range && p >= r.range[0] && p <= r.range[1]) return { name: r.name, base: r.base };
  }
  return null;
}

function isPrivate(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(ip);
}

function toSeverity(score) {
  if (score >= 3) return "high";
  if (score === 2) return "medium";
  return "low";
}

function evalSuspicious(rows) {
  const counts = new Map();
  rows.forEach(r => {
    const k = `${r.src}->${r.dst}:${r.port}`;
    counts.set(k, (counts.get(k) || 0) + 1);
  });
  const out = [];
  for (const r of rows) {
    const svc = findService(r);
    const external = !isPrivate(r.dst);
    const repeated = (counts.get(`${r.src}->${r.dst}:${r.port}`) || 0) >= 3;
    let score = 0;
    if (svc) score += svc.base;
    if (external) score += 1;
    if (repeated) score += 1;
    if (score === 0) continue;
    const reasons = [];
    if (svc) reasons.push(`risky_service:${svc.name}`);
    if (external) reasons.push("external_dst");
    if (repeated) reasons.push("repeated_access");
    out.push({ ...r, reasons, score, severity: toSeverity(score), service: svc ? svc.name : null });
  }
  return out;
}

export default function App() {
  const [logInput, setLogInput] = useState("");
  const [parsedData, setParsedData] = useState([]);
  const [suspicious, setSuspicious] = useState([]);

  function handleParse() {
    const result = parseLogData(logInput);
    setParsedData(result);
    setSuspicious(evalSuspicious(result));
  }

  function handleExport() {
    const blob = new Blob([JSON.stringify(suspicious, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "suspicious.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  function rowSeverityFor(r) {
    const key = `${r.src}->${r.dst}:${r.port}:${r.timestamp}`;
    const hit = suspicious.find(s => `${s.src}->${s.dst}:${s.port}:${s.timestamp}` === key);
    return hit ? hit.severity : null;
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <h1 className="text-2xl font-bold mb-4">Mini Network Threat Analyzer</h1>

      <textarea
        value={logInput}
        onChange={e => setLogInput(e.target.value)}
        className="w-full h-48 p-3 bg-gray-800 border border-gray-700 rounded resize-none mb-4"
        placeholder="Paste logs here..."
      />

      <div className="flex gap-2">
        <button onClick={handleParse} className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded">Analyze Logs</button>
        {suspicious.length > 0 && (
          <button onClick={handleExport} className="bg-emerald-600 hover:bg-emerald-700 px-4 py-2 rounded">Export Suspicious as JSON</button>
        )}
      </div>

      <div className="mt-6">
        {parsedData.length > 0 && (
          <table className="w-full text-sm border-collapse mt-4">
            <thead>
              <tr className="bg-gray-700">
                <th className="border px-2 py-1">Timestamp</th>
                <th className="border px-2 py-1">Source</th>
                <th className="border px-2 py-1">Destination</th>
                <th className="border px-2 py-1">Port</th>
                <th className="border px-2 py-1">Protocol</th>
                <th className="border px-2 py-1">Service</th>
                <th className="border px-2 py-1">Severity</th>
                <th className="border px-2 py-1">Reasons</th>
              </tr>
            </thead>
            <tbody>
              {parsedData.map((r, i) => {
                const sev = rowSeverityFor(r);
                const rowCls = sev === "high" ? "bg-red-900/40" : sev === "medium" ? "bg-yellow-900/25" : "";
                const hit = suspicious.find(s => s.timestamp === r.timestamp && s.src === r.src && s.dst === r.dst && String(s.port) === String(r.port));
                return (
                  <tr key={i} className={`even:bg-gray-800 ${rowCls}`}>
                    <td className="border px-2 py-1">{r.timestamp}</td>
                    <td className="border px-2 py-1">{r.src}</td>
                    <td className="border px-2 py-1">{r.dst}</td>
                    <td className="border px-2 py-1">{r.port}</td>
                    <td className="border px-2 py-1">{r.proto}</td>
                    <td className="border px-2 py-1">{hit?.service || ""}</td>
                    <td className="border px-2 py-1 capitalize">{hit?.severity || ""}</td>
                    <td className="border px-2 py-1">{(hit?.reasons || []).join(", ")}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
