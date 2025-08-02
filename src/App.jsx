import { useState } from "react"
import { parseLogData } from "./utils/parseLogs.js"

export default function App() {
  const [logInput, setLogInput] = useState("")
  const [parsedData, setParsedData] = useState([])

  function handleParse() {
    const result = parseLogData(logInput)
    setParsedData(result)
    console.log("Total:", result.length)
    console.log("Suspicious:", result.filter(e => e.suspicious).length)
  }

  function handleExport() {
  const suspicious = parsedData.filter(e => e.suspicious)
  const blob = new Blob([JSON.stringify(suspicious, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'suspicious-connections.json'
  a.click()
  URL.revokeObjectURL(url)
}

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <h1 className="text-2xl font-bold mb-4">Small Network Threat Analyzer</h1>

      <textarea
        value={logInput}
        onChange={(e) => setLogInput(e.target.value)}
        className="w-full h-48 p-3 bg-gray-800 border border-gray-700 rounded resize-none mb-4"
        placeholder="Paste logs here..."
      />

      <button
        onClick={handleParse}
        className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded"
      >
        Analyze Logs
      </button>
            
            {parsedData.length > 0 && (
        <div className="mt-4 bg-gray-800 p-4 rounded border border-gray-700">
          <p>Total Connections: <span className="font-bold">{parsedData.length}</span></p>
          <p>Suspicious Connections:{" "}
            <span className="font-bold text-red-400">
              {parsedData.filter(e => e.suspicious).length}
            </span>
          </p>
          <p>
            Suspicion Rate:{" "}
            <span className="font-bold text-yellow-400">
              {Math.round(parsedData.filter(e => e.suspicious).length / parsedData.length * 100)}%
            </span>
          </p>
        </div>
      )}
      <button
        onClick={handleExport}
        className="mt-2 bg-green-700 hover:bg-green-800 px-3 py-1 rounded"
      >
        Export Suspicious as JSON
      </button>

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
              </tr>
            </thead>
            <tbody>
              {parsedData.map((entry, i) => (
              <tr
                  key={i}
                  style={entry.suspicious ? { backgroundColor: 'darkred', color: 'salmon', fontWeight: 'bold' } : {}}
              >

                  <td className="border px-2 py-1">{entry.timestamp}</td>
                  <td className="border px-2 py-1">{entry.src}</td>
                  <td className="border px-2 py-1">{entry.dst}</td>
                  <td className="border px-2 py-1">{entry.port}</td>
                  <td className="border px-2 py-1">{entry.proto}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
