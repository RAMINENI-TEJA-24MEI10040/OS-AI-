const { useState, useEffect } = React;

function App() {
  const [indicatorInput, setIndicatorInput] = useState('');
  const [activeCase, setActiveCase] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('findings');
  const [historyCases, setHistoryCases] = useState([]);
  const [dbMode, setDbMode] = useState('Turso libSQL Cloud');
  const [copiedCaseId, setCopiedCaseId] = useState(false);

  useEffect(() => {
    fetchHealth();
    fetchHistory();
  }, []);

  const fetchHealth = async () => {
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        const data = await res.json();
        setDbMode(data.database_mode || 'Turso libSQL Cloud');
      }
    } catch (e) {
      console.warn("Health check error:", e);
    }
  };

  const fetchHistory = async () => {
    try {
      const res = await fetch('/api/cases');
      if (res.ok) {
        const data = await res.json();
        setHistoryCases(data.cases || []);
      }
    } catch (e) {
      console.warn("Fetch history error:", e);
    }
  };

  const handleInvestigate = async (targetIndicator) => {
    const query = targetIndicator || indicatorInput;
    if (!query.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator: query.trim() })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Investigation failed');
      }

      setActiveCase(data);
      setActiveTab('findings');
      fetchHistory();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const loadCaseFromHistory = async (caseId) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/case/${caseId}`);
      if (!res.ok) throw new Error("Failed to load case details");
      const data = await res.json();
      
      const c = data.case;
      const formattedCase = {
        case_id: c.id,
        raw_input: c.raw_input || c.indicator,
        target_indicator: c.indicator,
        indicator_type: c.indicator_type,
        status: c.status,
        threat_level: c.threat_level,
        threat_scoring_engine: "Heuristic Rule Engine (Deterministic)",
        threat_rationale: "Loaded from Turso Database persistence ledger.",
        assessment: "Persisted investigation ledger entry.",
        summary: {
          total_evidence_count: data.evidence.length,
          relationships_count: data.relationships.length,
          verification_breakdown: {
            VERIFIED: data.findings.filter(f => f.verification_status === 'VERIFIED').length,
            CORRELATED: data.findings.filter(f => f.verification_status === 'CORRELATED').length,
            OBSERVED: data.findings.filter(f => f.verification_status === 'OBSERVED').length,
            HYPOTHESIS: data.findings.filter(f => f.verification_status === 'HYPOTHESIS').length,
            UNVERIFIED: data.findings.filter(f => f.verification_status === 'UNVERIFIED').length
          }
        },
        observations: data.evidence.map(e => e.content),
        relationships: data.relationships.map(r => ({
          source: r.source_indicator,
          target: r.target_indicator,
          type: r.relation_type
        })),
        findings: data.findings,
        timing_ms: { total_investigation: c.duration_ms || 0 }
      };

      setActiveCase(formattedCase);
      setActiveTab('findings');
    } catch (err) {
      setError(err.message);
    } fontally {
      setLoading(false);
    }
  };

  const copyFullCaseId = () => {
    if (!activeCase) return;
    navigator.clipboard.writeText(activeCase.case_id);
    setCopiedCaseId(true);
    setTimeout(() => setCopiedCaseId(false), 2000);
  };

  const exportReport = () => {
    if (!activeCase) return;
    window.open(`/api/export/${activeCase.case_id}`, '_blank');
  };

  const renderBadge = (status) => {
    const map = {
      VERIFIED: 'badge-verified',
      CORRELATED: 'badge-correlated',
      OBSERVED: 'badge-observed',
      HYPOTHESIS: 'badge-hypothesis',
      UNVERIFIED: 'badge-unverified'
    };
    const cls = map[status] || 'bg-gray-800 text-gray-300';
    return (
      <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider font-mono ${cls}`}>
        [{status}]
      </span>
    );
  };

  const renderThreatBadge = (level) => {
    const colors = {
      CRITICAL: 'bg-red-900/60 text-red-300 border-red-700',
      HIGH: 'bg-orange-900/60 text-orange-300 border-orange-700',
      MEDIUM: 'bg-amber-900/60 text-amber-300 border-amber-700',
      LOW: 'bg-emerald-900/60 text-emerald-300 border-emerald-700'
    };
    const cls = colors[level] || 'bg-slate-800 text-slate-300 border-slate-700';
    return (
      <span className={`px-2.5 py-1 rounded border text-xs font-bold font-mono tracking-widest ${cls}`}>
        THREAT LEVEL: {level}
      </span>
    );
  };

  return (
    <div className="min-h-screen flex flex-col">
      {/* HEADER */}
      <header className="border-b border-gray-800 bg-gray-950 px-6 py-4">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded bg-brand-600/20 border border-brand-500/40 flex items-center justify-center text-brand-500 font-mono font-bold text-lg">
              OT
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl font-bold tracking-tight text-white font-mono">OpenTrace AI</h1>
                <span className="text-xs px-2 py-0.5 rounded bg-brand-950 text-brand-400 border border-brand-800 font-mono">
                  v1.0.0
                </span>
              </div>
              <p className="text-xs text-gray-400">Evidence-Grounded Open-Source AI Cyber Investigation Agent</p>
            </div>
          </div>

          <div className="flex items-center space-x-3 text-xs font-mono">
            <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-gray-900 border border-gray-800 text-gray-300">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse-subtle"></span>
              <span>DB: {dbMode}</span>
            </div>
            <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-gray-900 border border-gray-800 text-gray-300">
              <span className="w-2 h-2 rounded-full bg-sky-500"></span>
              <span>Model: Open-Weight Harness</span>
            </div>
          </div>
        </div>
      </header>

      {/* MAIN CONTENT AREA */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6">
        {/* INVESTIGATION SEARCH BAR */}
        <div className="cyber-card rounded-lg p-5">
          <label className="block text-xs font-mono font-semibold uppercase tracking-wider text-gray-400 mb-2">
            Target Indicator Investigation Console
          </label>
          <div className="flex flex-col sm:flex-row gap-3">
            <input
              type="text"
              value={indicatorInput}
              onChange={(e) => setIndicatorInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleInvestigate()}
              placeholder="Enter IP (e.g. 1.1.1.1), Domain (phish-site.org), File Hash, URL, Crypto Wallet, or Raw Log text..."
              className="flex-1 bg-gray-900 border border-gray-700 rounded px-4 py-2.5 text-sm font-mono text-white placeholder-gray-500 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 transition"
            />
            <button
              onClick={() => handleInvestigate()}
              disabled={loading || !indicatorInput.trim()}
              className="bg-brand-600 hover:bg-brand-500 disabled:bg-gray-800 disabled:text-gray-600 text-white font-mono font-medium text-sm px-6 py-2.5 rounded transition flex items-center justify-center space-x-2 shrink-0"
            >
              {loading ? (
                <>
                  <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                  </svg>
                  <span>INVESTIGATING...</span>
                </>
              ) : (
                <span>INVESTIGATE INDICATOR</span>
              )}
            </button>
          </div>

          {/* Quick Presets */}
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs font-mono text-gray-400">
            <span className="text-gray-500">Quick Test Presets:</span>
            <button
              onClick={() => { setIndicatorInput('malicious-phish-domain.com'); handleInvestigate('malicious-phish-domain.com'); }}
              className="px-2 py-1 bg-gray-900 hover:bg-gray-800 border border-gray-800 rounded text-gray-300 transition"
            >
              Domain (phish-site.com)
            </button>
            <button
              onClick={() => { setIndicatorInput('1.1.1.1'); handleInvestigate('1.1.1.1'); }}
              className="px-2 py-1 bg-gray-900 hover:bg-gray-800 border border-gray-800 rounded text-gray-300 transition"
            >
              IPv4 (1.1.1.1)
            </button>
            <button
              onClick={() => { setIndicatorInput('131f44c51e084442bca4325d77b1b4ee166738c37725a761690925f8928ed06e'); handleInvestigate('131f44c51e084442bca4325d77b1b4ee166738c37725a761690925f8928ed06e'); }}
              className="px-2 py-1 bg-gray-900 hover:bg-gray-800 border border-gray-800 rounded text-gray-300 transition"
            >
              WannaCry Hash
            </button>
            <button
              onClick={() => {
                const sampleLog = "Unauthorized ssh access attempt from IP 198.51.100.45 attempting to download payload from http://malware-drop.org/payload.exe";
                setIndicatorInput(sampleLog);
                handleInvestigate(sampleLog);
              }}
              className="px-2 py-1 bg-gray-900 hover:bg-gray-800 border border-gray-800 rounded text-gray-300 transition"
            >
              Suspicious Log Event
            </button>
          </div>
        </div>

        {/* ERROR DISPLAY */}
        {error && (
          <div className="bg-red-950/80 border border-red-800 text-red-300 px-4 py-3 rounded-lg text-sm font-mono flex items-center space-x-2">
            <span className="font-bold">[SECURITY NOTICE / ERROR]</span>
            <span>{error}</span>
          </div>
        )}

        {/* ACTIVE CASE DASHBOARD */}
        {activeCase ? (
          <div className="space-y-6">
            {/* CASE SUMMARY HEADER */}
            <div className="cyber-card rounded-lg p-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-gray-800">
                <div>
                  <div className="flex items-center space-x-3 mb-1">
                    <div className="flex items-center space-x-1.5" title={activeCase.case_id}>
                      <span className="font-mono text-xs text-gray-400">CASE ID:</span>
                      <span className="font-mono text-xs font-bold text-gray-300 bg-gray-900 px-2 py-0.5 rounded border border-gray-800">
                        {activeCase.case_id}
                      </span>
                      <button
                        onClick={copyFullCaseId}
                        className="text-xs font-mono text-brand-400 hover:text-brand-300 px-1.5 py-0.5 rounded bg-gray-900 border border-gray-800 transition"
                      >
                        {copiedCaseId ? 'COPIED!' : 'COPY ID'}
                      </button>
                    </div>
                    {renderThreatBadge(activeCase.threat_level)}
                  </div>

                  <h2 className="text-2xl font-bold font-mono text-white tracking-tight break-all mt-2">
                    {activeCase.target_indicator}
                  </h2>

                  {activeCase.raw_input && activeCase.raw_input !== activeCase.target_indicator && (
                    <div className="text-xs font-mono text-gray-400 mt-1">
                      <span className="text-gray-500">Original Raw Input:</span> "{activeCase.raw_input}"
                    </div>
                  )}

                  <div className="flex items-center space-x-3 mt-2 text-xs text-gray-400 font-mono">
                    <span className="capitalize">Target Type: {activeCase.indicator_type}</span>
                    <span>•</span>
                    <span>Total Latency: {activeCase.timing_ms?.total_investigation || 0} ms</span>
                  </div>

                  {activeCase.threat_rationale && (
                    <div className="mt-2 text-xs font-mono text-amber-300/90 bg-amber-950/30 p-2 rounded border border-amber-800/40">
                      <span className="font-bold">Scoring Rationale:</span> {activeCase.threat_rationale}
                    </div>
                  )}
                </div>

                <div className="flex items-center space-x-3 shrink-0">
                  <button
                    onClick={exportReport}
                    className="bg-gray-800 hover:bg-gray-700 text-gray-200 font-mono text-xs px-4 py-2 rounded border border-gray-700 transition flex items-center space-x-1.5"
                  >
                    <span>EXPORT REPORT (.MD)</span>
                  </button>
                </div>
              </div>

              {/* SUMMARY STATS BAR */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4">
                <div className="bg-gray-950/60 p-3 rounded border border-gray-800/80">
                  <div className="text-xs font-mono text-gray-400">EVIDENCE FEEDS</div>
                  <div className="text-xl font-bold font-mono text-brand-400 mt-0.5">
                    {activeCase.summary?.total_evidence_count || 0}
                  </div>
                </div>
                <div className="bg-gray-950/60 p-3 rounded border border-gray-800/80">
                  <div className="text-xs font-mono text-gray-400">RELATIONSHIPS</div>
                  <div className="text-xl font-bold font-mono text-sky-400 mt-0.5">
                    {activeCase.summary?.relationships_count || 0}
                  </div>
                </div>
                <div className="bg-gray-950/60 p-3 rounded border border-gray-800/80">
                  <div className="text-xs font-mono text-gray-400">VERIFIED FACTS</div>
                  <div className="text-xl font-bold font-mono text-emerald-400 mt-0.5">
                    {activeCase.summary?.verification_breakdown?.VERIFIED || 0}
                  </div>
                </div>
                <div className="bg-gray-950/60 p-3 rounded border border-gray-800/80">
                  <div className="text-xs font-mono text-gray-400">AI HYPOTHESES</div>
                  <div className="text-xl font-bold font-mono text-amber-400 mt-0.5">
                    {(activeCase.summary?.verification_breakdown?.HYPOTHESIS || 0) + (activeCase.summary?.verification_breakdown?.CORRELATED || 0) + (activeCase.summary?.verification_breakdown?.UNVERIFIED || 0)}
                  </div>
                </div>
              </div>
            </div>

            {/* TABBED INVESTIGATION PANELS */}
            <div className="cyber-card rounded-lg overflow-hidden">
              {/* TAB STRIP */}
              <div className="flex border-b border-gray-800 bg-gray-950 px-4 pt-2 overflow-x-auto">
                <button
                  onClick={() => setActiveTab('findings')}
                  className={`px-4 py-2.5 font-mono text-xs font-semibold border-b-2 transition shrink-0 ${
                    activeTab === 'findings'
                      ? 'border-brand-500 text-brand-400 bg-gray-900/40'
                      : 'border-transparent text-gray-400 hover:text-gray-200'
                  }`}
                >
                  FINDINGS & HYPOTHESES ({activeCase.findings?.length || 0})
                </button>
                <button
                  onClick={() => setActiveTab('evidence')}
                  className={`px-4 py-2.5 font-mono text-xs font-semibold border-b-2 transition shrink-0 ${
                    activeTab === 'evidence'
                      ? 'border-brand-500 text-brand-400 bg-gray-900/40'
                      : 'border-transparent text-gray-400 hover:text-gray-200'
                  }`}
                >
                  EVIDENCE LEDGER ({activeCase.observations?.length || 0})
                </button>
                <button
                  onClick={() => setActiveTab('relationships')}
                  className={`px-4 py-2.5 font-mono text-xs font-semibold border-b-2 transition shrink-0 ${
                    activeTab === 'relationships'
                      ? 'border-brand-500 text-brand-400 bg-gray-900/40'
                      : 'border-transparent text-gray-400 hover:text-gray-200'
                  }`}
                >
                  RELATIONSHIP GRAPH ({activeCase.relationships?.length || 0})
                </button>
                <button
                  onClick={() => setActiveTab('timings')}
                  className={`px-4 py-2.5 font-mono text-xs font-semibold border-b-2 transition shrink-0 ${
                    activeTab === 'timings'
                      ? 'border-brand-500 text-brand-400 bg-gray-900/40'
                      : 'border-transparent text-gray-400 hover:text-gray-200'
                  }`}
                >
                  PIPELINE TIMINGS
                </button>
              </div>

              {/* TAB CONTENT PANELS */}
              <div className="p-6">
                {/* TAB 1: FINDINGS */}
                {activeTab === 'findings' && (
                  <div className="space-y-4">
                    {activeCase.findings && activeCase.findings.length > 0 ? (
                      activeCase.findings.map((f, i) => {
                        const isAiHypothesis = f.id && f.id.startsWith("find_ai_");
                        return (
                          <div 
                            key={i} 
                            className={`border rounded-lg p-4 space-y-2 ${
                              isAiHypothesis 
                                ? 'bg-amber-950/10 border-amber-800/40' 
                                : 'bg-gray-950 border-gray-800'
                            }`}
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <div className="flex items-center space-x-2">
                                {renderBadge(f.verification_status)}
                                <h4 className="font-mono text-sm font-bold text-white">{f.title}</h4>
                              </div>
                              <span className="font-mono text-xs px-2 py-0.5 rounded bg-gray-900 border border-gray-800 text-gray-300">
                                {f.confidence_label || `Confidence: ${Math.round((f.confidence || 0.5) * 100)}%`}
                              </span>
                            </div>
                            <p className="text-sm text-gray-300 leading-relaxed font-sans pl-1">
                              {f.hypothesis}
                            </p>
                            {f.evidence_sources && f.evidence_sources.length > 0 ? (
                              <div className="pt-2 flex items-center space-x-2 text-xs font-mono text-gray-400">
                                <span>Supporting Tool Sources:</span>
                                {f.evidence_sources.map((s, idx) => (
                                  <span key={idx} className="px-2 py-0.5 bg-gray-900 border border-gray-800 rounded text-brand-400">
                                    {s}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <div className="pt-2 text-xs font-mono text-amber-400/80">
                                <span>Note: Unverified Model Hypothesis (Zero Tool Evidence Sources)</span>
                              </div>
                            )}
                          </div>
                        );
                      })
                    ) : (
                      <p className="text-sm text-gray-500 font-mono">No findings recorded for this case.</p>
                    )}
                  </div>
                )}

                {/* TAB 2: EVIDENCE LEDGER */}
                {activeTab === 'evidence' && (
                  <div className="space-y-4">
                    {activeCase.observations && activeCase.observations.length > 0 ? (
                      activeCase.observations.map((obs, i) => (
                        <div key={i} className="bg-gray-950 border border-gray-800 rounded-lg p-4">
                          <div className="flex flex-wrap items-center justify-between pb-2 border-b border-gray-800 mb-3 gap-2">
                            <div className="flex items-center space-x-2">
                              <span className="font-mono text-xs font-bold text-brand-400 uppercase">
                                TOOL FEED: {obs.tool || 'DETERMINISTIC_TOOL'}
                              </span>
                              <span className="font-mono text-xs text-gray-500">
                                Provenance: {obs.provenance_type || 'TOOL_OUTPUT'}
                              </span>
                            </div>
                            <span className="font-mono text-xs text-emerald-400 uppercase">
                              STATUS: {obs.status || 'SUCCESS'}
                            </span>
                          </div>
                          <pre className="text-xs font-mono text-gray-300 bg-gray-900 p-3 rounded border border-gray-800/80 overflow-x-auto">
                            {JSON.stringify(obs, null, 2)}
                          </pre>
                        </div>
                      ))
                    ) : (
                      <p className="text-sm text-gray-500 font-mono">No raw evidence observations recorded.</p>
                    )}
                  </div>
                )}

                {/* TAB 3: RELATIONSHIP GRAPH */}
                {activeTab === 'relationships' && (
                  <div className="space-y-4">
                    {activeCase.relationships && activeCase.relationships.length > 0 ? (
                      <div className="overflow-x-auto border border-gray-800 rounded-lg">
                        <table className="w-full text-left font-mono text-xs">
                          <thead className="bg-gray-950 border-b border-gray-800 text-gray-400">
                            <tr>
                              <th className="px-4 py-3">SOURCE ENTITY</th>
                              <th className="px-4 py-3">RELATIONSHIP TYPE</th>
                              <th className="px-4 py-3">TARGET ENTITY</th>
                              <th className="px-4 py-3">EVIDENCE TOOL / RATIONALE</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-gray-800 bg-gray-900/40">
                            {activeCase.relationships.map((rel, i) => (
                              <tr key={i} className="hover:bg-gray-900/80 transition">
                                <td className="px-4 py-3 font-semibold text-brand-400">{rel.source}</td>
                                <td className="px-4 py-3 text-sky-400">{rel.type}</td>
                                <td className="px-4 py-3 text-emerald-400">{rel.target}</td>
                                <td className="px-4 py-3 text-gray-400">{rel.rationale || rel.evidence_tool || 'Deterministic Mapping'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <p className="text-sm text-gray-500 font-mono">No entity relationships discovered.</p>
                    )}
                  </div>
                )}

                {/* TAB 4: PIPELINE TIMINGS */}
                {activeTab === 'timings' && (
                  <div className="space-y-4">
                    <div className="bg-gray-950 border border-gray-800 rounded-lg p-5">
                      <h4 className="font-mono text-xs font-bold text-gray-400 uppercase tracking-wider mb-4">
                        Investigation Latency Instrumentation Breakdown (ms)
                      </h4>
                      <div className="space-y-3 font-mono text-xs">
                        {Object.entries(activeCase.timing_ms || {}).map(([key, val]) => (
                          <div key={key} className="flex items-center justify-between py-1.5 border-b border-gray-800/60">
                            <span className="capitalize text-gray-300">{key.replace('_', ' ')}:</span>
                            <span className="font-bold text-brand-400">{val} ms</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : (
          /* EMPTY STATE */
          <div className="cyber-card rounded-lg p-12 text-center space-y-4">
            <div className="w-16 h-16 rounded-full bg-brand-950/60 border border-brand-800 flex items-center justify-center mx-auto text-brand-400 font-mono text-xl font-bold">
              ?
            </div>
            <div className="max-w-md mx-auto space-y-1">
              <h3 className="text-lg font-bold font-mono text-white">No Target Active</h3>
              <p className="text-xs text-gray-400">
                Enter an IP address, domain, URL, file hash, crypto wallet, or suspicious log snippet above to initiate an evidence-grounded cyber investigation.
              </p>
            </div>
          </div>
        )}

        {/* INVESTIGATION HISTORY LEDGER (TURSO DB PERSISTENCE) */}
        <div className="cyber-card rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold font-mono text-white">Investigation History Ledger</h3>
              <p className="text-xs text-gray-400">Persisted in Turso libSQL Cloud Database with indexed lookups</p>
            </div>
            <button
              onClick={fetchHistory}
              className="text-xs font-mono text-brand-400 hover:text-brand-300 transition"
            >
              [REFRESH LEDGER]
            </button>
          </div>

          <div className="overflow-x-auto border border-gray-800 rounded-lg">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-gray-950 border-b border-gray-800 text-gray-400">
                <tr>
                  <th className="px-4 py-3">CASE ID</th>
                  <th className="px-4 py-3">TARGET INDICATOR</th>
                  <th className="px-4 py-3">TYPE</th>
                  <th className="px-4 py-3">THREAT LEVEL</th>
                  <th className="px-4 py-3">TIMESTAMP</th>
                  <th className="px-4 py-3 text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 bg-gray-900/30">
                {historyCases && historyCases.length > 0 ? (
                  historyCases.map((c) => (
                    <tr key={c.id} className="hover:bg-gray-900/70 transition">
                      <td className="px-4 py-3 text-gray-400 font-mono text-xs" title={c.id}>
                        {c.id.length > 22 ? `${c.id.substring(0, 20)}...` : c.id}
                      </td>
                      <td className="px-4 py-3 font-semibold text-white break-all">{c.indicator}</td>
                      <td className="px-4 py-3 text-brand-400 uppercase">{c.indicator_type}</td>
                      <td className="px-4 py-3">{renderThreatBadge(c.threat_level)}</td>
                      <td className="px-4 py-3 text-gray-400">{c.created_at}</td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => loadCaseFromHistory(c.id)}
                          className="px-3 py-1 bg-brand-950 hover:bg-brand-900 border border-brand-800 text-brand-400 rounded transition"
                        >
                          LOAD CASE
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="6" className="px-4 py-6 text-center text-gray-500">
                      No investigation cases in Turso ledger.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>

      {/* FOOTER */}
      <footer className="border-t border-gray-800 bg-gray-950 px-6 py-4 mt-auto">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between text-xs text-gray-500 font-mono gap-2">
          <div>OpenTrace AI — Apache-2.0 License</div>
          <div>Built for Best Open-Source AI Project Challenge</div>
        </div>
      </footer>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
