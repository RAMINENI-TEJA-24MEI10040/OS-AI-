const { useState, useEffect, createElement: e } = React;

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
        observations: data.evidence.map(ev => ev.content),
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
    } finally {
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
    return e('span', { className: `px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider font-mono ${cls}` }, `[${status}]`);
  };

  const renderThreatBadge = (level) => {
    const colors = {
      CRITICAL: 'bg-red-900/60 text-red-300 border-red-700',
      HIGH: 'bg-orange-900/60 text-orange-300 border-orange-700',
      MEDIUM: 'bg-amber-900/60 text-amber-300 border-amber-700',
      LOW: 'bg-emerald-900/60 text-emerald-300 border-emerald-700'
    };
    const cls = colors[level] || 'bg-slate-800 text-slate-300 border-slate-700';
    return e('span', { className: `px-2.5 py-1 rounded border text-xs font-bold font-mono tracking-widest ${cls}` }, `THREAT LEVEL: ${level}`);
  };

  return e('div', { className: 'min-h-screen flex flex-col' },
    // HEADER
    e('header', { className: 'border-b border-gray-800 bg-gray-950 px-6 py-4' },
      e('div', { className: 'max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4' },
        e('div', { className: 'flex items-center space-x-3' },
          e('div', { className: 'w-9 h-9 rounded bg-brand-600/20 border border-brand-500/40 flex items-center justify-center text-brand-500 font-mono font-bold text-lg' }, 'OT'),
          e('div', null,
            e('div', { className: 'flex items-center space-x-2' },
              e('h1', { className: 'text-xl font-bold tracking-tight text-white font-mono' }, 'OpenTrace AI'),
              e('span', { className: 'text-xs px-2 py-0.5 rounded bg-brand-950 text-brand-400 border border-brand-800 font-mono' }, 'v1.0.0')
            ),
            e('p', { className: 'text-xs text-gray-400' }, 'Evidence-Grounded Open-Source AI Cyber Investigation Agent')
          )
        ),
        e('div', { className: 'flex items-center space-x-3 text-xs font-mono' },
          e('div', { className: 'flex items-center space-x-1.5 px-3 py-1.5 rounded bg-gray-900 border border-gray-800 text-gray-300' },
            e('span', { className: 'w-2 h-2 rounded-full bg-emerald-500 animate-pulse-subtle' }),
            e('span', null, `DB: ${dbMode}`)
          ),
          e('div', { className: 'flex items-center space-x-1.5 px-3 py-1.5 rounded bg-gray-900 border border-gray-800 text-gray-300' },
            e('span', { className: 'w-2 h-2 rounded-full bg-sky-500' }),
            e('span', null, 'Model: Open-Weight Harness')
          )
        )
      )
    ),

    // MAIN CONTENT AREA
    e('main', { className: 'flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6' },
      // SEARCH BAR
      e('div', { className: 'cyber-card rounded-lg p-5' },
        e('label', { className: 'block text-xs font-mono font-semibold uppercase tracking-wider text-gray-400 mb-2' }, 'Target Indicator Investigation Console'),
        e('div', { className: 'flex flex-col sm:flex-row gap-3' },
          e('input', {
            type: 'text',
            value: indicatorInput,
            onChange: (evt) => setIndicatorInput(evt.target.value),
            onKeyDown: (evt) => evt.key === 'Enter' && handleInvestigate(),
            placeholder: 'Enter IP (e.g. 1.1.1.1), Domain (phish-site.org), File Hash, URL, Crypto Wallet, or Raw Log text...',
            className: 'flex-1 bg-gray-900 border border-gray-700 rounded px-4 py-2.5 text-sm font-mono text-white placeholder-gray-500 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 transition'
          }),
          e('button', {
            onClick: () => handleInvestigate(),
            disabled: loading || !indicatorInput.trim(),
            className: 'bg-brand-600 hover:bg-brand-500 disabled:bg-gray-800 disabled:text-gray-600 text-white font-mono font-medium text-sm px-6 py-2.5 rounded transition flex items-center justify-center space-x-2 shrink-0'
          }, loading ? 'INVESTIGATING...' : 'INVESTIGATE INDICATOR')
        ),
        // Presets
        e('div', { className: 'mt-3 flex flex-wrap items-center gap-2 text-xs font-mono text-gray-400' },
          e('span', { className: 'text-gray-500' }, 'Quick Test Presets:'),
          e('button', {
            onClick: () => { setIndicatorInput('malicious-phish-domain.com'); handleInvestigate('malicious-phish-domain.com'); },
            className: 'px-2 py-1 bg-gray-900 hover:bg-gray-800 border border-gray-800 rounded text-gray-300 transition'
          }, 'Domain (phish-site.com)'),
          e('button', {
            onClick: () => { setIndicatorInput('1.1.1.1'); handleInvestigate('1.1.1.1'); },
            className: 'px-2 py-1 bg-gray-900 hover:bg-gray-800 border border-gray-800 rounded text-gray-300 transition'
          }, 'IPv4 (1.1.1.1)'),
          e('button', {
            onClick: () => { setIndicatorInput('131f44c51e084442bca4325d77b1b4ee166738c37725a761690925f8928ed06e'); handleInvestigate('131f44c51e084442bca4325d77b1b4ee166738c37725a761690925f8928ed06e'); },
            className: 'px-2 py-1 bg-gray-900 hover:bg-gray-800 border border-gray-800 rounded text-gray-300 transition'
          }, 'WannaCry Hash'),
          e('button', {
            onClick: () => {
              const sampleLog = "Unauthorized ssh access attempt from IP 198.51.100.45 attempting to download payload from http://malware-drop.org/payload.exe";
              setIndicatorInput(sampleLog);
              handleInvestigate(sampleLog);
            },
            className: 'px-2 py-1 bg-gray-900 hover:bg-gray-800 border border-gray-800 rounded text-gray-300 transition'
          }, 'Suspicious Log Event')
        )
      ),

      // ERROR DISPLAY
      error && e('div', { className: 'bg-red-950/80 border border-red-800 text-red-300 px-4 py-3 rounded-lg text-sm font-mono flex items-center space-x-2' },
        e('span', { className: 'font-bold' }, '[SECURITY NOTICE / ERROR]'),
        e('span', null, error)
      ),

      // ACTIVE CASE DASHBOARD
      activeCase ? e('div', { className: 'space-y-6' },
        // SUMMARY HEADER
        e('div', { className: 'cyber-card rounded-lg p-6' },
          e('div', { className: 'flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-gray-800' },
            e('div', null,
              e('div', { className: 'flex items-center space-x-3 mb-1' },
                e('div', { className: 'flex items-center space-x-1.5', title: activeCase.case_id },
                  e('span', { className: 'font-mono text-xs text-gray-400' }, 'CASE ID:'),
                  e('span', { className: 'font-mono text-xs font-bold text-gray-300 bg-gray-900 px-2 py-0.5 rounded border border-gray-800' }, activeCase.case_id),
                  e('button', {
                    onClick: copyFullCaseId,
                    className: 'text-xs font-mono text-brand-400 hover:text-brand-300 px-1.5 py-0.5 rounded bg-gray-900 border border-gray-800 transition'
                  }, copiedCaseId ? 'COPIED!' : 'COPY ID')
                ),
                renderThreatBadge(activeCase.threat_level)
              ),
              e('h2', { className: 'text-2xl font-bold font-mono text-white tracking-tight break-all mt-2' }, activeCase.target_indicator),
              activeCase.raw_input && activeCase.raw_input !== activeCase.target_indicator && e('div', { className: 'text-xs font-mono text-gray-400 mt-1' },
                e('span', { className: 'text-gray-500' }, 'Original Raw Input: '), `"${activeCase.raw_input}"`
              ),
              e('div', { className: 'flex items-center space-x-3 mt-2 text-xs text-gray-400 font-mono' },
                e('span', { className: 'capitalize' }, `Target Type: ${activeCase.indicator_type}`),
                e('span', null, '•'),
                e('span', null, `Total Latency: ${activeCase.timing_ms?.total_investigation || 0} ms`)
              ),
              activeCase.threat_rationale && e('div', { className: 'mt-2 text-xs font-mono text-amber-300/90 bg-amber-950/30 p-2 rounded border border-amber-800/40' },
                e('span', { className: 'font-bold' }, 'Scoring Rationale: '), activeCase.threat_rationale
              )
            ),
            e('div', { className: 'flex items-center space-x-3 shrink-0' },
              e('button', {
                onClick: exportReport,
                className: 'bg-gray-800 hover:bg-gray-700 text-gray-200 font-mono text-xs px-4 py-2 rounded border border-gray-700 transition'
              }, 'EXPORT REPORT (.MD)')
            )
          ),
          // STATS GRID
          e('div', { className: 'grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4' },
            e('div', { className: 'bg-gray-950/60 p-3 rounded border border-gray-800/80' },
              e('div', { className: 'text-xs font-mono text-gray-400' }, 'EVIDENCE FEEDS'),
              e('div', { className: 'text-xl font-bold font-mono text-brand-400 mt-0.5' }, activeCase.summary?.total_evidence_count || 0)
            ),
            e('div', { className: 'bg-gray-950/60 p-3 rounded border border-gray-800/80' },
              e('div', { className: 'text-xs font-mono text-gray-400' }, 'RELATIONSHIPS'),
              e('div', { className: 'text-xl font-bold font-mono text-sky-400 mt-0.5' }, activeCase.summary?.relationships_count || 0)
            ),
            e('div', { className: 'bg-gray-950/60 p-3 rounded border border-gray-800/80' },
              e('div', { className: 'text-xs font-mono text-gray-400' }, 'VERIFIED FACTS'),
              e('div', { className: 'text-xl font-bold font-mono text-emerald-400 mt-0.5' }, activeCase.summary?.verification_breakdown?.VERIFIED || 0)
            ),
            e('div', { className: 'bg-gray-950/60 p-3 rounded border border-gray-800/80' },
              e('div', { className: 'text-xs font-mono text-gray-400' }, 'AI HYPOTHESES'),
              e('div', { className: 'text-xl font-bold font-mono text-amber-400 mt-0.5' },
                (activeCase.summary?.verification_breakdown?.HYPOTHESIS || 0) + (activeCase.summary?.verification_breakdown?.CORRELATED || 0) + (activeCase.summary?.verification_breakdown?.UNVERIFIED || 0)
              )
            )
          )
        ),

        // TAB SYSTEM
        e('div', { className: 'cyber-card rounded-lg overflow-hidden' },
          e('div', { className: 'flex border-b border-gray-800 bg-gray-950 px-4 pt-2 overflow-x-auto' },
            e('button', {
              onClick: () => setActiveTab('findings'),
              className: `px-4 py-2.5 font-mono text-xs font-semibold border-b-2 transition shrink-0 ${activeTab === 'findings' ? 'border-brand-500 text-brand-400 bg-gray-900/40' : 'border-transparent text-gray-400 hover:text-gray-200'}`
            }, `FINDINGS & HYPOTHESES (${activeCase.findings?.length || 0})`),
            e('button', {
              onClick: () => setActiveTab('evidence'),
              className: `px-4 py-2.5 font-mono text-xs font-semibold border-b-2 transition shrink-0 ${activeTab === 'evidence' ? 'border-brand-500 text-brand-400 bg-gray-900/40' : 'border-transparent text-gray-400 hover:text-gray-200'}`
            }, `EVIDENCE LEDGER (${activeCase.observations?.length || 0})`),
            e('button', {
              onClick: () => setActiveTab('relationships'),
              className: `px-4 py-2.5 font-mono text-xs font-semibold border-b-2 transition shrink-0 ${activeTab === 'relationships' ? 'border-brand-500 text-brand-400 bg-gray-900/40' : 'border-transparent text-gray-400 hover:text-gray-200'}`
            }, `RELATIONSHIP GRAPH (${activeCase.relationships?.length || 0})`),
            e('button', {
              onClick: () => setActiveTab('timings'),
              className: `px-4 py-2.5 font-mono text-xs font-semibold border-b-2 transition shrink-0 ${activeTab === 'timings' ? 'border-brand-500 text-brand-400 bg-gray-900/40' : 'border-transparent text-gray-400 hover:text-gray-200'}`
            }, 'PIPELINE TIMINGS')
          ),

          e('div', { className: 'p-6' },
            activeTab === 'findings' && e('div', { className: 'space-y-4' },
              activeCase.findings && activeCase.findings.length > 0 ? activeCase.findings.map((fn, idx) => {
                const isAi = fn.id && fn.id.startsWith("find_ai_");
                return e('div', {
                  key: idx,
                  className: `border rounded-lg p-4 space-y-2 ${isAi ? 'bg-amber-950/10 border-amber-800/40' : 'bg-gray-950 border-gray-800'}`
                },
                  e('div', { className: 'flex flex-wrap items-center justify-between gap-2' },
                    e('div', { className: 'flex items-center space-x-2' },
                      renderBadge(fn.verification_status),
                      e('h4', { className: 'font-mono text-sm font-bold text-white' }, fn.title)
                    ),
                    e('span', { className: 'font-mono text-xs px-2 py-0.5 rounded bg-gray-900 border border-gray-800 text-gray-300' },
                      fn.confidence_label || `Confidence: ${Math.round((fn.confidence || 0.5) * 100)}%`
                    )
                  ),
                  e('p', { className: 'text-sm text-gray-300 leading-relaxed font-sans pl-1' }, fn.hypothesis),
                  fn.evidence_sources && fn.evidence_sources.length > 0 ? e('div', { className: 'pt-2 flex items-center space-x-2 text-xs font-mono text-gray-400' },
                    e('span', null, 'Supporting Tool Sources:'),
                    fn.evidence_sources.map((src, sidx) => e('span', { key: sidx, className: 'px-2 py-0.5 bg-gray-900 border border-gray-800 rounded text-brand-400' }, src))
                  ) : e('div', { className: 'pt-2 text-xs font-mono text-amber-400/80' }, 'Note: Unverified Model Hypothesis (Zero Tool Evidence Sources)')
                );
              }) : e('p', { className: 'text-sm text-gray-500 font-mono' }, 'No findings recorded for this case.')
            ),

            activeTab === 'evidence' && e('div', { className: 'space-y-4' },
              activeCase.observations && activeCase.observations.length > 0 ? activeCase.observations.map((obs, idx) =>
                e('div', { key: idx, className: 'bg-gray-950 border border-gray-800 rounded-lg p-4' },
                  e('div', { className: 'flex flex-wrap items-center justify-between pb-2 border-b border-gray-800 mb-3 gap-2' },
                    e('div', { className: 'flex items-center space-x-2' },
                      e('span', { className: 'font-mono text-xs font-bold text-brand-400 uppercase' }, `TOOL FEED: ${obs.tool || 'DETERMINISTIC_TOOL'}`),
                      e('span', { className: 'font-mono text-xs text-gray-500' }, `Provenance: ${obs.provenance_type || 'TOOL_OUTPUT'}`)
                    ),
                    e('span', { className: 'font-mono text-xs text-emerald-400 uppercase' }, `STATUS: ${obs.status || 'SUCCESS'}`)
                  ),
                  e('pre', { className: 'text-xs font-mono text-gray-300 bg-gray-900 p-3 rounded border border-gray-800/80 overflow-x-auto' },
                    JSON.stringify(obs, null, 2)
                  )
                )
              ) : e('p', { className: 'text-sm text-gray-500 font-mono' }, 'No raw evidence observations recorded.')
            ),

            activeTab === 'relationships' && e('div', { className: 'space-y-4' },
              activeCase.relationships && activeCase.relationships.length > 0 ? e('div', { className: 'overflow-x-auto border border-gray-800 rounded-lg' },
                e('table', { className: 'w-full text-left font-mono text-xs' },
                  e('thead', { className: 'bg-gray-950 border-b border-gray-800 text-gray-400' },
                    e('tr', null,
                      e('th', { className: 'px-4 py-3' }, 'SOURCE ENTITY'),
                      e('th', { className: 'px-4 py-3' }, 'RELATIONSHIP TYPE'),
                      e('th', { className: 'px-4 py-3' }, 'TARGET ENTITY'),
                      e('th', { className: 'px-4 py-3' }, 'EVIDENCE TOOL / RATIONALE')
                    )
                  ),
                  e('tbody', { className: 'divide-y divide-gray-800 bg-gray-900/40' },
                    activeCase.relationships.map((rel, idx) => e('tr', { key: idx, className: 'hover:bg-gray-900/80 transition' },
                      e('td', { className: 'px-4 py-3 font-semibold text-brand-400' }, rel.source),
                      e('td', { className: 'px-4 py-3 text-sky-400' }, rel.type),
                      e('td', { className: 'px-4 py-3 text-emerald-400' }, rel.target),
                      e('td', { className: 'px-4 py-3 text-gray-400' }, rel.rationale || rel.evidence_tool || 'Deterministic Mapping')
                    ))
                  )
                )
              ) : e('p', { className: 'text-sm text-gray-500 font-mono' }, 'No entity relationships discovered.')
            ),

            activeTab === 'timings' && e('div', { className: 'space-y-4' },
              e('div', { className: 'bg-gray-950 border border-gray-800 rounded-lg p-5' },
                e('h4', { className: 'font-mono text-xs font-bold text-gray-400 uppercase tracking-wider mb-4' }, 'Investigation Latency Instrumentation Breakdown (ms)'),
                e('div', { className: 'space-y-3 font-mono text-xs' },
                  Object.entries(activeCase.timing_ms || {}).map(([key, val]) =>
                    e('div', { key: key, className: 'flex items-center justify-between py-1.5 border-b border-gray-800/60' },
                      e('span', { className: 'capitalize text-gray-300' }, `${key.replace('_', ' ')}:`),
                      e('span', { className: 'font-bold text-brand-400' }, `${val} ms`)
                    )
                  )
                )
              )
            )
          )
        )
      ) : e('div', { className: 'cyber-card rounded-lg p-12 text-center space-y-4' },
        e('div', { className: 'w-16 h-16 rounded-full bg-brand-950/60 border border-brand-800 flex items-center justify-center mx-auto text-brand-400 font-mono text-xl font-bold' }, '?'),
        e('div', { className: 'max-w-md mx-auto space-y-1' },
          e('h3', { className: 'text-lg font-bold font-mono text-white' }, 'No Target Active'),
          e('p', { className: 'text-xs text-gray-400' }, 'Enter an IP address, domain, URL, file hash, crypto wallet, or suspicious log snippet above to initiate an evidence-grounded cyber investigation.')
        )
      ),

      // HISTORY LEDGER
      e('div', { className: 'cyber-card rounded-lg p-6' },
        e('div', { className: 'flex items-center justify-between mb-4' },
          e('div', null,
            e('h3', { className: 'text-base font-bold font-mono text-white' }, 'Investigation History Ledger'),
            e('p', { className: 'text-xs text-gray-400' }, 'Persisted in Turso libSQL Cloud Database with indexed lookups')
          ),
          e('button', {
            onClick: fetchHistory,
            className: 'text-xs font-mono text-brand-400 hover:text-brand-300 transition'
          }, '[REFRESH LEDGER]')
        ),

        e('div', { className: 'overflow-x-auto border border-gray-800 rounded-lg' },
          e('table', { className: 'w-full text-left font-mono text-xs' },
            e('thead', { className: 'bg-gray-950 border-b border-gray-800 text-gray-400' },
              e('tr', null,
                e('th', { className: 'px-4 py-3' }, 'CASE ID'),
                e('th', { className: 'px-4 py-3' }, 'TARGET INDICATOR'),
                e('th', { className: 'px-4 py-3' }, 'TYPE'),
                e('th', { className: 'px-4 py-3' }, 'THREAT LEVEL'),
                e('th', { className: 'px-4 py-3' }, 'TIMESTAMP'),
                e('th', { className: 'px-4 py-3 text-right' }, 'ACTION')
              )
            ),
            e('tbody', { className: 'divide-y divide-gray-800 bg-gray-900/30' },
              historyCases && historyCases.length > 0 ? historyCases.map((c) =>
                e('tr', { key: c.id, className: 'hover:bg-gray-900/70 transition' },
                  e('td', { className: 'px-4 py-3 text-gray-400 font-mono text-xs', title: c.id },
                    c.id.length > 22 ? `${c.id.substring(0, 20)}...` : c.id
                  ),
                  e('td', { className: 'px-4 py-3 font-semibold text-white break-all' }, c.indicator),
                  e('td', { className: 'px-4 py-3 text-brand-400 uppercase' }, c.indicator_type),
                  e('td', { className: 'px-4 py-3' }, renderThreatBadge(c.threat_level)),
                  e('td', { className: 'px-4 py-3 text-gray-400' }, c.created_at),
                  e('td', { className: 'px-4 py-3 text-right' },
                    e('button', {
                      onClick: () => loadCaseFromHistory(c.id),
                      className: 'px-3 py-1 bg-brand-950 hover:bg-brand-900 border border-brand-800 text-brand-400 rounded transition'
                    }, 'LOAD CASE')
                  )
                )
              ) : e('tr', null,
                e('td', { colSpan: '6', className: 'px-4 py-6 text-center text-gray-500' }, 'No investigation cases in Turso ledger.')
              )
            )
          )
        )
      )
    ),

    // FOOTER
    e('footer', { className: 'border-t border-gray-800 bg-gray-950 px-6 py-4 mt-auto' },
      e('div', { className: 'max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between text-xs text-gray-500 font-mono gap-2' },
        e('div', null, 'OpenTrace AI — Apache-2.0 License'),
        e('div', null, 'Built for Best Open-Source AI Project Challenge')
      )
    )
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(e(App));
