// NTRO Cybersecurity Orchestration Platform
// Main Application JavaScript

class NTROPlatform {
    constructor() {
        this.currentTab = 'overview';
        this.scanners = {
            network: { status: 'running', progress: 67 },
            vulnerability: { status: 'completed', progress: 100 },
            threat: { status: 'running', progress: 42 }
        };
        this.charts = {};
        this.liveFeedInterval = null;
        this.processingSteps = [
            'Parsing natural language query...',
            'Triggering relevant scanners...',
            'Retrieving contextual data via RAG...',
            'Processing through MCP pipeline...',
            'Generating attack path visualization...',
            'Creating provenance cards...',
            'Updating analyst dashboard...'
        ];
        this.currentTemplateCategory = 'threat_hunting';
        this.queryHistory = [];
        this.favoriteQueries = [];
        this.knowledgeSources = {
            'MITRE ATT&CK': { status: 'Active', confidence: 96, records: 14567, lastUpdated: '2025-10-15T13:00:00Z' },
            'CVE Database': { status: 'Active', confidence: 94, records: 234891, lastUpdated: '2025-10-15T12:45:00Z' },
            'Threat Connect': { status: 'Active', confidence: 87, records: 89342, lastUpdated: '2025-10-15T13:10:00Z' },
            'NIST Framework': { status: 'Active', confidence: 93, records: 1854, lastUpdated: '2025-10-15T12:30:00Z' },
            'SANS ISC': { status: 'Active', confidence: 91, records: 45672, lastUpdated: '2025-10-15T13:05:00Z' }
        };
        this.exampleQueries = {
            threat_hunting: [
                {
                    query: "Show me all lateral movement activities in the last 24 hours",
                    description: "Detects T1021 lateral movement techniques across network",
                    expected_results: 15,
                    confidence: 0.92
                },
                {
                    query: "Find suspicious PowerShell executions with encoded commands",
                    description: "Identifies T1059.001 PowerShell obfuscation attempts",
                    expected_results: 8,
                    confidence: 0.87
                },
                {
                    query: "Detect credential dumping attempts across domain controllers",
                    description: "Searches for T1003 credential access techniques",
                    expected_results: 3,
                    confidence: 0.95
                },
                {
                    query: "Identify potential APT29 tactics, techniques, and procedures",
                    description: "Correlates known APT29 TTPs with current environment",
                    expected_results: 12,
                    confidence: 0.89
                },
                {
                    query: "Search for living off the land binaries (LOLBins) usage",
                    description: "Detects legitimate tools used maliciously",
                    expected_results: 21,
                    confidence: 0.83
                }
            ],
            vulnerability_assessment: [
                {
                    query: "List critical vulnerabilities in Exchange servers",
                    description: "Shows CVE entries for Microsoft Exchange infrastructure",
                    expected_results: 7,
                    confidence: 0.96
                },
                {
                    query: "Show unpatched systems with internet exposure",
                    description: "Identifies vulnerable internet-facing assets",
                    expected_results: 34,
                    confidence: 0.91
                },
                {
                    query: "Find systems vulnerable to privilege escalation attacks",
                    description: "Lists assets susceptible to T1068 exploitation",
                    expected_results: 18,
                    confidence: 0.88
                },
                {
                    query: "Identify zero-day exploits in our environment",
                    description: "Searches for unknown vulnerability indicators",
                    expected_results: 2,
                    confidence: 0.76
                },
                {
                    query: "Check for misconfigurations in cloud services",
                    description: "Reviews cloud infrastructure security posture",
                    expected_results: 45,
                    confidence: 0.84
                }
            ],
            incident_response: [
                {
                    query: "Analyze the timeline of the recent phishing campaign",
                    description: "Reconstructs T1566 spearphishing attack sequence",
                    expected_results: 156,
                    confidence: 0.93
                },
                {
                    query: "Show impact assessment for CVE-2024-43532",
                    description: "Evaluates organizational exposure to specific CVE",
                    expected_results: 23,
                    confidence: 0.97
                },
                {
                    query: "Track persistence mechanisms used by threat actors",
                    description: "Identifies T1053, T1547 persistence techniques",
                    expected_results: 9,
                    confidence: 0.91
                },
                {
                    query: "Investigate unusual network traffic patterns",
                    description: "Analyzes network anomalies for T1071 application layer protocol",
                    expected_results: 67,
                    confidence: 0.79
                },
                {
                    query: "Find indicators of compromise (IOCs) for known APT groups",
                    description: "Searches environment for threat actor artifacts",
                    expected_results: 134,
                    confidence: 0.86
                }
            ],
            compliance_risk: [
                {
                    query: "Generate PCI DSS compliance report",
                    description: "Assesses payment card industry data security standards",
                    expected_results: 89,
                    confidence: 0.94
                },
                {
                    query: "Show NIST framework coverage gaps",
                    description: "Identifies missing cybersecurity framework controls",
                    expected_results: 27,
                    confidence: 0.92
                },
                {
                    query: "List assets without endpoint protection",
                    description: "Shows unprotected systems requiring security controls",
                    expected_results: 12,
                    confidence: 0.98
                },
                {
                    query: "Check for data exfiltration indicators",
                    description: "Detects T1041 exfiltration over C2 channel",
                    expected_results: 4,
                    confidence: 0.87
                },
                {
                    query: "Assess third-party vendor security risks",
                    description: "Evaluates supply chain security posture",
                    expected_results: 38,
                    confidence: 0.81
                }
            ],
            threat_intelligence: [
                {
                    query: "What are the latest TTPs for Lazarus Group?",
                    description: "Retrieves current tactics for DPRK-linked threat actor",
                    expected_results: 76,
                    confidence: 0.89
                },
                {
                    query: "Show emerging threats targeting healthcare sector",
                    description: "Industry-specific threat landscape analysis",
                    expected_results: 54,
                    confidence: 0.85
                },
                {
                    query: "Find attribution data for recent ransomware campaigns",
                    description: "Correlates ransomware families with threat actors",
                    expected_results: 43,
                    confidence: 0.82
                },
                {
                    query: "Analyze trends in supply chain attacks",
                    description: "Examines T1195 supply chain compromise patterns",
                    expected_results: 29,
                    confidence: 0.88
                },
                {
                    query: "Compare threat landscape with industry peers",
                    description: "Benchmarks security posture against similar organizations",
                    expected_results: 167,
                    confidence: 0.90
                }
            ]
        };
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadInitialData();
        this.startLiveFeed();
        this.initializeCharts();
        this.populateIntelSources();
        this.setupMCPPipeline();
        this.loadIncidents();
        this.loadScanners();
        this.loadProvenanceCards();
        this.initializeRAGInterface();
        this.loadKnowledgeSources();
    }

    setupEventListeners() {
        // Tab navigation
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabName = e.target.dataset.tab;
                this.switchTab(tabName);
            });
        });

        // Natural language query
        const queryInput = document.getElementById('nlQueryInput');
        const queryBtn = document.getElementById('queryBtn');
        
        queryBtn.addEventListener('click', () => this.processNLQuery());
        queryInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.processNLQuery();
        });
        queryInput.addEventListener('input', (e) => this.showQuerySuggestions(e.target.value));
        queryInput.addEventListener('focus', () => this.showQuerySuggestions(queryInput.value));
        queryInput.addEventListener('blur', () => {
            setTimeout(() => document.getElementById('querySuggestions').style.display = 'none', 200);
        });

        // Enhanced RAG interface
        document.getElementById('ragSearchBtn').addEventListener('click', () => this.performRAGSearch());
        document.getElementById('ragQuery').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.performRAGSearch();
        });
        document.getElementById('ragQuery').addEventListener('input', (e) => this.showRAGSuggestions(e.target.value));
        document.getElementById('ragQuery').addEventListener('focus', () => this.showRAGSuggestions(document.getElementById('ragQuery').value));
        document.getElementById('ragQuery').addEventListener('blur', () => {
            setTimeout(() => {
                const suggestions = document.getElementById('ragQuerySuggestions');
                if (suggestions) suggestions.style.display = 'none';
            }, 200);
        });
        
        // Template tabs
        document.querySelectorAll('.template-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const category = e.target.dataset.category;
                this.switchTemplateCategory(category);
            });
        });
        
        // Query controls
        document.getElementById('queryBuilderBtn').addEventListener('click', () => this.showQueryBuilder());
        document.getElementById('queryHistoryBtn').addEventListener('click', () => this.showQueryHistory());
        document.getElementById('exportResults').addEventListener('click', () => this.exportResults());
        document.getElementById('saveQuery').addEventListener('click', () => this.saveCurrentQuery());

        // Scanner controls
        document.getElementById('startAllScans').addEventListener('click', () => this.startAllScans());
        document.getElementById('stopAllScans').addEventListener('click', () => this.stopAllScans());

        // Attack path export
        document.getElementById('exportPath').addEventListener('click', () => this.exportAttackPath());

        // Incident selection
        document.addEventListener('click', (e) => {
            if (e.target.closest('.incident-item')) {
                this.selectIncident(e.target.closest('.incident-item'));
            }
        });
    }

    switchTab(tabName) {
        // Update active tab
        document.querySelectorAll('.nav-tab').forEach(tab => tab.classList.remove('active'));
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update active content
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        document.getElementById(tabName).classList.add('active');

        this.currentTab = tabName;

        // Initialize tab-specific features
        if (tabName === 'attack-paths') {
            this.initializeAttackGraph();
        }
    }

    loadInitialData() {
        // Sample threat data based on provided JSON
        this.threatData = {
            feeds: [
                { name: 'MITRE ATT&CK', status: 'Active', confidence: 95, lastUpdated: '2025-10-15T12:30:00Z' },
                { name: 'CVE Database', status: 'Active', confidence: 90, lastUpdated: '2025-10-15T12:25:00Z' },
                { name: 'Threat Connect', status: 'Active', confidence: 85, lastUpdated: '2025-10-15T12:20:00Z' }
            ],
            activeThreats: [
                {
                    id: 'T001',
                    name: 'APT29 Lateral Movement',
                    severity: 'critical',
                    confidence: 92,
                    technique: 'T1021.001',
                    description: 'Suspected APT29 activity using RDP for lateral movement',
                    affectedSystems: 15,
                    firstSeen: '2025-10-15T10:30:00Z',
                    status: 'Active'
                },
                {
                    id: 'T002',
                    name: 'Phishing Campaign',
                    severity: 'medium',
                    confidence: 87,
                    technique: 'T1566.001',
                    description: 'Spearphishing attachment campaign targeting finance department',
                    affectedSystems: 8,
                    firstSeen: '2025-10-15T09:15:00Z',
                    status: 'Investigating'
                },
                {
                    id: 'T003',
                    name: 'Credential Harvesting',
                    severity: 'critical',
                    confidence: 98,
                    technique: 'T1003.001',
                    description: 'LSASS memory dumping detected on multiple endpoints',
                    affectedSystems: 23,
                    firstSeen: '2025-10-15T08:45:00Z',
                    status: 'Containment'
                }
            ],
            vulnerabilities: [
                {
                    cveId: 'CVE-2024-43532',
                    severity: 'Critical',
                    cvssScore: 9.8,
                    affectedSystems: 45,
                    patchAvailable: true,
                    description: 'Remote code execution in Microsoft Exchange Server'
                },
                {
                    cveId: 'CVE-2024-21762',
                    severity: 'High',
                    cvssScore: 8.4,
                    affectedSystems: 12,
                    patchAvailable: true,
                    description: 'Privilege escalation in Windows Print Spooler'
                }
            ],
            metrics: {
                totalAssets: 1247,
                criticalVulnerabilities: 23,
                activeThreats: 12,
                securityScore: 78
            }
        };

        // Update dashboard metrics
        document.getElementById('criticalThreats').textContent = this.threatData.metrics.activeThreats;
        document.getElementById('vulnerabilities').textContent = this.threatData.metrics.criticalVulnerabilities;
        document.getElementById('totalAssets').textContent = this.threatData.metrics.totalAssets.toLocaleString();
        document.getElementById('securityScore').textContent = `${this.threatData.metrics.securityScore}%`;
    }

    initializeCharts() {
        // Threat Trends Chart
        const threatTrendsCtx = document.getElementById('threatTrendsChart').getContext('2d');
        this.charts.threatTrends = new Chart(threatTrendsCtx, {
            type: 'line',
            data: {
                labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                datasets: [{
                    label: 'Critical Threats',
                    data: [5, 8, 12, 15, 18, 12],
                    borderColor: '#dc2626',
                    backgroundColor: 'rgba(220, 38, 38, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Medium Threats',
                    data: [12, 15, 20, 25, 22, 18],
                    borderColor: '#ea580c',
                    backgroundColor: 'rgba(234, 88, 12, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        labels: { color: '#212529' }
                    }
                },
                scales: {
                    x: { 
                        ticks: { color: '#495057' },
                        grid: { color: '#dee2e6' }
                    },
                    y: { 
                        ticks: { color: '#495057' },
                        grid: { color: '#dee2e6' }
                    }
                }
            }
        });

        // Vulnerability Distribution Chart
        const vulnerabilityCtx = document.getElementById('vulnerabilityChart').getContext('2d');
        this.charts.vulnerability = new Chart(vulnerabilityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [23, 45, 67, 89],
                    backgroundColor: ['#dc2626', '#ea580c', '#f59e0b', '#059669']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        labels: { color: '#212529' }
                    }
                }
            }
        });
    }

    startLiveFeed() {
        const feedContainer = document.getElementById('liveFeed');
        const threats = [
            'Suspicious PowerShell execution detected',
            'Anomalous network traffic to known C2 server',
            'Failed login attempts from unusual location',
            'Malware signature detected in email attachment',
            'Privilege escalation attempt blocked',
            'DNS tunneling activity observed',
            'Lateral movement via SMB detected'
        ];

        let feedIndex = 0;
        this.liveFeedInterval = setInterval(() => {
            const threat = threats[feedIndex % threats.length];
            const severity = ['critical', 'high', 'medium', 'low'][Math.floor(Math.random() * 4)];
            const time = new Date().toLocaleTimeString();
            
            const feedItem = document.createElement('div');
            feedItem.className = 'feed-item';
            feedItem.innerHTML = `
                <div class="feed-severity ${severity}"></div>
                <div class="feed-content">
                    <div class="feed-title">${threat}</div>
                    <div class="feed-time">${time}</div>
                </div>
            `;
            
            feedContainer.insertBefore(feedItem, feedContainer.firstChild);
            
            // Keep only last 10 items
            if (feedContainer.children.length > 10) {
                feedContainer.removeChild(feedContainer.lastChild);
            }
            
            feedIndex++;
        }, 3000);

        // Initialize geographic threat map
        this.initializeGeoMap();
    }

    initializeGeoMap() {
        const mapContainer = document.getElementById('threatMap');
        const geoThreats = [
            { country: 'China', count: 1247, lat: 35.8617, lng: 104.1954 },
            { country: 'Russia', count: 892, lat: 61.5240, lng: 105.3188 },
            { country: 'North Korea', count: 567, lat: 40.3399, lng: 127.5101 },
            { country: 'Iran', count: 423, lat: 32.4279, lng: 53.6880 }
        ];

        mapContainer.innerHTML = geoThreats.map(threat => `
            <div style="margin-bottom: 12px; padding: 8px; background: #f8f9fa; border-radius: 4px; border-left: 3px solid #dc2626; border: 1px solid #e9ecef;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="color: #212529; font-weight: 500;">${threat.country}</span>
                    <span style="color: #dc2626; font-weight: 600;">${threat.count}</span>
                </div>
                <div style="font-size: 12px; color: #495057; margin-top: 4px;">Active threat sources</div>
            </div>
        `).join('');
    }

    showQuerySuggestions(query) {
        const suggestions = [
            'Show me lateral movement threats',
            'Analyze phishing campaigns',
            'Find credential harvesting activities',
            'Display APT29 related incidents',
            'Show critical vulnerabilities',
            'Analyze attack paths for domain controllers',
            'Find suspicious PowerShell executions',
            'Show threats from China',
            'Analyze MITRE ATT&CK T1021 techniques',
            'Display security score trends'
        ];

        const filtered = suggestions.filter(s => 
            s.toLowerCase().includes(query.toLowerCase()) && query.length > 0
        );

        const suggestionsContainer = document.getElementById('querySuggestions');
        if (filtered.length > 0 && query.length > 0) {
            suggestionsContainer.innerHTML = filtered.slice(0, 5).map(suggestion => 
                `<div class="suggestion-item" onclick="this.parentElement.style.display='none'; document.getElementById('nlQueryInput').value='${suggestion}'; ntroApp.processNLQuery();">${suggestion}</div>`
            ).join('');
            suggestionsContainer.style.display = 'block';
        } else {
            suggestionsContainer.style.display = 'none';
        }
    }

    processNLQuery() {
        const query = document.getElementById('nlQueryInput').value.trim();
        if (!query) return;

        this.showProcessingModal();
        
        // Simulate processing steps
        this.simulateProcessing().then(() => {
            this.hideProcessingModal();
            this.displayQueryResults(query);
            this.showAlert('Query processed successfully', 'success');
        });
    }

    simulateProcessing() {
        return new Promise((resolve) => {
            const steps = document.getElementById('processingSteps');
            steps.innerHTML = '';
            
            this.processingSteps.forEach((step, index) => {
                const stepElement = document.createElement('div');
                stepElement.className = 'processing-step';
                stepElement.innerHTML = `
                    <div class="step-icon">${index + 1}</div>
                    <span>${step}</span>
                `;
                steps.appendChild(stepElement);
            });

            let currentStep = 0;
            const interval = setInterval(() => {
                if (currentStep > 0) {
                    steps.children[currentStep - 1].classList.remove('active');
                    steps.children[currentStep - 1].classList.add('completed');
                    steps.children[currentStep - 1].querySelector('.step-icon').innerHTML = '✓';
                }
                
                if (currentStep < this.processingSteps.length) {
                    steps.children[currentStep].classList.add('active');
                    document.getElementById('processingText').textContent = this.processingSteps[currentStep];
                    currentStep++;
                } else {
                    clearInterval(interval);
                    resolve();
                }
            }, 800);
        });
    }

    displayQueryResults(query) {
        // Simulate switching to relevant tab based on query
        if (query.toLowerCase().includes('lateral movement') || query.toLowerCase().includes('attack path')) {
            this.switchTab('attack-paths');
        } else if (query.toLowerCase().includes('phishing') || query.toLowerCase().includes('threat')) {
            this.switchTab('threat-intel');
        } else if (query.toLowerCase().includes('vulnerability')) {
            this.switchTab('scanners');
        } else {
            this.switchTab('analyst-workbench');
        }
    }

    showProcessingModal() {
        document.getElementById('processingModal').classList.add('active');
    }

    hideProcessingModal() {
        document.getElementById('processingModal').classList.remove('active');
    }

    populateIntelSources() {
        const sourcesContainer = document.getElementById('intelSources');
        Object.entries(this.knowledgeSources).forEach(([name, data]) => {
            const sourceItem = document.createElement('div');
            sourceItem.className = 'source-item';
            sourceItem.innerHTML = `
                <div class="source-info">
                    <div class="source-name">${name}</div>
                    <div class="source-status">Confidence: ${data.confidence}% • ${data.records.toLocaleString()} records</div>
                </div>
                <div class="source-indicator ${data.status === 'Active' ? 'active' : ''}"></div>
            `;
            sourcesContainer.appendChild(sourceItem);
        });
    }

    initializeRAGInterface() {
        this.switchTemplateCategory('threat_hunting');
        this.loadKnowledgeSources();
    }

    switchTemplateCategory(category) {
        // Update active tab
        document.querySelectorAll('.template-tab').forEach(tab => tab.classList.remove('active'));
        document.querySelector(`[data-category="${category}"]`).classList.add('active');
        
        this.currentTemplateCategory = category;
        this.loadTemplateQueries(category);
    }

    loadTemplateQueries(category) {
        const templateContent = document.getElementById('templateContent');
        const queries = this.exampleQueries[category] || [];
        
        templateContent.innerHTML = queries.map(queryData => `
            <div class="example-query" onclick="ntroApp.selectExampleQuery('${queryData.query.replace(/'/g, '\\\'')}')">
                <div class="query-text">${queryData.query}</div>
                <div class="query-description">${queryData.description}</div>
                <div class="query-meta">
                    <span class="expected-results">${queryData.expected_results} results</span>
                    <span class="confidence-score">${Math.round(queryData.confidence * 100)}%</span>
                </div>
            </div>
        `).join('');
    }

    selectExampleQuery(query) {
        document.getElementById('ragQuery').value = query;
        this.performRAGSearch();
    }

    showRAGSuggestions(query) {
        const allQueries = Object.values(this.exampleQueries).flat();
        const suggestions = allQueries.filter(q => 
            q.query.toLowerCase().includes(query.toLowerCase()) && query.length > 2
        ).slice(0, 5);

        const suggestionsContainer = document.getElementById('ragQuerySuggestions');
        if (suggestions.length > 0 && query.length > 2) {
            suggestionsContainer.innerHTML = suggestions.map(suggestion => 
                `<div class="suggestion-item" onclick="document.getElementById('ragQuery').value='${suggestion.query.replace(/'/g, '\\\'')}'; ntroApp.performRAGSearch(); this.parentElement.style.display='none';">${suggestion.query}</div>`
            ).join('');
            suggestionsContainer.style.display = 'block';
        } else {
            suggestionsContainer.style.display = 'none';
        }
    }

    performRAGSearch() {
        const query = document.getElementById('ragQuery').value.trim();
        if (!query) return;

        // Add to query history
        if (!this.queryHistory.includes(query)) {
            this.queryHistory.unshift(query);
            if (this.queryHistory.length > 50) this.queryHistory.pop();
        }

        const resultsContainer = document.getElementById('ragResults');
        resultsContainer.innerHTML = `
            <div style="text-align: center; color: #495057; padding: 40px;">
                <div class="spinner" style="margin: 0 auto 20px;"></div>
                <div>Searching knowledge base...</div>
                <div style="font-size: 12px; margin-top: 8px; color: #6c757d;">Querying ${Object.keys(this.knowledgeSources).length} sources</div>
            </div>
        `;

        // Simulate progressive results loading
        setTimeout(() => this.displayProgressiveResults(query), 800);
    }

    displayProgressiveResults(query) {
        const resultsContainer = document.getElementById('ragResults');
        
        // Generate contextual results based on query keywords
        let mockResults = this.generateContextualResults(query);
        
        const startTime = Date.now();
        let resultIndex = 0;
        
        const displayResult = () => {
            if (resultIndex === 0) {
                resultsContainer.innerHTML = `
                    <div style="margin-bottom: 20px; padding: 12px; background: #e3f2fd; border-radius: 6px; border-left: 3px solid var(--color-primary);">
                        <div style="font-size: 14px; font-weight: 600; color: var(--color-primary); margin-bottom: 4px;">Query: "${query}"</div>
                        <div style="font-size: 12px; color: #495057;">Found ${mockResults.length} relevant results • Query time: ${((Date.now() - startTime) / 1000).toFixed(1)}s</div>
                    </div>
                `;
            }
            
            if (resultIndex < mockResults.length) {
                const result = mockResults[resultIndex];
                const resultHTML = `
                    <div class="rag-result-item" style="animation: slideIn 0.3s ease;">
                        <div class="rag-result-header">
                            <div class="rag-result-title">${result.title}</div>
                            <div class="result-confidence">${result.confidence}%</div>
                        </div>
                        <div class="rag-result-content">${result.content}</div>
                        <div class="result-meta">
                            <span class="result-source">${result.source}</span>
                            <span>${result.technique ? result.technique + ' • ' : ''}${result.timestamp}</span>
                        </div>
                    </div>
                `;
                
                resultsContainer.innerHTML += resultHTML;
                resultIndex++;
                setTimeout(displayResult, 400);
            } else {
                // Show knowledge sources used
                this.updateKnowledgeSourcesPanel(query);
            }
        };
        
        displayResult();
    }

    generateContextualResults(query) {
        const queryLower = query.toLowerCase();
        let results = [];
        
        // Lateral movement queries
        if (queryLower.includes('lateral movement') || queryLower.includes('rdp') || queryLower.includes('t1021')) {
            results = [
                {
                    title: 'MITRE ATT&CK T1021.001 - Remote Desktop Protocol',
                    content: 'Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user. This technique is commonly used for lateral movement within enterprise networks.',
                    confidence: 94,
                    source: 'MITRE ATT&CK',
                    technique: 'T1021.001',
                    timestamp: '2025-10-15 13:00 UTC'
                },
                {
                    title: 'Lateral Movement Detection - Network Monitoring',
                    content: 'Monitor for unusual RDP connections, especially to servers and workstations that typically do not receive such connections. Look for connections from administrative workstations to multiple systems.',
                    confidence: 89,
                    source: 'SANS ISC',
                    timestamp: '2025-10-15 12:45 UTC'
                },
                {
                    title: 'APT29 Lateral Movement Campaign - October 2025',
                    content: 'Recent APT29 campaigns have utilized RDP and WMI for lateral movement after initial compromise. The group focuses on domain controllers and high-value targets.',
                    confidence: 87,
                    source: 'Threat Connect',
                    timestamp: '2025-10-15 11:30 UTC'
                }
            ];
        }
        // PowerShell queries
        else if (queryLower.includes('powershell') || queryLower.includes('encoded') || queryLower.includes('t1059')) {
            results = [
                {
                    title: 'MITRE ATT&CK T1059.001 - PowerShell Execution',
                    content: 'Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment.',
                    confidence: 96,
                    source: 'MITRE ATT&CK',
                    technique: 'T1059.001',
                    timestamp: '2025-10-15 13:00 UTC'
                },
                {
                    title: 'Base64 Encoded PowerShell Detection',
                    content: 'Monitor for PowerShell execution with the -EncodedCommand parameter. Base64 encoding is commonly used to obfuscate malicious PowerShell commands.',
                    confidence: 92,
                    source: 'CVE Database',
                    timestamp: '2025-10-15 12:30 UTC'
                },
                {
                    title: 'PowerShell Obfuscation Techniques',
                    content: 'Threat actors use various obfuscation methods including string concatenation, variable substitution, and encoding to evade detection.',
                    confidence: 88,
                    source: 'NIST Framework',
                    timestamp: '2025-10-15 11:15 UTC'
                }
            ];
        }
        // APT29 queries
        else if (queryLower.includes('apt29') || queryLower.includes('cozy bear')) {
            results = [
                {
                    title: 'APT29 (Cozy Bear) - Current Threat Profile',
                    content: 'APT29 is a sophisticated threat group attributed to Russia\'s SVR. Known for long-term persistence and advanced techniques including WMI, PowerShell, and cloud services abuse.',
                    confidence: 95,
                    source: 'Threat Connect',
                    timestamp: '2025-10-15 12:00 UTC'
                },
                {
                    title: 'APT29 TTPs - Recent Updates',
                    content: 'Recent campaigns show increased use of legitimate cloud services, supply chain attacks, and advanced persistence mechanisms. Focus on healthcare and government sectors.',
                    confidence: 91,
                    source: 'MITRE ATT&CK',
                    timestamp: '2025-10-15 10:45 UTC'
                },
                {
                    title: 'Cozy Bear Detection Strategies',
                    content: 'Monitor for unusual WMI activity, PowerShell execution, and connections to known C2 infrastructure. Focus on long-term persistence indicators.',
                    confidence: 89,
                    source: 'SANS ISC',
                    timestamp: '2025-10-15 09:30 UTC'
                }
            ];
        }
        // Default general security results
        else {
            results = [
                {
                    title: 'Cybersecurity Framework Mapping',
                    content: 'NIST Cybersecurity Framework provides guidelines for identifying, protecting, detecting, responding to, and recovering from cybersecurity incidents.',
                    confidence: 93,
                    source: 'NIST Framework',
                    timestamp: '2025-10-15 12:30 UTC'
                },
                {
                    title: 'Threat Intelligence Integration',
                    content: 'Effective threat intelligence integration requires automated feeds, contextual analysis, and actionable insights for security operations teams.',
                    confidence: 87,
                    source: 'Threat Connect',
                    timestamp: '2025-10-15 11:45 UTC'
                },
                {
                    title: 'Security Monitoring Best Practices',
                    content: 'Implement continuous monitoring, behavioral analysis, and threat hunting capabilities to detect advanced persistent threats and zero-day exploits.',
                    confidence: 84,
                    source: 'SANS ISC',
                    timestamp: '2025-10-15 10:15 UTC'
                }
            ];
        }
        
        return results;
    }

    updateKnowledgeSourcesPanel(query) {
        const panel = document.getElementById('knowledgeSourcesPanel');
        if (!panel) return;
        
        panel.innerHTML = `
            <h5 style="margin-bottom: 12px; color: var(--color-text);">Knowledge Sources Queried</h5>
            ${Object.entries(this.knowledgeSources).map(([name, data]) => `
                <div class="knowledge-source-item">
                    <div class="source-details">
                        <div class="source-name">${name}</div>
                        <div class="source-meta">${data.records.toLocaleString()} records • Updated ${new Date(data.lastUpdated).toLocaleTimeString()}</div>
                    </div>
                    <div class="source-status">
                        <div class="source-indicator"></div>
                        <div class="source-confidence">${data.confidence}%</div>
                    </div>
                </div>
            `).join('')}
        `;
    }

    loadKnowledgeSources() {
        this.updateKnowledgeSourcesPanel('');
    }

    showQueryBuilder() {
        this.showAlert('Query Builder - Advanced filtering and Boolean operators', 'info');
        // In a real implementation, this would open a modal with drag-and-drop query building
    }

    showQueryHistory() {
        const historyHTML = this.queryHistory.length > 0 ? 
            this.queryHistory.slice(0, 10).map(q => `
                <div class="suggestion-item" onclick="document.getElementById('ragQuery').value='${q.replace(/'/g, '\\\'')}'; ntroApp.performRAGSearch();">${q}</div>
            `).join('') : 
            '<div style="padding: 20px; text-align: center; color: #6c757d;">No query history available</div>';
            
        const suggestions = document.getElementById('ragQuerySuggestions');
        suggestions.innerHTML = historyHTML;
        suggestions.style.display = 'block';
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            suggestions.style.display = 'none';
        }, 5000);
    }

    exportResults() {
        this.showAlert('Query results exported to JSON format', 'success');
        // In a real implementation, this would export the current results
    }

    saveCurrentQuery() {
        const query = document.getElementById('ragQuery').value.trim();
        if (!query) {
            this.showAlert('Please enter a query to save', 'warning');
            return;
        }
        
        if (!this.favoriteQueries.includes(query)) {
            this.favoriteQueries.push(query);
            this.showAlert('Query saved to favorites', 'success');
        } else {
            this.showAlert('Query already in favorites', 'info');
        }
    }

    setupMCPPipeline() {
        const pipelineContainer = document.getElementById('mcpPipeline');
        const stages = [
            { name: 'Parsing', status: 'Completed', metrics: { processed: 1247, errors: 0, rate: '99.8%' } },
            { name: 'Enrichment', status: 'Active', metrics: { enriched: 892, sources: 12, coverage: '87%' } },
            { name: 'Analysis', status: 'Active', metrics: { analyzed: 567, alerts: 23, accuracy: '94%' } },
            { name: 'Visualization', status: 'Queued', metrics: { generated: 234, exported: 45, quality: '96%' } }
        ];

        stages.forEach((stage, index) => {
            const stageElement = document.createElement('div');
            stageElement.className = `pipeline-stage ${stage.status === 'Active' ? 'processing' : ''}`;
            stageElement.innerHTML = `
                <div class="stage-header">
                    <div class="stage-name">${stage.name}</div>
                    <div class="stage-status">${stage.status}</div>
                </div>
                <div class="stage-metrics">
                    ${Object.entries(stage.metrics).map(([key, value]) => 
                        `<div><strong>${value}</strong><br><small>${key}</small></div>`
                    ).join('')}
                </div>
            `;
            pipelineContainer.appendChild(stageElement);
        });
    }

    initializeAttackGraph() {
        const graphContainer = document.getElementById('attackGraph');
        if (!graphContainer) return;

        // Create a simple attack path visualization
        graphContainer.innerHTML = `
            <svg width="100%" height="400" style="background: linear-gradient(135deg, #f8f9fa 0%, #ffffff 100%); border: 1px solid #e9ecef; border-radius: 6px;">
                <!-- Nodes -->
                <circle cx="100" cy="200" r="30" fill="#0066cc" stroke="#0052a3" stroke-width="2"/>
                <text x="100" y="205" text-anchor="middle" fill="white" font-size="10">Entry Point</text>
                
                <circle cx="250" cy="150" r="30" fill="#ea580c" stroke="#c2410c" stroke-width="2"/>
                <text x="250" y="155" text-anchor="middle" fill="white" font-size="10">Credential</text>
                
                <circle cx="250" cy="250" r="30" fill="#ea580c" stroke="#c2410c" stroke-width="2"/>
                <text x="250" y="255" text-anchor="middle" fill="white" font-size="10">Lateral Move</text>
                
                <circle cx="400" cy="200" r="30" fill="#dc2626" stroke="#b91c1c" stroke-width="2"/>
                <text x="400" y="205" text-anchor="middle" fill="white" font-size="10">DC Access</text>
                
                <!-- Connections -->
                <line x1="130" y1="190" x2="220" y2="160" stroke="#0066cc" stroke-width="2" marker-end="url(#arrowhead)"/>
                <line x1="130" y1="210" x2="220" y2="240" stroke="#0066cc" stroke-width="2" marker-end="url(#arrowhead)"/>
                <line x1="280" y1="160" x2="370" y2="190" stroke="#ea580c" stroke-width="2" marker-end="url(#arrowhead2)"/>
                <line x1="280" y1="240" x2="370" y2="210" stroke="#ea580c" stroke-width="2" marker-end="url(#arrowhead2)"/>
                
                <!-- Arrow markers -->
                <defs>
                    <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                        <polygon points="0 0, 10 3.5, 0 7" fill="#0066cc"/>
                    </marker>
                    <marker id="arrowhead2" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                        <polygon points="0 0, 10 3.5, 0 7" fill="#ea580c"/>
                    </marker>
                </defs>
                
                <!-- Timeline -->
                <text x="100" y="30" fill="#495057" font-size="12">T+0: Initial Access</text>
                <text x="200" y="50" fill="#495057" font-size="12">T+15m: Credential Harvest</text>
                <text x="320" y="30" fill="#495057" font-size="12">T+45m: Domain Admin</text>
            </svg>
        `;

        // Update timeline
        this.updateAttackTimeline();
    }

    updateAttackTimeline() {
        const timelineContainer = document.getElementById('attackTimeline');
        const steps = [
            { step: 1, action: 'Initial Access via Phishing', technique: 'T1566.001', system: 'WORKSTATION-01', active: true },
            { step: 2, action: 'Credential Dumping', technique: 'T1003.001', system: 'WORKSTATION-01', active: true },
            { step: 3, action: 'Lateral Movement', technique: 'T1021.001', system: 'SERVER-DC01', active: false },
            { step: 4, action: 'Domain Admin Escalation', technique: 'T1484.001', system: 'SERVER-DC01', active: false }
        ];

        timelineContainer.innerHTML = steps.map(step => `
            <div class="timeline-step ${step.active ? 'active' : ''}">
                <div style="font-weight: 600; color: #212529; margin-bottom: 4px;">Step ${step.step}</div>
                <div style="font-size: 12px; color: #495057; margin-bottom: 2px;">${step.technique}</div>
                <div style="font-size: 11px; color: #495057;">${step.system}</div>
                <div style="font-size: 10px; margin-top: 4px;">${step.action}</div>
            </div>
        `).join('');
    }

    loadIncidents() {
        const incidentsContainer = document.getElementById('incidentsList');
        const incidents = [
            { id: 'INC-2024-001', title: 'APT29 Lateral Movement Campaign', severity: 'critical', status: 'Active', time: '2h ago' },
            { id: 'INC-2024-002', title: 'Phishing Attack on Finance Dept', severity: 'high', status: 'Investigating', time: '4h ago' },
            { id: 'INC-2024-003', title: 'Suspicious PowerShell Activity', severity: 'medium', status: 'Analyzing', time: '6h ago' },
            { id: 'INC-2024-004', title: 'Failed Login Brute Force', severity: 'medium', status: 'Monitoring', time: '8h ago' }
        ];

        incidentsContainer.innerHTML = incidents.map(incident => `
            <div class="incident-item" data-incident-id="${incident.id}">
                <div class="incident-title">${incident.title}</div>
                <div class="incident-meta">
                    <span class="incident-severity ${incident.severity}">${incident.severity}</span>
                    <span>${incident.time}</span>
                </div>
            </div>
        `).join('');
    }

    selectIncident(incidentElement) {
        // Remove previous selection
        document.querySelectorAll('.incident-item').forEach(item => item.classList.remove('selected'));
        incidentElement.classList.add('selected');

        const incidentId = incidentElement.dataset.incidentId;
        const investigationPanel = document.getElementById('investigationPanel');
        
        // Simulate loading investigation data
        investigationPanel.innerHTML = `
            <div style="margin-bottom: 20px;">
                <h4 style="color: #212529; margin-bottom: 10px;">${incidentId}: APT29 Lateral Movement Campaign</h4>
                <div style="font-size: 14px; color: #495057; margin-bottom: 15px;">First detected: 2025-10-15 10:30 UTC</div>
            </div>
            
            <div style="background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 15px; margin-bottom: 15px;">
                <h5 style="color: #212529; margin-bottom: 8px;">Timeline</h5>
                <div style="font-size: 12px; color: #495057; line-height: 1.6;">
                    10:30 - Initial RDP connection from 192.168.1.45<br>
                    10:35 - LSASS memory dump detected<br>
                    10:42 - Lateral movement to DC01<br>
                    10:58 - Privilege escalation attempt<br>
                </div>
            </div>
            
            <div style="background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 15px; margin-bottom: 15px;">
                <h5 style="color: #212529; margin-bottom: 8px;">Affected Systems</h5>
                <div style="font-size: 12px; color: #495057;">
                    • WORKSTATION-01 (192.168.1.45)<br>
                    • SERVER-DC01 (192.168.1.10)<br>
                    • FILE-SERVER-02 (192.168.1.25)<br>
                </div>
            </div>
            
            <div style="background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 15px;">
                <h5 style="color: #212529; margin-bottom: 8px;">IOCs</h5>
                <div style="font-size: 12px; color: #495057; font-family: monospace;">
                    Hash: a1b2c3d4e5f6...<br>
                    IP: 203.0.113.42<br>
                    Domain: malicious-c2.com<br>
                </div>
            </div>
        `;
    }

    loadScanners() {
        const scannersContainer = document.getElementById('scannersList');
        const scanners = [
            { name: 'Network Scanner', type: 'Infrastructure', status: 'running', progress: 67, findings: 234, lastScan: '12:00 UTC' },
            { name: 'Vulnerability Scanner', type: 'Security', status: 'completed', progress: 100, findings: 89, lastScan: '11:30 UTC' },
            { name: 'Threat Intel Scanner', type: 'Intelligence', status: 'running', progress: 42, findings: 156, lastScan: '12:15 UTC' },
            { name: 'Malware Scanner', type: 'Endpoint', status: 'idle', progress: 0, findings: 0, lastScan: '10:00 UTC' }
        ];

        scannersContainer.innerHTML = scanners.map(scanner => `
            <div class="scanner-card">
                <div class="scanner-header">
                    <div class="scanner-name">${scanner.name}</div>
                    <div class="scanner-status ${scanner.status}">${scanner.status}</div>
                </div>
                <div class="scanner-metrics">
                    <div class="scanner-metric">
                        <span class="metric-value-scanner">${scanner.findings}</span>
                        <span class="metric-label-scanner">Findings</span>
                    </div>
                    <div class="scanner-metric">
                        <span class="metric-value-scanner">${scanner.lastScan}</span>
                        <span class="metric-label-scanner">Last Scan</span>
                    </div>
                    <div class="scanner-metric">
                        <span class="metric-value-scanner">${scanner.type}</span>
                        <span class="metric-label-scanner">Type</span>
                    </div>
                </div>
                ${scanner.status === 'running' ? `
                    <div class="scan-progress">
                        <div class="progress-bar" style="width: ${scanner.progress}%"></div>
                    </div>
                ` : ''}
            </div>
        `).join('');
    }

    loadProvenanceCards() {
        const provenanceContainer = document.getElementById('provenanceCards');
        const cards = [
            {
                cardId: 'PC001',
                threatId: 'T001',
                hash: 'sha256:a1b2c3d4e5f6789...',
                signature: 'RSA-2048:verified',
                timestamp: '2025-10-15T10:30:00Z',
                source: 'MITRE ATT&CK',
                verified: true
            },
            {
                cardId: 'PC002',
                threatId: 'T002',
                hash: 'sha256:f6e5d4c3b2a1098...',
                signature: 'RSA-2048:verified',
                timestamp: '2025-10-15T09:15:00Z',
                source: 'Threat Connect',
                verified: true
            },
            {
                cardId: 'PC003',
                threatId: 'T003',
                hash: 'sha256:9876543210abcdef...',
                signature: 'RSA-2048:pending',
                timestamp: '2025-10-15T08:45:00Z',
                source: 'Internal Analysis',
                verified: false
            }
        ];

        provenanceContainer.innerHTML = cards.map(card => `
            <div class="provenance-card">
                <div class="card-header">
                    <div class="card-id">${card.cardId}</div>
                    <div class="verification-status">
                        <div class="verification-icon">${card.verified ? '✓' : '⏳'}</div>
                    </div>
                </div>
                <div class="card-content">
                    <div class="card-field">
                        <span class="field-label">Threat ID:</span>
                        <span class="field-value">${card.threatId}</span>
                    </div>
                    <div class="card-field">
                        <span class="field-label">Hash:</span>
                        <span class="field-value hash-value">${card.hash}</span>
                    </div>
                    <div class="card-field">
                        <span class="field-label">Signature:</span>
                        <span class="field-value">${card.signature}</span>
                    </div>
                    <div class="card-field">
                        <span class="field-label">Source:</span>
                        <span class="field-value">${card.source}</span>
                    </div>
                    <div class="card-field">
                        <span class="field-label">Timestamp:</span>
                        <span class="field-value">${new Date(card.timestamp).toLocaleString()}</span>
                    </div>
                </div>
            </div>
        `).join('');
    }

    startAllScans() {
        this.showAlert('All scanners started successfully', 'success');
        // Update scanner statuses
        document.querySelectorAll('.scanner-status.idle').forEach(status => {
            status.textContent = 'running';
            status.className = 'scanner-status running';
        });
    }

    stopAllScans() {
        this.showAlert('All scanners stopped', 'warning');
        // Update scanner statuses
        document.querySelectorAll('.scanner-status.running').forEach(status => {
            status.textContent = 'idle';
            status.className = 'scanner-status idle';
        });
    }

    exportAttackPath() {
        this.showAlert('Attack path exported to MISP format', 'success');
    }

    showAlert(message, type = 'info') {
        const alertSystem = document.getElementById('alertSystem');
        const alert = document.createElement('div');
        alert.className = `alert ${type}`;
        alert.innerHTML = `
            <div class="alert-content">
                <i class="alert-icon fas ${
                    type === 'success' ? 'fa-check-circle' :
                    type === 'error' ? 'fa-exclamation-circle' :
                    type === 'warning' ? 'fa-exclamation-triangle' :
                    'fa-info-circle'
                }"></i>
                <div class="alert-message">${message}</div>
                <button class="alert-close" onclick="this.parentElement.parentElement.remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        
        alertSystem.appendChild(alert);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (alert.parentElement) {
                alert.remove();
            }
        }, 5000);
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.ntroApp = new NTROPlatform();
});