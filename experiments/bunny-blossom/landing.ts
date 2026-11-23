// Styled Divine Blossom landing page explaining open media hosting,
// how to bring your own Blossom server on Nostr, and the full HTTP API.

export const LANDING_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Divine Media — Open Blossom Server</title>
  <meta name="description" content="Divine's open-source Blossom media server for human-made short-form video on Nostr. Content-addressed storage, adaptive HLS, captions, and zero platform lock-in.">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --green: #27C58B;
      --dark-green: #07241B;
      --light-green: #D0FBCB;
      --off-white: #F9F7F6;
      --surface: #FFFFFF;
      --border: #E5E1DC;
      --ink: #07241B;
      --muted: #465B53;
      --yellow-light: #FFFABB;
      --yellow-dark: #363313;
      --lime-light: #F1FFC8;
      --lime-dark: #272F0E;
      --pink-light: #FFDEEA;
      --pink-dark: #3E0C1F;
      --orange-light: #FFD8C9;
      --orange-dark: #471F10;
      --violet-light: #E1E3FF;
      --violet-dark: #2D214D;
      --blue-light: #CCEEFE;
      --blue-dark: #0A223C;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    html { scroll-behavior: smooth; }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 16px;
      line-height: 1.55;
      color: var(--ink);
      background: var(--off-white);
      -webkit-font-smoothing: antialiased;
    }

    h1, h2, h3 {
      font-family: 'Bricolage Grotesque', 'Inter', sans-serif;
      letter-spacing: -0.02em;
      line-height: 1.15;
    }

    a {
      color: var(--dark-green);
      text-decoration: underline;
      text-decoration-color: var(--green);
      text-decoration-thickness: 2px;
      text-underline-offset: 3px;
    }

    a:hover {
      background: var(--light-green);
      border-radius: 3px;
    }

    code, pre {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    code {
      background: #EEF2EF;
      color: var(--dark-green);
      padding: 0.12rem 0.4rem;
      border-radius: 6px;
      font-size: 0.875em;
    }

    /* Top bar */
    .topbar {
      background: var(--dark-green);
      color: var(--off-white);
      border-bottom: 3px solid var(--green);
    }

    .topbar-inner {
      max-width: 1040px;
      margin: 0 auto;
      padding: 1rem 1.5rem;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.65rem;
      text-decoration: none;
      color: var(--off-white);
    }

    .brand:hover { background: transparent; }

    .brand-mark {
      width: 34px;
      height: 34px;
      border-radius: 10px;
      background: var(--green);
      color: var(--dark-green);
      font-family: 'Bricolage Grotesque', sans-serif;
      font-weight: 800;
      font-size: 1.15rem;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .brand-name {
      font-family: 'Bricolage Grotesque', sans-serif;
      font-weight: 800;
      font-size: 1.2rem;
      color: var(--off-white);
    }

    .nav {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem 1.25rem;
      align-items: center;
      font-size: 0.92rem;
      font-weight: 500;
    }

    .nav a {
      color: var(--light-green);
      text-decoration: none;
    }

    .nav a:hover {
      color: #FFFFFF;
      background: transparent;
      text-decoration: underline;
      text-decoration-color: var(--green);
    }

    /* Hero */
    .hero {
      background: var(--dark-green);
      color: var(--off-white);
      padding: 3.5rem 1.5rem 4rem;
    }

    .hero-inner {
      max-width: 1040px;
      margin: 0 auto;
    }

    .pill-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-bottom: 1.25rem;
    }

    .pill {
      display: inline-flex;
      align-items: center;
      padding: 0.3rem 0.75rem;
      border-radius: 999px;
      font-size: 0.8rem;
      font-weight: 600;
    }

    .pill-green { background: var(--light-green); color: var(--dark-green); }
    .pill-orange { background: var(--orange-light); color: var(--orange-dark); }
    .pill-lime { background: var(--lime-light); color: var(--lime-dark); }

    .hero h1 {
      font-size: clamp(2.1rem, 4.5vw, 3.25rem);
      font-weight: 800;
      color: #FFFFFF;
      max-width: 18ch;
      margin-bottom: 1rem;
    }

    .hero-lead {
      font-size: 1.12rem;
      color: #D2E3DC;
      max-width: 64ch;
      margin-bottom: 1.75rem;
    }

    .cta-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      padding: 0.7rem 1.2rem;
      border-radius: 10px;
      font-weight: 700;
      font-size: 0.95rem;
      text-decoration: none;
      border: 2px solid transparent;
    }

    .btn-primary {
      background: var(--green);
      color: var(--dark-green);
    }

    .btn-primary:hover {
      background: var(--light-green);
      color: var(--dark-green);
    }

    .btn-secondary {
      background: transparent;
      color: var(--off-white);
      border-color: #2E5B4C;
    }

    .btn-secondary:hover {
      background: #103A2D;
      color: #FFFFFF;
    }

    /* Main content */
    main {
      max-width: 1040px;
      margin: 0 auto;
      padding: 2.5rem 1.5rem 4rem;
      display: flex;
      flex-direction: column;
      gap: 2.25rem;
    }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 2rem;
    }

    .card-tint {
      background: var(--light-green);
      border-color: #AEE6B8;
    }

    .section-kicker {
      display: inline-block;
      font-size: 0.8rem;
      font-weight: 700;
      padding: 0.2rem 0.6rem;
      border-radius: 6px;
      background: var(--light-green);
      color: var(--dark-green);
      margin-bottom: 0.75rem;
    }

    .card-tint .section-kicker {
      background: var(--dark-green);
      color: var(--light-green);
    }

    h2 {
      font-size: 1.7rem;
      font-weight: 800;
      margin-bottom: 0.75rem;
    }

    .section-intro {
      color: var(--muted);
      max-width: 68ch;
      margin-bottom: 1.5rem;
    }

    .card-tint .section-intro {
      color: #164435;
    }

    .grid-2 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1rem;
    }

    .grid-3 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
    }

    .tile {
      background: var(--off-white);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.15rem 1.25rem;
    }

    .card-tint .tile {
      background: var(--surface);
      border-color: #B9E5C1;
    }

    .tile h3 {
      font-size: 1.05rem;
      font-weight: 700;
      margin-bottom: 0.45rem;
      color: var(--ink);
    }

    .tile p {
      font-size: 0.92rem;
      color: var(--muted);
    }

    .steps {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 1rem;
      margin-top: 1.25rem;
    }

    .step {
      background: var(--surface);
      border: 1px solid #B9E5C1;
      border-radius: 12px;
      padding: 1.15rem 1.25rem;
    }

    .step-num {
      display: inline-flex;
      width: 28px;
      height: 28px;
      border-radius: 8px;
      background: var(--dark-green);
      color: var(--light-green);
      font-family: 'Bricolage Grotesque', sans-serif;
      font-weight: 800;
      font-size: 0.9rem;
      align-items: center;
      justify-content: center;
      margin-bottom: 0.6rem;
    }

    .step h3 {
      font-size: 1rem;
      margin-bottom: 0.35rem;
    }

    .step p {
      font-size: 0.9rem;
      color: var(--muted);
    }

    .code-block {
      margin-top: 1.25rem;
      background: var(--dark-green);
      color: var(--off-white);
      border-radius: 12px;
      padding: 1rem 1.2rem;
      overflow-x: auto;
      font-size: 0.86rem;
      line-height: 1.5;
    }

    .code-block code {
      background: transparent;
      color: var(--light-green);
      padding: 0;
      font-size: inherit;
    }

    /* API Endpoints */
    .api-group {
      margin-top: 1.5rem;
    }

    .api-group:first-of-type {
      margin-top: 0.5rem;
    }

    .api-group-title {
      font-family: 'Inter', sans-serif;
      font-size: 0.92rem;
      font-weight: 700;
      color: var(--muted);
      padding-bottom: 0.5rem;
      border-bottom: 2px solid var(--off-white);
      margin-bottom: 0.25rem;
    }

    .endpoint {
      display: flex;
      align-items: flex-start;
      gap: 0.9rem;
      padding: 0.85rem 0;
      border-bottom: 1px solid #F0EDE9;
    }

    .endpoint:last-child { border-bottom: none; }

    .method {
      display: inline-block;
      padding: 0.24rem 0.55rem;
      border-radius: 6px;
      font-size: 0.74rem;
      font-weight: 700;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      min-width: 66px;
      text-align: center;
      flex-shrink: 0;
      margin-top: 0.1rem;
    }

    .m-get { background: var(--light-green); color: var(--dark-green); }
    .m-head { background: var(--blue-light); color: var(--blue-dark); }
    .m-put { background: var(--orange-light); color: var(--orange-dark); }
    .m-post { background: var(--violet-light); color: var(--violet-dark); }
    .m-delete { background: var(--pink-light); color: var(--pink-dark); }

    .endpoint-info { flex: 1; min-width: 0; }

    .endpoint-head {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.5rem;
    }

    .endpoint-path {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-weight: 700;
      font-size: 0.94rem;
      color: var(--dark-green);
      word-break: break-word;
    }

    .bud-tag {
      font-size: 0.72rem;
      font-weight: 700;
      padding: 0.12rem 0.45rem;
      border-radius: 999px;
      background: var(--yellow-light);
      color: var(--yellow-dark);
    }

    .endpoint-desc {
      color: var(--muted);
      font-size: 0.9rem;
      margin-top: 0.25rem;
    }

    /* Links list */
    .link-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 0.9rem;
    }

    .link-card {
      display: block;
      text-decoration: none;
      background: var(--off-white);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1rem 1.15rem;
    }

    .link-card:hover {
      background: var(--light-green);
      border-color: var(--green);
    }

    .link-card strong {
      display: block;
      font-family: 'Bricolage Grotesque', sans-serif;
      font-size: 1rem;
      color: var(--dark-green);
      margin-bottom: 0.25rem;
    }

    .link-card span {
      display: block;
      font-size: 0.86rem;
      color: var(--muted);
    }

    /* Footer */
    footer {
      border-top: 1px solid var(--border);
      background: var(--surface);
      padding: 2.25rem 1.5rem;
      color: var(--muted);
      font-size: 0.9rem;
    }

    .footer-inner {
      max-width: 1040px;
      margin: 0 auto;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 1rem;
      align-items: center;
    }

    .footer-links {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem 1.15rem;
    }

    @media (max-width: 640px) {
      .hero { padding: 2.5rem 1.25rem 3rem; }
      .card { padding: 1.35rem; }
      .endpoint { flex-direction: column; gap: 0.4rem; }
    }
  </style>
</head>
<body>
  <div class="topbar">
    <div class="topbar-inner">
      <a class="brand" href="https://divine.video">
        <span class="brand-mark">D</span>
        <span class="brand-name">Divine Media</span>
      </a>
      <nav class="nav" aria-label="Primary">
        <a href="#how-it-works">How it works</a>
        <a href="#own-server">Use your own server</a>
        <a href="#api">API reference</a>
        <a href="#links">Open network</a>
        <a href="https://divine.video">divine.video</a>
      </nav>
    </div>
  </div>

  <header class="hero">
    <div class="hero-inner">
      <div class="pill-row">
        <span class="pill pill-green">Blossom Protocol</span>
        <span class="pill pill-lime">Open Network on Nostr</span>
        <span class="pill pill-orange">Bunny Edge + Backblaze B2</span>
      </div>
      <h1>Your videos belong to you, not a walled garden.</h1>
      <p class="hero-lead">
        This is Divine's open Blossom media server. We host human-made short-form video, thumbnails, adaptive HLS streams, and captions for the open Nostr network — and if you'd rather host your own media somewhere else, we built it so you can.
      </p>
      <div class="cta-row">
        <a class="btn btn-primary" href="#api">Explore the Blossom API</a>
        <a class="btn btn-secondary" href="#own-server">Bring your own Blossom server</a>
        <a class="btn btn-secondary" href="https://github.com/divinevideo/divine-blossom">View source on GitHub</a>
      </div>
    </div>
  </header>

  <main>
    <section id="how-it-works" class="card">
      <span class="section-kicker">How Divine hosts media</span>
      <h2>Fast playback, verifiable files, no AI slop.</h2>
      <p class="section-intro">
        Every video, image, and audio file uploaded to Divine is stored by its SHA-256 fingerprint instead of a proprietary database ID. That means links don't break when servers change, and anyone can verify they received the exact bytes a creator signed.
      </p>
      <div class="grid-3">
        <div class="tile">
          <h3>Content-addressed by SHA-256</h3>
          <p>Files live at <code>/&lt;sha256&gt;</code>. The hash is the address and the checksum, so the same file works across every Blossom server on Nostr.</p>
        </div>
        <div class="tile">
          <h3>Instant 6-second playback</h3>
          <p>Video uploads automatically generate JPEG thumbnails (<code>.jpg</code>), 720p and 480p adaptive HLS streams (<code>.hls</code>), and HTTP Range byte streaming from global edge caches.</p>
        </div>
        <div class="tile">
          <h3>Captions &amp; audio analysis</h3>
          <p>On-demand WebVTT transcripts live at stable URLs (<code>/&lt;sha256&gt;.vtt</code>) alongside extracted audio tracks and sound metadata.</p>
        </div>
        <div class="tile">
          <h3>Human-first moderation</h3>
          <p>Divine keeps AI slop and illegal or abusive material off our host using transparent status levels (<code>SAFE</code>, <code>REVIEW</code>, <code>AGE_RESTRICTED</code>, <code>PERMANENT_BAN</code>) and ProofMode / C2PA provenance (<code>/provenance</code>).</p>
        </div>
        <div class="tile">
          <h3>Signed with your Nostr keys</h3>
          <p>No separate passwords or platform accounts. Uploads, mirroring, deletion, and restricted playback authenticate with signed Nostr events (Blossom <code>kind 24242</code> and NIP-98 <code>kind 27235</code>).</p>
        </div>
        <div class="tile">
          <h3>Real deletion &amp; GDPR vanish</h3>
          <p>Soft-delete any file you uploaded via <code>DELETE /&lt;sha256&gt;</code>, or erase every blob tied to your public key in one signed request via <code>DELETE /vanish</code>.</p>
        </div>
      </div>
    </section>

    <section id="own-server" class="card card-tint">
      <span class="section-kicker">Open networks, zero lock-in</span>
      <h2>You don't have to host with Divine.</h2>
      <p class="section-intro">
        Divine runs this server so posting is effortless out of the box, but the whole point of Nostr and Blossom is freedom of choice. Your posts reference media by hash — you can point your account at your own Blossom server, a community server, or mirror your files across several hosts at once.
      </p>
      <div class="steps">
        <div class="step">
          <span class="step-num">1</span>
          <h3>Pick or run a Blossom server</h3>
          <p>Run our open-source server (<a href="https://github.com/divinevideo/divine-blossom">divine-blossom</a>), host any <a href="https://github.com/hzrd149/blossom">BUD-compliant Blossom server</a>, or choose a community host you trust.</p>
        </div>
        <div class="step">
          <span class="step-num">2</span>
          <h3>Publish your BUD-03 server list</h3>
          <p>Sign a Nostr <code>kind 10063</code> event listing your preferred Blossom server URLs (<a href="https://github.com/hzrd149/blossom/blob/master/buds/03.md">BUD-03</a>). Divine and other Nostr apps read your list automatically.</p>
        </div>
        <div class="step">
          <span class="step-num">3</span>
          <h3>Mirror for resilience</h3>
          <p>Use <code>PUT /mirror</code> (<a href="https://github.com/hzrd149/blossom/blob/master/buds/04.md">BUD-04</a>) to copy your files between servers. Because every server uses the same SHA-256 hash, viewers seamlessly fall back if one host goes down.</p>
        </div>
      </div>
      <div class="code-block" aria-label="Example BUD-03 kind 10063 user server list event">
<code>{
  "kind": 10063,
  "tags": [
    ["server", "https://media.your-domain.example"],
    ["server", "https://media.divine.video"]
  ],
  "content": ""
}</code>
      </div>
    </section>

    <section id="api" class="card">
      <span class="section-kicker">Developer documentation</span>
      <h2>Blossom &amp; Divine HTTP API</h2>
      <p class="section-intro">
        Implements <a href="https://github.com/hzrd149/blossom">Blossom</a> BUD-01 (Blob Retrieval), BUD-02 (Upload, List, Delete), BUD-04 (Mirroring), BUD-06 (Upload Pre-validation), and BUD-09 (Reporting), plus Divine's HLS, captions, and provenance extensions. Maximum upload size: <code>50 GB</code>.
      </p>

      <div class="api-group">
        <div class="api-group-title">Playback, thumbnails &amp; adaptive streaming</div>
        <div class="endpoint">
          <span class="method m-get">GET</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/&lt;sha256&gt;[.ext]</span>
              <span class="bud-tag">BUD-01</span>
            </div>
            <p class="endpoint-desc">Fetch a blob by SHA-256 hash with full HTTP <code>Range</code> support. Append <code>.jpg</code> on videos to fetch the generated JPEG thumbnail.</p>
          </div>
        </div>
        <div class="endpoint">
          <span class="method m-head">HEAD</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/&lt;sha256&gt;[.ext]</span>
              <span class="bud-tag">BUD-01</span>
            </div>
            <p class="endpoint-desc">Check blob availability, <code>Content-Type</code>, <code>Content-Length</code>, and range capability without transferring bytes.</p>
          </div>
        </div>
        <div class="endpoint">
          <span class="method m-get">GET</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/&lt;sha256&gt;.hls</span>
              <span class="endpoint-path">/&lt;sha256&gt;/hls/master.m3u8</span>
            </div>
            <p class="endpoint-desc">Adaptive HLS master playlist (720p &amp; 480p H.264). Triggers on-demand transcoding if needed and returns <code>202 Accepted</code> with <code>Retry-After</code> while encoding.</p>
          </div>
        </div>
        <div class="endpoint">
          <span class="method m-get">GET</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/&lt;sha256&gt;/720p</span>
              <span class="endpoint-path">/&lt;sha256&gt;/480p</span>
            </div>
            <p class="endpoint-desc">Direct progressive MP4 downloads for the 720p (2.5 Mbps) and 480p (1 Mbps) H.264 transcoded variants.</p>
          </div>
        </div>
        <div class="endpoint">
          <span class="method m-get">GET</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/&lt;sha256&gt;.audio.m4a</span>
              <span class="endpoint-path">/&lt;sha256&gt;/sound</span>
            </div>
            <p class="endpoint-desc">Extracted audio track (AAC/M4A) and JSON sound analysis metadata for clips with audio.</p>
          </div>
        </div>
      </div>

      <div class="api-group">
        <div class="api-group-title">Captions, subtitles &amp; provenance</div>
        <div class="endpoint">
          <span class="method m-get">GET</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/&lt;sha256&gt;.vtt</span>
              <span class="endpoint-path">/&lt;sha256&gt;.&lt;lang&gt;.vtt</span>
              <span class="endpoint-path">/&lt;sha256&gt;/VTT</span>
            </div>
            <p class="endpoint-desc">WebVTT transcript for audio/video blobs, triggering on-demand transcription when not yet generated.</p>
          </div>
        </div>
        <div class="endpoint">
          <span class="method m-post">POST</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/v1/subtitles/jobs</span>
            </div>
            <p class="endpoint-desc">Create or reuse a subtitle job by hash (<code>video_sha256</code>, optional <code>lang</code> and <code>force</code>). Inspect status via <code>GET /v1/subtitles/jobs/&lt;job_id&gt;</code> or <code>GET /v1/subtitles/by-hash/&lt;sha256&gt;</code>.</p>
          </div>
        </div>
        <div class="endpoint">
          <span class="method m-get">GET</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/&lt;sha256&gt;/provenance</span>
            </div>
            <p class="endpoint-desc">Returns ProofMode / C2PA authenticity and capture verification metadata when attached to a human-recorded clip.</p>
          </div>
        </div>
      </div>

      <div class="api-group">
        <div class="api-group-title">Uploads, mirroring &amp; creator catalog</div>
        <div class="endpoint">
          <span class="method m-head">HEAD</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/upload</span>
              <span class="bud-tag">BUD-06</span>
            </div>
            <p class="endpoint-desc">Pre-validate an upload using <code>X-SHA-256</code>, <code>X-Content-Length</code>, and <code>X-Content-Type</code> headers before sending bytes.</p>
          </div>
        </div>
        <div class="endpoint">
          <span class="method m-put">PUT</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/upload</span>
              <span class="bud-tag">BUD-02</span>
            </div>
            <p class="endpoint-desc">Upload a new blob with Nostr <code>kind 24242</code> authorization. Returns a Blossom Blob Descriptor JSON object; videos queue thumbnails and transcoding automatically.</p>
          </div>
        </div>
        <div class="endpoint">
          <span class="method m-put">PUT</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/mirror</span>
              <span class="bud-tag">BUD-04</span>
            </div>
            <p class="endpoint-desc">Mirror a blob from another URL onto this server using Nostr <code>kind 24242</code> auth. Great for moving or backing up clips across Blossom hosts.</p>
          </div>
        </div>
        <div class="endpoint">
          <span class="method m-get">GET</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/list/&lt;pubkey&gt;</span>
              <span class="bud-tag">BUD-02</span>
            </div>
            <p class="endpoint-desc">List blobs uploaded by a 64-character hex Nostr public key. Supports <code>since</code>, <code>until</code>, and cursor pagination.</p>
          </div>
        </div>
      </div>

      <div class="api-group">
        <div class="api-group-title">Deletion, reporting &amp; health</div>
        <div class="endpoint">
          <span class="method m-delete">DELETE</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/&lt;sha256&gt;</span>
              <span class="bud-tag">BUD-02</span>
            </div>
            <p class="endpoint-desc">Soft-delete a blob you own so it immediately stops serving publicly. Non-owner co-uploaders only unlink their own reference. Requires Nostr <code>kind 24242</code> auth.</p>
          </div>
        </div>
        <div class="endpoint">
          <span class="method m-delete">DELETE</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/vanish</span>
            </div>
            <p class="endpoint-desc">GDPR Right to Erasure. Permanently removes all blobs and references owned by the authenticated Nostr public key.</p>
          </div>
        </div>
        <div class="endpoint">
          <span class="method m-put">PUT</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/report</span>
              <span class="bud-tag">BUD-09</span>
            </div>
            <p class="endpoint-desc">Report abusive or policy-violating media using a signed NIP-56 report event (<code>kind 1984</code>).</p>
          </div>
        </div>
        <div class="endpoint">
          <span class="method m-get">GET</span>
          <div class="endpoint-info">
            <div class="endpoint-head">
              <span class="endpoint-path">/health</span>
              <span class="endpoint-path">/version</span>
            </div>
            <p class="endpoint-desc">Public runtime health check and current edge build version.</p>
          </div>
        </div>
      </div>
    </section>

    <section id="links" class="card">
      <span class="section-kicker">Open network links</span>
      <h2>Explore Divine &amp; the open Blossom community</h2>
      <p class="section-intro">
        Everything we build is open source and interoperable with the wider Nostr network. Jump into the app, inspect our code, or read the specs.
      </p>
      <div class="link-grid">
        <a class="link-card" href="https://divine.video">
          <strong>Divine App</strong>
          <span>Watch, make, and share human-made 6-second videos on divine.video.</span>
        </a>
        <a class="link-card" href="https://github.com/divinevideo/divine-blossom">
          <strong>divine-blossom on GitHub</strong>
          <span>Run this media server yourself, read the architecture, or open a PR.</span>
        </a>
        <a class="link-card" href="https://github.com/hzrd149/blossom">
          <strong>Blossom Protocol (BUDs)</strong>
          <span>The open specification for content-addressed Nostr blob servers.</span>
        </a>
        <a class="link-card" href="https://github.com/hzrd149/blossom/blob/master/buds/03.md">
          <strong>BUD-03: User Server Lists</strong>
          <span>How to advertise your own Blossom servers with a Nostr kind 10063 event.</span>
        </a>
        <a class="link-card" href="https://api.divine.video">
          <strong>Divine Funnelcake API</strong>
          <span>REST API and Nostr relay (<code>wss://relay.divine.video</code>) powering feeds and discovery.</span>
        </a>
        <a class="link-card" href="https://nostr.com">
          <strong>Learn about Nostr</strong>
          <span>Open keys, open relays, and portable social identity you actually own.</span>
        </a>
      </div>
    </section>
  </main>

  <footer>
    <div class="footer-inner">
      <div>
        <strong>Divine</strong> — Joyscrolling for humans, built on Nostr and Blossom. Independent open-source project.
      </div>
      <div class="footer-links">
        <a href="https://divine.video">divine.video</a>
        <a href="https://github.com/divinevideo">GitHub</a>
        <a href="https://github.com/hzrd149/blossom">Blossom Spec</a>
        <a href="https://bunny.net/edge-scripting/">Bunny Edge</a>
      </div>
    </div>
  </footer>
</body>
</html>`;
