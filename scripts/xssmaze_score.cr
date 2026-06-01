# Benchmarks dalfox against XSSMaze (https://github.com/hahwul/xssmaze) and
# records how much of the lab it can detect.
#
# Flow:
#   1. Ensure an XSSMaze instance is reachable. If not, pull and run the
#      `main` image in Docker and tear it down afterwards.
#   2. Read the catalog from `/map/json` and the lab version from `/version`.
#   3. Scan every endpoint with dalfox, targeting the injection point the
#      catalog declares (query / body / header / path). An endpoint counts as
#      detected when dalfox returns at least one finding.
#   4. Aggregate detection per category and overall, write the machine-readable
#      snapshot to `docs/data/xssmaze-score.json`, and re-render the table +
#      graph block in `docs/content/reference/xssmaze.md`.
#
# Invoked by `just xssmaze-score`. Tunable via environment variables:
#   XSSMAZE_URL          base URL                (default http://localhost:3000)
#   XSSMAZE_IMAGE        docker image            (default ghcr.io/hahwul/xssmaze:main)
#   XSSMAZE_CONTAINER    container name          (default dalfox-xssmaze-bench)
#   XSSMAZE_MANAGE       false = never touch docker, just scan an existing instance
#   XSSMAZE_CONCURRENCY  parallel endpoint scans (default 8)
#   XSSMAZE_LIMIT        scan only the first N endpoints (smoke testing)
#   XSSMAZE_RENDER_ONLY  1 = skip scanning, re-render the page from the JSON snapshot
#   DALFOX_BIN           dalfox binary           (default target/release/dalfox)

require "json"
require "http/client"
require "uri"
require "file_utils"

BASE_URL    = ENV.fetch("XSSMAZE_URL", "http://localhost:3000").rstrip("/")
IMAGE       = ENV.fetch("XSSMAZE_IMAGE", "ghcr.io/hahwul/xssmaze:main")
CONTAINER   = ENV.fetch("XSSMAZE_CONTAINER", "dalfox-xssmaze-bench")
DALFOX_BIN  = ENV.fetch("DALFOX_BIN", "target/release/dalfox")
CONCURRENCY = ENV.fetch("XSSMAZE_CONCURRENCY", "8").to_i
LIMIT       = ENV["XSSMAZE_LIMIT"]?.try(&.to_i?)
RENDER_ONLY = ENV["XSSMAZE_RENDER_ONLY"]? == "1"
MANAGE      = ENV.fetch("XSSMAZE_MANAGE", "true") != "false"

DATA_PATH = ENV.fetch("XSSMAZE_DATA_PATH", "docs/data/xssmaze-score.json")
PAGE_PATH = ENV.fetch("XSSMAZE_PAGE_PATH", "docs/content/reference/xssmaze.md")

# Catalog params that are really request-header injection points rather than
# query/body parameters. See xssmaze's catalog.cr (build_openapi).
HEADER_PARAMS = Set{"Cookie", "Referer", "User-Agent", "Authorization"}

# ---------------------------------------------------------------------------
# Catalog models (shape of /map/json — see xssmaze src/maze.cr#to_json_object).
# ---------------------------------------------------------------------------

struct Maze
  include JSON::Serializable
  getter name : String
  getter url : String
  getter type : String
  getter desc : String
  getter method : String
  getter params : Array(String)
end

struct MapResponse
  include JSON::Serializable
  getter endpoints : Array(Maze)
end

# Per-category tally accumulated during scanning.
class Tally
  property endpoints = 0
  property detected = 0
  property verified = 0
end

# ---------------------------------------------------------------------------
# HTTP / process helpers.
# ---------------------------------------------------------------------------

def http_get(path : String) : String?
  resp = HTTP::Client.get(BASE_URL + path)
  resp.success? ? resp.body : nil
rescue
  nil
end

def run_quiet(cmd : String, args : Array(String)) : Bool
  Process.run(cmd, args,
    output: Process::Redirect::Close,
    error: Process::Redirect::Close).success?
rescue
  false
end

def capture(cmd : String, args : Array(String)) : String
  buf = IO::Memory.new
  Process.run(cmd, args, output: buf, error: Process::Redirect::Close)
  buf.to_s.strip
rescue
  ""
end

def dalfox_version : String
  capture(DALFOX_BIN, ["--version"]).match(/(\d+\.\d+\.\d+\S*)/).try(&.[1]) || "unknown"
end

def image_digest : String?
  d = capture("docker", ["inspect", "--format", "{{index .RepoDigests 0}}", IMAGE])
  d.empty? ? nil : d
end

# ---------------------------------------------------------------------------
# XSSMaze lifecycle.
# ---------------------------------------------------------------------------

def docker_port : String
  uri = URI.parse(BASE_URL)
  (uri.port || 3000).to_s
end

# Returns true if this process started the container (and must stop it later).
def ensure_xssmaze : Bool
  return false if http_get("/health")

  unless MANAGE
    abort "XSSMaze is not reachable at #{BASE_URL} and XSSMAZE_MANAGE=false."
  end

  puts "==> XSSMaze not running; pulling #{IMAGE}"
  abort "docker pull failed" unless run_quiet("docker", ["pull", IMAGE])
  run_quiet("docker", ["rm", "-f", CONTAINER])
  puts "==> starting container #{CONTAINER} on port #{docker_port}"
  unless run_quiet("docker", ["run", "-d", "--name", CONTAINER, "-p", "#{docker_port}:3000", IMAGE])
    abort "docker run failed"
  end

  print "==> waiting for /health "
  60.times do
    if http_get("/health")
      puts "ok"
      return true
    end
    print "."
    sleep 1.second
  end
  run_quiet("docker", ["rm", "-f", CONTAINER])
  abort "\nXSSMaze did not become healthy in time."
end

def stop_xssmaze
  puts "==> stopping container #{CONTAINER}"
  run_quiet("docker", ["rm", "-f", CONTAINER])
end

# ---------------------------------------------------------------------------
# Scanning.
# ---------------------------------------------------------------------------

# Body (POST) params declared by the catalog, minus the path sentinel and any
# request-header injection points.
def body_params(maze : Maze) : Array(String)
  return [] of String unless maze.method == "POST"
  maze.params.reject { |p| p == ":path" || HEADER_PARAMS.includes?(p) }
end

# Compose the scan URL. The catalog's `params` are advisory — for several
# categories they are a generic `query` placeholder while the real injection
# point lives elsewhere (a differently-named query key, a header, the path).
# Rather than trust them, we let dalfox's own discovery test every query key in
# the URL. We only need to ensure each query-style catalog param is actually
# present so there is something to discover; some endpoints (e.g. `redirect`)
# declare a param the bare URL omits.
def scan_url(maze : Maze) : String
  base = BASE_URL + maze.url
  return base if maze.method == "POST" # body params are seeded via -d
  existing = (URI.parse(maze.url).query || "")
    .split('&', remove_empty: true)
    .map { |kv| kv.split('=', 2).first }
  missing = maze.params.reject do |p|
    p == ":path" || HEADER_PARAMS.includes?(p) || existing.includes?(p)
  end
  return base if missing.empty?
  sep = maze.url.includes?('?') ? "&" : "?"
  base + sep + missing.map { |p| "#{p}=a" }.join("&")
end

# Build the dalfox argument list for one maze. Mining is skipped (the endpoint
# is known) while discovery/reflection checks stay on so query / header / path
# cases all resolve. We deliberately do *not* force `-p name:query`: a wrong
# placeholder name would suppress the other vectors discovery finds on its own.
# Header injection points, which discovery does not surface, are targeted
# explicitly. `json_body` swaps the POST body encoding for the retry pass.
def build_args(maze : Maze, out_file : String, json_body : Bool) : Array(String)
  args = ["scan", scan_url(maze),
          "--format", "json", "-o", out_file,
          "-S", "--no-color", "--skip-mining",
          "--timeout", "7", "--scan-timeout", "40"]
  args.push("-X", maze.method) if maze.method != "GET"

  maze.params.each do |p|
    args.push("-p", "#{p}:header") if HEADER_PARAMS.includes?(p)
  end

  bp = body_params(maze)
  unless bp.empty?
    if json_body
      args.push("-d", "{" + bp.map { |p| %("#{p}":"a") }.join(",") + "}")
    else
      args.push("-d", bp.map { |p| "#{p}=a" }.join("&"))
    end
  end
  args
end

# Run dalfox once with the given body encoding. Returns {detected, verified}.
def run_dalfox(maze : Maze, json_body : Bool) : {Bool, Bool}
  out_file = File.tempname("dalfox-xssmaze", ".json")
  args = build_args(maze, out_file, json_body)
  status = Process.run(DALFOX_BIN, args,
    output: Process::Redirect::Close,
    error: Process::Redirect::Close)

  findings = parse_findings(out_file)
  detected = !findings.empty? || status.exit_code == 1
  verified = findings.any? { |f| f["type"]?.try(&.as_s?) == "V" }
  {detected, verified}
ensure
  File.delete(out_file) if out_file && File.exists?(out_file)
end

# Scan one maze. Returns {detected, verified}. The catalog does not record
# whether a POST endpoint reads urlencoded or JSON, so POST bodies are tried as
# a form first and re-tried as JSON only if the form pass finds nothing.
def scan(maze : Maze) : {Bool, Bool}
  detected, verified = run_dalfox(maze, false)
  return {detected, verified} if detected
  return {detected, verified} if body_params(maze).empty?
  run_dalfox(maze, true)
end

def parse_findings(out_file : String) : Array(JSON::Any)
  return [] of JSON::Any unless File.exists?(out_file)
  body = File.read(out_file).strip
  return [] of JSON::Any if body.empty?
  parsed = JSON.parse(body)
  parsed.as_a? || [] of JSON::Any
rescue
  [] of JSON::Any
end

# ---------------------------------------------------------------------------
# Snapshot model.
# ---------------------------------------------------------------------------

def rate(detected : Int32, total : Int32) : Float64
  total.zero? ? 0.0 : (detected.to_f * 100 / total).round(1)
end

def collect : JSON::Any
  body = http_get("/map/json") || abort "could not read #{BASE_URL}/map/json"
  mazes = MapResponse.from_json(body).endpoints
  mazes = mazes.first(LIMIT.not_nil!) if LIMIT

  version_info = http_get("/version").try { |b| JSON.parse(b) }
  xm_version = version_info.try(&.["version"]?).try(&.as_s?) || "unknown"

  puts "==> scanning #{mazes.size} endpoints with #{CONCURRENCY} workers (dalfox: #{DALFOX_BIN})"

  jobs = Channel(Maze).new(mazes.size)
  done = Channel({String, Bool, Bool}).new(mazes.size)
  mazes.each { |m| jobs.send(m) }
  jobs.close

  CONCURRENCY.times do
    spawn do
      while maze = jobs.receive?
        detected, verified = scan(maze)
        done.send({maze.type, detected, verified})
      end
    end
  end

  tallies = Hash(String, Tally).new { |h, k| h[k] = Tally.new }
  done_count = 0
  mazes.size.times do
    cat, detected, verified = done.receive
    t = tallies[cat]
    t.endpoints += 1
    t.detected += 1 if detected
    t.verified += 1 if verified
    done_count += 1
    print "\r==> scanned #{done_count}/#{mazes.size}"
  end
  puts ""

  categories = tallies.map do |cat, t|
    {
      category:  cat,
      endpoints: t.endpoints,
      detected:  t.detected,
      verified:  t.verified,
      rate:      rate(t.detected, t.endpoints),
    }
  end.sort_by! { |c| {-c[:rate], c[:category]} }

  total_eps = tallies.sum { |_, t| t.endpoints }
  total_det = tallies.sum { |_, t| t.detected }
  total_ver = tallies.sum { |_, t| t.verified }

  snapshot = {
    generated_at:    Time.utc.to_s("%Y-%m-%dT%H:%M:%SZ"),
    dalfox_version:  dalfox_version,
    xssmaze_version: xm_version,
    xssmaze_image:   IMAGE,
    xssmaze_digest:  image_digest,
    total:           {endpoints: total_eps, detected: total_det, verified: total_ver, rate: rate(total_det, total_eps)},
    categories:      categories,
  }
  JSON.parse(snapshot.to_json)
end

# ---------------------------------------------------------------------------
# Rendering.
# ---------------------------------------------------------------------------

def bar_color(rate : Float64) : String
  case
  when rate >= 90 then "#34d399" # success
  when rate >= 70 then "#8b94e8" # accent
  when rate >= 40 then "#f59e0b" # amber
  else                 "#f87171" # red
  end
end

# Meter fill colour as hex + "r,g,b" (for the rgba glow), keyed off the overall rate.
def meter_palette(rate : Float64) : {String, String}
  case
  when rate >= 90 then {"#34d399", "52,211,153"}
  when rate >= 70 then {"#8b94e8", "139,148,232"}
  when rate >= 40 then {"#f59e0b", "245,158,11"}
  else                 {"#f87171", "248,113,113"}
  end
end

# Flat metric tile — no left-accent border; value can be tinted for meaning.
def tile(label : String, value : String, sub : String,
         value_color : String = "var(--text-primary,#e7e9f3)") : String
  String.build do |io|
    io << %(<div style="padding:.85rem 1rem;background:var(--bg-surface,#11141f);border:1px solid var(--border-light,#222741);border-radius:10px">)
    io << %(<div style="font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--text-muted,#636980)">#{label}</div>)
    io << %(<div style="margin-top:.3rem;font-size:1.5rem;font-weight:700;line-height:1;color:#{value_color};font-variant-numeric:tabular-nums">#{value}</div>)
    io << %(<div style="margin-top:.35rem;font-size:.75rem;color:var(--text-secondary,#9aa0bb)">#{sub}</div>) unless sub.empty?
    io << %(</div>)
  end
end

def render_block(data : JSON::Any) : String
  total = data["total"]
  cats = data["categories"].as_a
  digest = data["xssmaze_digest"]?.try(&.as_s?)
  rate = total["rate"].as_f
  detected = total["detected"]
  endpoints = total["endpoints"]
  hex, rgb = meter_palette(rate)
  perfect = cats.count { |c| c["rate"].as_f >= 100.0 }
  gaps = cats.reject { |c| c["rate"].as_f >= 100.0 }.sort_by { |c| c["rate"].as_f }
  gen_date = data["generated_at"].as_s.split("T").first

  String.build do |io|
    # --- Score board: one big score readout (one contiguous HTML block) ---
    io << %(<div style="margin:1.5rem 0;padding:1.6rem 1.75rem;background:radial-gradient(120% 140% at 100% 0%,rgba(139,148,232,0.10),transparent 55%),linear-gradient(135deg,var(--bg-surface,#11141f),var(--bg-sidebar,#0b0d18));border:1px solid var(--border-light,#222741);border-radius:14px">)
    io << %(<div style="font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.12em;color:var(--text-muted,#636980)">Detection score</div>)
    io << %(<div style="display:flex;align-items:baseline;margin-top:.4rem;color:var(--text-primary,#e7e9f3);font-variant-numeric:tabular-nums"><span style="font-size:clamp(2.6rem,9vw,3.6rem);font-weight:700;line-height:1;letter-spacing:-.02em">#{rate}</span><span style="font-size:1.6rem;font-weight:600;color:var(--text-secondary,#9aa0bb)">%</span></div>)
    io << %(<div style="margin-top:.55rem;font-size:.95rem;color:var(--text-secondary,#9aa0bb)"><strong style="color:var(--text-primary,#e7e9f3);font-variant-numeric:tabular-nums">#{detected}</strong> / #{endpoints} endpoints detected across #{cats.size} categories</div>)
    io << %(<div style="margin-top:1.4rem;height:.6rem;background:var(--bg-body,#070811);border-radius:999px;overflow:hidden"><div style="height:100%;width:#{rate}%;background:#{hex};box-shadow:0 0 16px rgba(#{rgb},0.45);border-radius:999px"></div></div>)
    io << %(<div style="margin-top:1.3rem;padding-top:1rem;border-top:1px solid var(--border,#161a28);display:flex;flex-wrap:wrap;gap:.4rem 1.25rem;font-size:.8rem;color:var(--text-muted,#636980)">)
    io << %(<span><span style="color:var(--text-secondary,#9aa0bb)">dalfox</span> v#{data["dalfox_version"].as_s}</span>)
    io << %(<span><span style="color:var(--text-secondary,#9aa0bb)">xssmaze</span> v#{data["xssmaze_version"].as_s}</span>)
    io << %(<span>generated #{gen_date}</span>)
    io << %(</div>)
    io << %(</div>)

    # --- Stat tiles: flat, no left accent; values tinted for meaning ---
    io << %(<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:.75rem;margin:1rem 0">)
    io << tile("Endpoints", endpoints.to_s, "catalogued")
    io << tile("Categories", cats.size.to_s, "test groups")
    io << tile("Fully detected", perfect.to_s, "categories at 100%", "#34d399")
    io << tile("With gaps", gaps.size.to_s, "below 100%", gaps.empty? ? "#34d399" : "#f59e0b")
    io << %(</div>)

    # --- Detailed scores ---
    io << "\n\n### Coverage by category\n\n"
    if gaps.empty?
      io << %(<div style="margin:1.1rem 0;padding:.9rem 1.1rem;background:rgba(52,211,153,0.08);border:1px solid rgba(52,211,153,0.3);border-radius:10px;color:#34d399;font-size:.9rem">Every catalogued category detects all of its endpoints.</div>)
    else
      io << "**#{perfect} of #{cats.size}** categories detect every endpoint. The chart highlights the **#{gaps.size}** with gaps (worst first); the full breakdown is in the table.\n\n"
      io << %(<div style="margin:1.1rem 0">)
      gaps.each do |c|
        r = c["rate"].as_f
        io << %(<div style="display:flex;align-items:center;gap:.75rem;padding:.4rem 0">)
        io << %(<span style="flex:0 1 10rem;font-family:var(--font-mono,ui-monospace,monospace);font-size:.82rem;color:var(--text-secondary,#9aa0bb);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">#{c["category"].as_s}</span>)
        io << %(<span style="flex:1 1 auto;min-width:3rem;height:.5rem;background:var(--bg-body,#070811);border-radius:999px;overflow:hidden"><span style="display:block;height:100%;width:#{r}%;background:#{bar_color(r)}"></span></span>)
        io << %(<span style="flex:0 0 6.5rem;text-align:right;font-size:.8rem;color:var(--text-primary,#e7e9f3);font-variant-numeric:tabular-nums">#{c["detected"]}/#{c["endpoints"]} · #{r}%</span>)
        io << %(</div>)
      end
      io << %(</div>)
    end

    # --- Full reference table (alphabetical, every category) ---
    io << "\n\n| Category | Endpoints | Detected | Verified | Rate |\n"
    io << "| --- | ---: | ---: | ---: | ---: |\n"
    cats.each do |c|
      io << "| `#{c["category"].as_s}` | #{c["endpoints"]} | #{c["detected"]} | #{c["verified"]} | #{c["rate"]}% |\n"
    end
    io << "| **Total** | **#{endpoints}** | **#{detected}** | **#{total["verified"]}** | **#{rate}%** |\n"

    io << "\n_Generated #{data["generated_at"].as_s} · image `#{data["xssmaze_image"].as_s}`"
    io << " (`#{digest}`)" if digest
    io << " · run `just xssmaze-score` to refresh._\n"
  end
end

BEGIN_MARKER = "<!-- XSSMAZE:BEGIN — generated by `just xssmaze-score`; do not edit by hand -->"
END_MARKER   = "<!-- XSSMAZE:END -->"

def render_page(data : JSON::Any)
  abort "missing page: #{PAGE_PATH}" unless File.exists?(PAGE_PATH)
  content = File.read(PAGE_PATH)
  block = "#{BEGIN_MARKER}\n\n#{render_block(data)}\n#{END_MARKER}"
  replaced = content.sub(/#{Regex.escape(BEGIN_MARKER)}[\s\S]*?#{Regex.escape(END_MARKER)}/, block)
  if replaced == content && !content.includes?(BEGIN_MARKER)
    abort "markers not found in #{PAGE_PATH}; expected #{BEGIN_MARKER} ... #{END_MARKER}"
  end
  File.write(PAGE_PATH, replaced)
  puts "==> wrote #{PAGE_PATH}"
end

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

if RENDER_ONLY
  abort "no snapshot at #{DATA_PATH}; run a full scan first" unless File.exists?(DATA_PATH)
  render_page(JSON.parse(File.read(DATA_PATH)))
  exit 0
end

started = ensure_xssmaze
begin
  data = collect
  FileUtils.mkdir_p(File.dirname(DATA_PATH))
  File.write(DATA_PATH, data.to_pretty_json + "\n")
  puts "==> wrote #{DATA_PATH}"
  render_page(data)
  t = data["total"]
  puts "==> done: #{t["detected"]}/#{t["endpoints"]} endpoints detected (#{t["rate"]}%)"
ensure
  stop_xssmaze if started
end
