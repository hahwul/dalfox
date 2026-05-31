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

# Build the dalfox argument list for one maze, pointing it at the catalog's
# declared injection point. Mining is skipped (the endpoint is known) while
# discovery/reflection checks stay on so header/path cases still resolve.
def build_args(maze : Maze, out_file : String) : Array(String)
  args = ["scan", BASE_URL + maze.url,
          "--format", "json", "-o", out_file,
          "-S", "--no-color", "--skip-mining",
          "--timeout", "7", "--scan-timeout", "40"]
  args.push("-X", maze.method) if maze.method != "GET"

  body_params = [] of String
  maze.params.each do |p|
    next if p == ":path" # default path reflection covers this
    if HEADER_PARAMS.includes?(p)
      args.push("-p", "#{p}:header")
    elsif maze.method == "POST"
      args.push("-p", "#{p}:body")
      body_params << p
    else
      args.push("-p", "#{p}:query")
    end
  end
  args.push("-d", body_params.map { |p| "#{p}=a" }.join("&")) unless body_params.empty?
  args
end

# Scan one maze. Returns {detected, verified}.
def scan(maze : Maze) : {Bool, Bool}
  out_file = File.tempname("dalfox-xssmaze", ".json")
  args = build_args(maze, out_file)
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
  when rate >= 90 then "#4ade80" # green
  when rate >= 70 then "#8b94e8" # accent
  when rate >= 40 then "#f59e0b" # amber
  else                 "#f87171" # red
  end
end

def render_block(data : JSON::Any) : String
  total = data["total"]
  cats = data["categories"].as_a
  digest = data["xssmaze_digest"]?.try(&.as_s?)
  short_digest = digest.try { |d| d.includes?("@") ? d.split("@").last[0, 19] : d[0, 19] }

  String.build do |io|
    # Summary cards.
    io << %(<div style="display:flex;flex-wrap:wrap;gap:.75rem;margin:1.25rem 0">)
    io << stat_card("Overall detection",
      "#{total["detected"]} / #{total["endpoints"]}",
      "#{total["rate"]}% of endpoints", bar_color(total["rate"].as_f))
    io << stat_card("Categories", cats.size.to_s, "", "#8b94e8")
    io << stat_card("dalfox", "v#{data["dalfox_version"].as_s}", "", "#8b94e8")
    io << stat_card("xssmaze", "v#{data["xssmaze_version"].as_s}",
      short_digest || "main", "#8b94e8")
    io << %(</div>)
    io << "\n\n### Coverage by category\n\n"

    # Horizontal bar chart (one contiguous HTML block — no blank lines).
    io << %(<div style="margin:1rem 0;font-size:.85rem">)
    cats.each do |c|
      r = c["rate"].as_f
      io << %(<div style="display:flex;align-items:center;gap:.6rem;margin:.3rem 0">)
      io << %(<span style="flex:0 0 13rem;color:var(--text-secondary,#9aa0bb);font-family:var(--font-mono,ui-monospace,monospace);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">#{c["category"].as_s}</span>)
      io << %(<span style="flex:1;height:.7rem;background:var(--bg-surface,#11141f);border:1px solid var(--border-light,#222741);border-radius:999px;overflow:hidden">)
      io << %(<span style="display:block;height:100%;width:#{r}%;background:#{bar_color(r)}"></span>)
      io << %(</span>)
      io << %(<span style="flex:0 0 7rem;text-align:right;color:var(--text-primary,#e7e9f3);font-variant-numeric:tabular-nums">#{c["detected"]}/#{c["endpoints"]} · #{r}%</span>)
      io << %(</div>)
    end
    io << %(</div>)

    # Data table.
    io << "\n\n| Category | Endpoints | Detected | Verified | Rate |\n"
    io << "| --- | ---: | ---: | ---: | ---: |\n"
    cats.each do |c|
      io << "| `#{c["category"].as_s}` | #{c["endpoints"]} | #{c["detected"]} | #{c["verified"]} | #{c["rate"]}% |\n"
    end
    io << "| **Total** | **#{total["endpoints"]}** | **#{total["detected"]}** | **#{total["verified"]}** | **#{total["rate"]}%** |\n"

    io << "\n_Generated #{data["generated_at"].as_s} · image `#{data["xssmaze_image"].as_s}`"
    io << " (`#{digest}`)" if digest
    io << " · run `just xssmaze-score` to refresh._\n"
  end
end

def stat_card(label : String, value : String, sub : String, accent : String) : String
  String.build do |io|
    io << %(<div style="flex:1 1 9rem;min-width:8rem;padding:.7rem .9rem;background:var(--bg-surface,#11141f);border:1px solid var(--border-light,#222741);border-left:3px solid #{accent};border-radius:6px">)
    io << %(<div style="font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--text-muted,#636980)">#{label}</div>)
    io << %(<div style="font-size:1.35rem;font-weight:600;color:var(--text-primary,#e7e9f3)">#{value}</div>)
    io << %(<div style="font-size:.75rem;color:var(--text-secondary,#9aa0bb)">#{sub}</div>) unless sub.empty?
    io << %(</div>)
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
