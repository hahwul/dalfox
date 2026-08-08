# Read-only linter for the `docs/` site (hwaro → GitHub Pages). It guards the
# invariants the build itself does not: the site is bilingual by *filename*
# (`page.md` + `page.ko.md`), it is served with no custom headers so its CSP
# lives in a `<meta>` tag with `script-src 'self'`, and every asset is vendored
# under `docs/static/`. Nothing here writes to `docs/` — a failing check is a
# doc to fix, never a check to relax.
#
# Checks (each selectable through DOCS_LINT_ONLY):
#   ko-siblings   every content page has its `.ko.md` twin, and vice versa
#   frontmatter   `+++` TOML block parses, and paired pages share a key set;
#                 language is carried by the filename, so a `lang`-style key
#                 would be a silent no-op and is rejected
#   links         internal links and `#anchors` resolve to a real page/heading
#   assets        no off-site script/stylesheet/font/image host (CSP + no CDN)
#   inline-script no live `<script>` in content (`script-src 'self'`)
#   markers       `<!-- NAME:BEGIN … -->` / `<!-- NAME:END -->` pairs balanced
#                 and ordered — a moved marker silently breaks its generator
#                 (scripts/xssmaze_score.cr:419-431 aborts or writes nowhere)
#   skill-digest  the recorded `sha256:` in the agent-skills discovery document
#                 still matches the SKILL.md it points at, and the published
#                 copy still matches the repo-root `skills/` original
#
# Site conventions this encodes, from docs/config.toml + docs/AGENTS.md:
#   * `content/index.md` → `/`, `content/x/_index.md` → `/x/`,
#     `content/x/y.md` → `/x/y/`; the `.ko.md` twin of each is `/ko/…`.
#   * Internal links are relative and directory-style (`./child/`,
#     `../sibling/`, `../../section/page/`) — never `.md`, never root-rooted,
#     because a root-rooted link would escape the `/ko/` prefix.
#   * `[markdown] safe = false` and `page.html` renders `{{ content }}`
#     unfiltered, so raw HTML in a page reaches the browser verbatim. That is
#     what makes the assets / inline-script checks load-bearing rather than
#     cosmetic.
#
# Environment:
#   DOCS_DIR        docs root                   (default docs)
#   SKILLS_DIR      repo-root skill bundle      (default skills)
#   DOCS_LINT_ONLY  run a single check by name  (default: all)

require "json"
require "digest/sha256"
require "./lib/report"

DOCS_DIR    = ENV.fetch("DOCS_DIR", "docs")
CONTENT_DIR = File.join(DOCS_DIR, "content")
STATIC_DIR  = File.join(DOCS_DIR, "static")
SKILLS_DIR  = ENV.fetch("SKILLS_DIR", "skills")
ONLY        = ENV["DOCS_LINT_ONLY"]?

CHECKS = %w[ko-siblings frontmatter links assets inline-script markers skill-digest]

def run?(name : String) : Bool
  ONLY.nil? || ONLY == name
end

# ---------------------------------------------------------------------------
# Page model.
# ---------------------------------------------------------------------------

class Page
  getter path : String        # docs/content/guide/output.ko.md
  getter rel : String         # guide/output.ko.md
  getter body : String        # markdown after the front-matter block
  getter frontmatter : String # raw text between the `+++` fences
  getter body_offset : Int32  # 1-based line number where `body` starts
  getter korean : Bool
  getter url : String # /ko/guide/output/

  def initialize(@path, @rel, raw : String)
    @korean = @rel.ends_with?(".ko.md")
    @frontmatter, @body, @body_offset = Page.split_frontmatter(raw)
    @url = Page.url_for(@rel, @korean)
  end

  # hwaro front matter is TOML between `+++` fences (docs/AGENTS.md), always at
  # the very top. A page without them is reported by the frontmatter check
  # rather than silently treated as bodyless.
  def self.split_frontmatter(raw : String) : {String, String, Int32}
    return {"", raw, 1} unless raw.starts_with?("+++")
    # `chomp: false` matters: the default strips the newlines, and rejoining
    # then collapses the whole page into one line — every per-line check below
    # silently degrades to "scan the entire file, report line 1".
    lines = raw.lines(chomp: false)
    close = (1...lines.size).find { |i| lines[i].strip == "+++" }
    return {"", raw, 1} unless close
    {lines[1...close].join, lines[(close + 1)..].join, close + 2}
  end

  def self.url_for(rel : String, korean : Bool) : String
    slug = rel.sub(/\.ko\.md$/, "").sub(/\.md$/, "")
    slug = slug.sub(/(^|\/)(_?index)$/, "\\1").chomp('/')
    prefix = korean ? "/ko" : ""
    slug.empty? ? "#{prefix}/" : "#{prefix}/#{slug}/"
  end

  # The `.ko.md` twin of an English page, or the English original of a Korean
  # one. Pure path arithmetic — the pairing is by filename, nothing else.
  def sibling_rel : String
    @korean ? @rel.sub(/\.ko\.md$/, ".md") : @rel.sub(/\.md$/, ".ko.md")
  end

  def frontmatter_keys : Set(String)
    @frontmatter.each_line.compact_map { |l| l.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/).try(&.[1]) }.to_set
  end

  # `[^\n]+` rather than `.+`: Crystal's `m` flag is DOTALL as well as
  # MULTILINE, so a `.+` here runs past the end of the line it matched.
  def frontmatter_value(key : String) : String?
    @frontmatter.match(/^\s*#{key}\s*=\s*([^\n]+)$/m).try(&.[1].strip)
  end

  def aliases : Array(String)
    raw = frontmatter_value("aliases") || return [] of String
    raw.scan(/"([^"]*)"/).map(&.[1])
  end

  # Body with fenced blocks and inline code spans blanked out (newlines kept so
  # line numbers still line up). Everything that inspects *live* markup — the
  # script, asset, link, and heading scans — works on this, because
  # `` `<script>` `` in a payload table is documentation, not markup.
  @live : String?

  def live_body : String
    @live ||= begin
      buf = String::Builder.new
      fenced = false
      @body.each_line(chomp: false) do |line|
        if line.lstrip.starts_with?("```") || line.lstrip.starts_with?("~~~")
          fenced = !fenced
          buf << "\n"
          next
        end
        if fenced
          buf << "\n"
        else
          # Blank the inside of every inline code span, keeping the length so
          # column offsets in a report still point at the right place.
          buf << line.gsub(/`[^`\n]*`/) { |m| " " * m.size }
        end
      end
      buf.to_s
    end
  end

  # Anchor targets the page offers: heading slugs plus any explicit `id="…"`
  # (the landing pages are hand-written HTML).
  @anchors : Set(String)?

  def anchors : Set(String)
    @anchors ||= begin
      set = Set(String).new
      live_body.each_line do |line|
        # `#[#]{0,5}` rather than `#{1,6}`: the latter is Crystal string
        # interpolation inside a regex literal, not a repetition count.
        if m = line.match(/^ {0,3}(#[#]{0,5})[ \t]+(.+?)[ \t]*#*[ \t]*$/)
          set << Docs.slugify(m[2])
        end
      end
      live_body.scan(/\sid\s*=\s*"([^"]+)"/) { |m| set << m[1].downcase }
      set
    end
  end
end

module Docs
  # Heading → anchor slug. Matches what the site actually links to today:
  # `## Baselines: reporting only what is new` → `baselines-reporting-only-what-is-new`
  # `## 베이스라인: 새로 생긴 것만 보고하기`      → `베이스라인-새로-생긴-것만-보고하기`
  # i.e. markup stripped, punctuation dropped, whitespace runs → one hyphen,
  # Unicode letters preserved (Korean headings slug to Korean anchors).
  def self.slugify(text : String) : String
    s = text.strip
    s = s.gsub(/!?\[([^\]]*)\]\([^)]*\)/, "\\1") # links/images → label
    s = s.gsub(/[`*_~]/, "")
    s = s.downcase
    s = s.gsub(/[^\p{L}\p{N}\s\-]/, "")
    s = s.gsub(/\s+/, "-")
    s.strip('-')
  end

  # Resolve `target` (a relative or root-rooted site path) against the URL of
  # the page it appears on. Directory semantics: page URLs already end in `/`,
  # so `./x/` is a child and `../x/` is a sibling.
  def self.resolve(from_url : String, target : String) : String
    segments = target.starts_with?('/') ? [] of String : from_url.split('/', remove_empty: true)
    target.split('/', remove_empty: true).each do |seg|
      case seg
      when "." then next
      when ".."
        segments.pop?
      else
        segments << seg
      end
    end
    trailing = target.ends_with?('/') || target.empty? ? "/" : ""
    segments.empty? ? "/" : "/#{segments.join('/')}#{trailing}"
  end

  # Links this linter has no opinion about: off-site, protocol-relative,
  # non-http schemes, and hwaro shortcode expansions.
  def self.skip_link?(target : String) : Bool
    return true if target.empty?
    return true if target.starts_with?("//")
    return true if target.starts_with?("{{")
    return true if target.matches?(/^[a-zA-Z][a-zA-Z0-9+.\-]*:/)
    false
  end
end

def load_pages : Array(Page)
  Dir.glob(File.join(CONTENT_DIR, "**", "*.md")).sort.map do |path|
    rel = path[(CONTENT_DIR.size + 1)..]
    Page.new(path, rel, File.read(path))
  end
end

unless Dir.exists?(CONTENT_DIR)
  abort "no content directory at #{CONTENT_DIR} (set DOCS_DIR)"
end

pages = load_pages
by_rel = pages.to_h { |p| {p.rel, p} }
report = Report.new("docs lint — #{pages.size} pages under #{CONTENT_DIR}")

if ONLY && !CHECKS.includes?(ONLY)
  abort "DOCS_LINT_ONLY=#{ONLY} is not one of: #{CHECKS.join(", ")}"
end

# ---------------------------------------------------------------------------
# ko-siblings — the pairing is by filename, so a missing twin is invisible to
# the build: hwaro just serves one language and the switcher dead-ends.
# ---------------------------------------------------------------------------

if run?("ko-siblings")
  report.group("ko-siblings")

  missing_ko = pages.reject(&.korean).reject { |p| by_rel.has_key?(p.sibling_rel) }.map(&.rel)
  report.check_empty("every English page has a .ko.md sibling", missing_ko)

  orphan_ko = pages.select(&.korean).reject { |p| by_rel.has_key?(p.sibling_rel) }.map(&.rel)
  report.check_empty("every .ko.md page has an English original", orphan_ko)

  en_count = pages.count { |p| !p.korean }
  report.check_eq("page counts match per language", en_count, pages.count(&.korean))
end

# ---------------------------------------------------------------------------
# frontmatter — keys drive the sidebar (`weight`), the TOC, and the template.
# A key present on one side of a pair and not the other renders the two
# languages differently for no authored reason.
# ---------------------------------------------------------------------------

if run?("frontmatter")
  report.group("frontmatter")

  no_fm = pages.select(&.frontmatter.empty?).map(&.rel)
  report.check_empty("every page opens with a `+++` TOML block", no_fm)

  untitled = pages.reject { |p| p.frontmatter_keys.includes?("title") }.map(&.rel)
  report.check_empty("every page declares `title`", untitled)

  undescribed = pages.reject { |p| p.frontmatter_keys.includes?("description") }.map(&.rel)
  report.check_empty("every page declares `description`", undescribed)

  # Language is derived from the `.ko.md` suffix (docs/config.toml), and hwaro
  # exposes it to templates as `page_language`. A front-matter key trying to set
  # it would be read by nothing at all — worse than absent, because it looks
  # authoritative.
  lang_keys = pages.compact_map do |p|
    hit = p.frontmatter_keys & Set{"lang", "language", "page_language", "locale"}
    "#{p.rel} (#{hit.to_a.join(", ")})" unless hit.empty?
  end
  report.check_empty("no page tries to set a language key in front matter", lang_keys)

  drift = [] of String
  pages.reject(&.korean).each do |en|
    ko = by_rel[en.sibling_rel]? || next
    only_en = (en.frontmatter_keys - ko.frontmatter_keys).to_a.sort
    only_ko = (ko.frontmatter_keys - en.frontmatter_keys).to_a.sort
    next if only_en.empty? && only_ko.empty?
    parts = [] of String
    parts << "only in #{en.rel}: #{only_en.join(", ")}" unless only_en.empty?
    parts << "only in #{ko.rel}: #{only_ko.join(", ")}" unless only_ko.empty?
    drift << parts.join("; ")
  end
  report.check_empty("paired pages share a front-matter key set", drift)

  # `weight` orders the sidebar; if the twins disagree the two languages list
  # their pages in different orders.
  weight_drift = pages.reject(&.korean).compact_map do |en|
    ko = by_rel[en.sibling_rel]? || next
    a, b = en.frontmatter_value("weight"), ko.frontmatter_value("weight")
    "#{en.rel}=#{a} vs #{ko.rel}=#{b}" if a != b
  end
  report.check_empty("paired pages agree on `weight`", weight_drift)
end

# ---------------------------------------------------------------------------
# links — a dead internal link is invisible until a reader clicks it; hwaro
# does not fail the build on one.
# ---------------------------------------------------------------------------

if run?("links")
  report.group("links")

  known_urls = Set(String).new
  anchors_by_url = {} of String => Set(String)
  pages.each do |p|
    known_urls << p.url
    anchors_by_url[p.url] = p.anchors
    p.aliases.each { |a| known_urls << (a.ends_with?('/') ? a : "#{a}/") }
  end
  # Everything under static/ is copied to the site root verbatim, so a
  # root-rooted link to `/robots.txt` or `/.well-known/security.txt` is valid.
  if Dir.exists?(STATIC_DIR)
    Dir.glob(File.join(STATIC_DIR, "**", "*"), match: File::MatchOptions::DotFiles).each do |f|
      known_urls << f[STATIC_DIR.size..] if File.file?(f)
    end
  end

  broken = [] of String
  bad_anchors = [] of String
  dot_md = [] of String
  root_rooted = [] of String

  # Markdown links plus the raw `href=` attributes the hand-written landing
  # pages use — both reach the browser, so both have to resolve.
  link_res = [
    /\[[^\]]*\]\(\s*([^)\s]+?)(?:\s+"[^"]*")?\s*\)/,
    /\shref\s*=\s*"([^"]*)"/,
  ]

  pages.each do |page|
    page.live_body.each_line.with_index(page.body_offset) do |line, lineno|
      link_res.each do |re|
        line.scan(re) do |m|
          target = m[1]
          next if Docs.skip_link?(target)
          where = "#{page.path}:#{lineno}"

          path_part, _, anchor = target.partition('#')

          if path_part.starts_with?('/') && !path_part.starts_with?("/.well-known")
            root_rooted << "#{where} → #{target}"
          end
          dot_md << "#{where} → #{target}" if path_part.ends_with?(".md")

          url = path_part.empty? ? page.url : Docs.resolve(page.url, path_part)
          unless path_part.empty? || known_urls.includes?(url)
            broken << "#{where} → #{target} (resolves to #{url})"
            next
          end
          next if anchor.empty?
          have = anchors_by_url[url]?
          if have && !have.includes?(anchor.downcase)
            bad_anchors << "#{where} → #{target} (no heading slugs to ##{anchor} on #{url})"
          end
        end
      end
    end
  end

  # A generous limit on purpose: a broken link is only actionable with its
  # file:line, and truncating the list hides half the pairs (every finding has
  # an EN and a KO twin).
  report.check_empty("internal links resolve to a real page", broken, limit: 30)
  report.check_empty("`#anchor` targets resolve to a real heading", bad_anchors, limit: 30)
  report.check_empty("no internal link keeps a `.md` extension", dot_md)
  # Root-rooted links break the `/ko/` prefix: `/guide/output/` on a Korean
  # page silently sends the reader to the English site.
  report.check_empty("no root-rooted internal link (breaks the /ko/ prefix)", root_rooted)
end

# ---------------------------------------------------------------------------
# assets — GitHub Pages serves no custom headers, so the only CSP is the
# `<meta>` tag in docs/templates/header.html (`default-src 'self'`). An
# off-site asset is not "slower", it is blocked.
# ---------------------------------------------------------------------------

if run?("assets")
  report.group("assets")

  # `src`/`href` on an element that *loads* something, pointing off-site.
  external_asset_res = {
    "script src"   => /<script[^>]*\ssrc\s*=\s*"(https?:\/\/[^"]*|\/\/[^"]*)"/i,
    "stylesheet"   => /<link[^>]*\shref\s*=\s*"(https?:\/\/[^"]*|\/\/[^"]*)"/i,
    "image src"    => /<img[^>]*\ssrc\s*=\s*"(https?:\/\/[^"]*|\/\/[^"]*)"/i,
    "iframe/embed" => /<(?:iframe|embed|object|source|video|audio)[^>]*\s(?:src|data)\s*=\s*"(https?:\/\/[^"]*|\/\/[^"]*)"/i,
    "css url()"    => /url\(\s*['"]?(https?:\/\/[^)'"]*)/i,
    "@import"      => /@import\s+(?:url\()?\s*['"](https?:\/\/[^'"]*)/i,
  }

  offenders = [] of String
  md_image_hosts = [] of String
  pages.each do |page|
    page.live_body.each_line.with_index(page.body_offset) do |line, lineno|
      external_asset_res.each do |label, re|
        if m = line.match(re)
          offenders << "#{page.path}:#{lineno} #{label} → #{m[1]}"
        end
      end
      # Markdown images are asset loads too, just with different syntax.
      line.scan(/!\[[^\]]*\]\(\s*(https?:\/\/[^)\s]+)/) do |m|
        md_image_hosts << "#{page.path}:#{lineno} → #{m[1]}"
      end
    end
  end

  report.check_empty("no off-site script/stylesheet/font/image host in content", offenders)
  report.check_empty("no markdown image pointing at an external host", md_image_hosts)
end

# ---------------------------------------------------------------------------
# inline-script — `script-src 'self'` has no `'unsafe-inline'`, so an inline
# `<script>` in a page is dead code that silently does nothing in production
# while working under `hwaro serve` (HWARO_DEV skips the meta CSP).
# ---------------------------------------------------------------------------

if run?("inline-script")
  report.group("inline-script")

  inline = [] of String
  handlers = [] of String
  pages.each do |page|
    page.live_body.each_line.with_index(page.body_offset) do |line, lineno|
      inline << "#{page.path}:#{lineno}: #{line.strip[0, 100]}" if line.matches?(/<script[\s>]/i)
      # Inline event handlers are `script-src` too under CSP Level 2+.
      if m = line.match(/\son(?:click|load|error|mouseover|submit|change|focus)\s*=\s*"/i)
        handlers << "#{page.path}:#{lineno}: #{m[0].strip}"
      end
    end
  end

  report.check_empty("no live `<script>` block in content", inline)
  report.check_empty("no inline event handler attribute in content", handlers)
end

# ---------------------------------------------------------------------------
# markers — generated blocks are rewritten by regex between a BEGIN/END pair
# (scripts/xssmaze_score.cr:426). A duplicated, reordered, or half-deleted
# marker makes the generator either abort or overwrite the wrong span.
# ---------------------------------------------------------------------------

if run?("markers")
  report.group("markers")

  marker_re = /<!--\s*([A-Z][A-Z0-9_]*)\s*:\s*(BEGIN|END)\b[^>]*-->/
  problems = [] of String
  seen_names = Set(String).new

  pages.each do |page|
    open = {} of String => Int32 # name → line it was opened on
    page.body.each_line.with_index(page.body_offset) do |line, lineno|
      line.scan(marker_re) do |m|
        name, kind = m[1], m[2]
        seen_names << name
        if kind == "BEGIN"
          if prev = open[name]?
            problems << "#{page.path}:#{lineno} #{name}:BEGIN reopened (already open since line #{prev})"
          end
          open[name] = lineno
        else
          if open.delete(name).nil?
            problems << "#{page.path}:#{lineno} #{name}:END without a matching BEGIN"
          end
        end
      end
    end
    open.each { |name, lineno| problems << "#{page.path}:#{lineno} #{name}:BEGIN never closed" }
  end

  report.check_empty("every generated block is balanced and ordered", problems)

  # The generators write the English page by default; a Korean twin holding the
  # same marker only refreshes when the generator is re-run against it.
  asym = [] of String
  seen_names.each do |name|
    holders = pages.select { |p| p.body.matches?(/<!--\s*#{name}\s*:\s*BEGIN\b/) }
    holders.reject(&.korean).each do |en|
      ko = by_rel[en.sibling_rel]?
      next if ko.nil?
      asym << "#{name}: #{en.rel} has it, #{ko.rel} does not" unless holders.includes?(ko)
    end
  end
  report.check_empty("generated blocks exist on both language twins", asym)

  if seen_names.empty?
    report.skip("marker names found", "no `<!-- NAME:BEGIN -->` pairs in content")
  else
    report.pass("marker names found", seen_names.to_a.sort.join(", "))
  end
end

# ---------------------------------------------------------------------------
# skill-digest — the agent-skills discovery document records a sha256 over the
# SKILL.md it advertises. Nothing regenerates it: editing the skill without
# re-hashing publishes a digest that no longer describes the file.
#
# NOTE: this overlaps whatever else in the repo verifies the skill surface;
# kept here on purpose so `docs_lint` is self-contained.
# ---------------------------------------------------------------------------

if run?("skill-digest")
  report.group("skill-digest")

  index_path = File.join(STATIC_DIR, ".well-known", "agent-skills", "index.json")
  if !File.exists?(index_path)
    report.skip("agent-skills discovery document", "no #{index_path}")
  else
    begin
      doc = JSON.parse(File.read(index_path))
      entries = doc["skills"]?.try(&.as_a?) || [] of JSON::Any
      if entries.empty?
        report.fail("agent-skills discovery document lists a skill", "`skills` is missing or empty")
      end
      entries.each do |entry|
        url = entry["url"]?.try(&.as_s?) || next
        name = entry["name"]?.try(&.as_s?) || url
        target = File.join(STATIC_DIR, url.lstrip('/'))
        unless File.exists?(target)
          report.fail("#{name}: advertised file exists", "#{url} → missing #{target}")
          next
        end
        recorded = entry["digest"]?.try(&.as_s?)
        if recorded.nil?
          report.skip("#{name}: digest recorded", "no `digest` field to verify")
        else
          algo, _, want = recorded.partition(':')
          actual = Digest::SHA256.hexdigest(File.read(target))
          if algo != "sha256"
            report.fail("#{name}: digest algorithm", "unsupported #{algo.inspect}")
          elsif want == actual
            report.pass("#{name}: recorded digest matches #{url}")
          else
            report.fail("#{name}: recorded digest matches #{url}",
              "#{index_path} records sha256:#{want[0, 16]}…, #{target} hashes to sha256:#{actual[0, 16]}…")
          end
        end

        # The published copy under docs/static is a hand-maintained duplicate
        # of the repo-root bundle. Drift there is the same trap one level up.
        origin = File.join(SKILLS_DIR, url.lstrip('/').sub(/^\.well-known\/agent-skills\//, ""))
        if File.exists?(origin)
          if File.read(origin) == File.read(target)
            report.pass("#{name}: published copy matches #{origin}")
          else
            report.fail("#{name}: published copy matches #{origin}",
              "#{target} and #{origin} differ")
          end
        else
          report.skip("#{name}: published copy matches its source", "no #{origin}")
        end
      end
    rescue ex
      report.fail("agent-skills discovery document parses", "#{index_path}: #{ex.message}")
    end
  end
end

exit report.finish
