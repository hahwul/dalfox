# Loader for the `tests/functional/mock_cases/**/*.toml` corpus.
#
# That corpus is the repo's only labelled XSS ground truth: each case declares a
# reflection template and whether dalfox is *expected* to detect it, which is
# exactly what an FP/FN measurement needs. The Rust functional tests consume it
# through `tests/functional/mock_case_loader.rs` + `xss_mock_server.rs`; this is
# the Crystal side.
#
# Crystal has no stdlib TOML parser and the corpus uses a deliberately small
# subset — `[[case]]` tables of scalars, literal strings, string arrays, and
# triple-quoted blocks — so the parser below covers that subset and nothing
# else. It raises on anything it does not understand rather than silently
# dropping a case: a dropped case would quietly inflate a detection score.
#
# Two fidelity notes for anyone serving these cases from Crystal:
#
#   * `Case#render` is a plain `{input}` substitution, matching
#     `xss_mock_server.rs#apply_reflection`. Doubled braces (`{{`) in the corpus
#     are NOT format-escapes there and must stay literal — "fixing" them would
#     make the Crystal lab disagree with the Rust one.
#   * `filter` (server-side sanitizer chain) and `page_template` (canned
#     real-world page) are behaviours implemented in the Rust server. A Crystal
#     lab that does not reimplement them must restrict itself to
#     `Case#self_contained?` cases rather than serving the rest unfiltered,
#     which would turn expected-clean cases into bogus false positives.

module MockCases
  ROOT = "tests/functional/mock_cases"

  alias Value = String | Bool | Int32 | Array(String)

  # One labelled reflection case.
  struct Case
    getter id : Int32
    getter name : String
    getter description : String
    getter handler_type : String
    getter reflection : String
    getter expected_detection : Bool
    getter source_file : String
    # Long-tail keys kept verbatim: `filter`, `page_template`, `category`,
    # `reference`, `status_code`, `content_type`, `response_headers`, plus the
    # per-type parameter-name overrides.
    getter extra : Hash(String, Value)

    def initialize(@id, @name, @description, @handler_type, @reflection,
                   @expected_detection, @source_file, @extra)
    end

    # Directory the case came from — `query`, `header`, `cookie`, `path`,
    # `body`, `dom_xss`, `realworld`.
    def category : String
      File.basename(File.dirname(@source_file))
    end

    # Corpus-unique identity (ids are only unique per injection type).
    def uid : String
      "#{category}/#{@id}"
    end

    def str(key : String) : String?
      @extra[key]?.as?(String)
    end

    def int(key : String) : Int32?
      @extra[key]?.as?(Int32)
    end

    def list(key : String) : Array(String)
      @extra[key]?.as?(Array(String)) || [] of String
    end

    # Server-side sanitizer chain (`strip_script`, `remove_keyword:alert|…`).
    def filter : String?
      str("filter")
    end

    # Canned real-world page shell the reflection is embedded in.
    def page_template : String?
      str("page_template")
    end

    def status_code : Int32
      int("status_code") || 200
    end

    def content_type : String
      str("content_type") || "text/html; charset=utf-8"
    end

    def response_headers : Array(String)
      list("response_headers")
    end

    # True when the case's behaviour is fully described by `reflection` alone,
    # i.e. no Rust-side filter chain or page template is involved. Only these
    # can be served faithfully by a harness that is not the Rust mock server.
    def self_contained? : Bool
      filter.nil? && page_template.nil?
    end

    # The parameter this case injects through, honouring the per-type override
    # keys and the defaults documented in `mock_cases/README.md`.
    def injection_param : String
      case @handler_type
      when "header" then str("header_name") || "X-Test"
      when "cookie" then str("cookie_name") || "test"
      else               str("param_name") || "query"
      end
    end

    # Render the case's HTML for `input`. `{input}` is the corpus placeholder;
    # see the fidelity note at the top of this file about `{{`.
    def render(input : String) : String
      @reflection.gsub("{input}", input)
    end
  end

  # Load every case under `dir` (defaults to the whole corpus).
  # `categories` filters by subdirectory name.
  def self.load(dir : String = ROOT, categories : Array(String)? = nil) : Array(Case)
    cases = [] of Case
    Dir.glob(File.join(dir, "**", "*.toml")).sort.each do |path|
      next if categories && !categories.includes?(File.basename(File.dirname(path)))
      cases.concat(parse_file(path))
    end
    cases
  end

  def self.parse_file(path : String) : Array(Case)
    parse(File.read(path), path)
  end

  # Parse the `[[case]]` tables out of one TOML file.
  def self.parse(source : String, path : String) : Array(Case)
    tables = [] of Hash(String, Value)
    current = nil.as(Hash(String, Value)?)

    lines = source.lines
    i = 0
    while i < lines.size
      line = lines[i].strip
      i += 1

      next if line.empty? || line.starts_with?('#')

      if line == "[[case]]"
        current = Hash(String, Value).new
        tables << current
        next
      end

      # Any other table header ends the case list for our purposes.
      if line.starts_with?('[')
        current = nil
        next
      end

      next unless current
      key, sep, rest = line.partition('=')
      raise "#{path}:#{i}: unparsed line #{line.inspect}" if sep.empty?
      key = key.strip
      value = rest.strip

      if value.starts_with?(%("""))
        current[key] = multiline(lines, pointerof(i), value, key, path)
      else
        current[key] = scalar(value, path, i)
      end
    end

    tables.compact_map { |t| build(t, path) }
  end

  # Consume a `"""` block starting at `first` (the text after `key =`),
  # advancing the line cursor past the closing delimiter.
  private def self.multiline(lines : Array(String), cursor : Int32*,
                             first : String, key : String, path : String) : String
    inner = first[3..]
    if idx = inner.index(%("""))
      return inner[0, idx]
    end

    buf = [] of String
    buf << inner unless inner.empty?
    while cursor.value < lines.size
      l = lines[cursor.value]
      cursor.value += 1
      if idx = l.index(%("""))
        buf << l[0, idx] unless idx.zero?
        return buf.join("\n")
      end
      buf << l.chomp
    end
    raise %(#{path}: unterminated """ for key #{key})
  end

  private def self.scalar(value : String, path : String, line : Int32) : Value
    if value.starts_with?('"')
      closing = find_closing_quote(value)
      raise "#{path}:#{line}: unterminated string" unless closing
      return unescape(value[1...closing])
    end

    # Literal string: no escape processing, so `\v` stays two characters —
    # which is the point for the payloads that use it.
    if value.starts_with?('\'')
      closing = value.index('\'', 1)
      raise "#{path}:#{line}: unterminated literal string" unless closing
      return value[1...closing]
    end

    if value.starts_with?('[')
      closing = value.rindex(']')
      raise "#{path}:#{line}: unterminated array" unless closing
      body = value[1...closing].strip
      return [] of String if body.empty?
      return split_array(body).map { |el| scalar(el.strip, path, line).to_s }
    end

    value = value.split('#').first.strip
    return true if value == "true"
    return false if value == "false"
    if int = value.to_i?
      return int
    end
    raise "#{path}:#{line}: unsupported value #{value.inspect}"
  end

  # Split an inline array body on commas that are outside quotes.
  private def self.split_array(body : String) : Array(String)
    parts = [] of String
    buf = String::Builder.new
    quote = nil.as(Char?)
    escaped = false
    body.each_char do |c|
      if escaped
        buf << c
        escaped = false
        next
      end
      case
      when c == '\\' && quote == '"'
        buf << c
        escaped = true
      when quote
        quote = nil if c == quote
        buf << c
      when c == '"' || c == '\''
        quote = c
        buf << c
      when c == ','
        parts << buf.to_s
        buf = String::Builder.new
      else
        buf << c
      end
    end
    tail = buf.to_s.strip
    parts << tail unless tail.empty?
    parts
  end

  private def self.find_closing_quote(value : String) : Int32?
    idx = 1
    while idx < value.size
      c = value[idx]
      return idx if c == '"'
      idx += (c == '\\' ? 2 : 1)
    end
    nil
  end

  private def self.unescape(s : String) : String
    s.gsub(/\\(.)/) do |_, m|
      case m[1]
      when "n"  then "\n"
      when "t"  then "\t"
      when "r"  then "\r"
      when "\\" then "\\"
      when "\"" then "\""
      else           m[1]
      end
    end
  end

  private def self.build(t : Hash(String, Value), path : String) : Case?
    return nil if t.empty?
    id = t["id"]?.as?(Int32) || raise "#{path}: case without an integer id"
    known = {"id", "name", "description", "handler_type", "reflection", "expected_detection"}
    Case.new(
      id: id,
      name: t["name"]?.as?(String) || "case_#{id}",
      description: t["description"]?.as?(String) || "",
      handler_type: t["handler_type"]?.as?(String) || File.basename(File.dirname(path)),
      reflection: t["reflection"]?.as?(String) || "",
      expected_detection: t["expected_detection"]?.as?(Bool) != false,
      source_file: path,
      extra: t.reject { |k, _| known.includes?(k) },
    )
  end
end
