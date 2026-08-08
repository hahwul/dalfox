# Pass/fail reporting for the gate-style harnesses (parity, lint, conformance,
# hostile-input). `version_check.cr` established the convention these follow:
# print one line per check and exit non-zero when anything failed, so the
# script drops straight into CI without a wrapper.
#
#   report = Report.new("surface parity")
#   report.check("config keys match CLI flags") { missing.empty? }
#   report.fail("docs key reference", "missing: --new-flag")
#   exit report.finish

require "colorize"

class Report
  enum Status
    Pass
    Fail
    Skip
  end

  record Entry, group : String, name : String, status : Status, detail : String

  getter title : String
  getter entries = [] of Entry
  property verbose : Bool

  # NO_COLOR is honoured because these run in CI logs as often as in a TTY.
  def initialize(@title : String, @verbose : Bool = false)
    @group = ""
    Colorize.enabled = STDOUT.tty? && !ENV.has_key?("NO_COLOR")
    puts "==> #{@title}"
  end

  # Start a named section. Purely cosmetic grouping in the summary.
  def group(name : String)
    @group = name
    puts "\n#{name}".colorize.bold.to_s
  end

  def group(name : String, &)
    group(name)
    yield
  end

  # Record a passing check.
  def pass(name : String, detail : String = "")
    record(Status::Pass, name, detail)
  end

  # Record a failing check. `detail` is what a reader needs to fix it.
  def fail(name : String, detail : String = "")
    record(Status::Fail, name, detail)
  end

  # Record a check that could not run (missing tool, absent optional fixture).
  # Skips never fail the run — a harness that must not be skipped should call
  # `fail` instead.
  def skip(name : String, detail : String = "")
    record(Status::Skip, name, detail)
  end

  # Run a predicate as a check. An exception counts as a failure with the
  # message attached, so a harness never dies half-way through its checklist.
  def check(name : String, detail : String = "", &block : -> Bool)
    ok = block.call
    ok ? pass(name, ok ? "" : detail) : fail(name, detail)
  rescue ex
    fail(name, "raised: #{ex.message}")
  end

  # Assert two values are equal, reporting the difference on failure.
  def check_eq(name : String, expected, actual)
    if expected == actual
      pass(name)
    else
      fail(name, "expected #{expected.inspect}, got #{actual.inspect}")
    end
  end

  # Assert a collection is empty, listing up to `limit` offenders.
  def check_empty(name : String, items : Enumerable, limit : Int32 = 8)
    list = items.to_a
    if list.empty?
      pass(name)
    else
      shown = list.first(limit).map(&.to_s).join(", ")
      more = list.size > limit ? " (+#{list.size - limit} more)" : ""
      fail(name, "#{list.size}: #{shown}#{more}")
    end
  end

  def failures : Array(Entry)
    @entries.select { |e| e.status.fail? }
  end

  def failed? : Bool
    !failures.empty?
  end

  # Print the summary and return the process exit code (0 clean, 1 on any
  # failure). Callers do `exit report.finish`.
  def finish : Int32
    passed = @entries.count { |e| e.status.pass? }
    skipped = @entries.count { |e| e.status.skip? }
    failed = failures.size

    puts ""
    if failed.zero?
      puts "==> #{@title}: #{passed} passed#{skipped.zero? ? "" : ", #{skipped} skipped"}".colorize.green.to_s
      0
    else
      puts "==> #{@title}: #{failed} FAILED, #{passed} passed#{skipped.zero? ? "" : ", #{skipped} skipped"}".colorize.red.to_s
      failures.each do |e|
        label = e.group.empty? ? e.name : "#{e.group} / #{e.name}"
        puts "    - #{label}#{e.detail.empty? ? "" : ": #{e.detail}"}"
      end
      1
    end
  end

  private def record(status : Status, name : String, detail : String)
    @entries << Entry.new(@group, name, status, detail)
    mark, color = case status
                  in Status::Pass then {"ok  ", :green}
                  in Status::Fail then {"FAIL", :red}
                  in Status::Skip then {"skip", :dark_gray}
                  end
    line = "  #{mark}  #{name}"
    line += " — #{detail}" unless detail.empty? || (status.pass? && !@verbose)
    puts line.colorize(color).to_s
  end
end
