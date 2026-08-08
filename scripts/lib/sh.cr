# Process helpers shared by the Crystal harnesses under `scripts/`.
#
# Everything here is deliberately non-raising: a harness that fails to spawn a
# process should report a failed check, not blow up mid-run. Callers that want
# a hard stop check `Sh::Output#success?` themselves.

module Sh
  # Result of one child process. `timed_out` is true when the process was
  # killed because it outlived the `timeout:` budget; `status` is then the
  # signal-derived exit code, which is meaningless — check `timed_out` first.
  struct Output
    getter status : Int32
    getter stdout : String
    getter stderr : String
    getter timed_out : Bool
    getter elapsed : Time::Span

    def initialize(@status, @stdout, @stderr, @timed_out, @elapsed)
    end

    def success? : Bool
      !@timed_out && @status == 0
    end

    # First line of stderr, for compact failure messages.
    def error_line : String
      @stderr.each_line.find { |l| !l.strip.empty? }.try(&.strip) || ""
    end
  end

  # Monotonic clock reading. `Time.monotonic` is deprecated from Crystal 1.21
  # in favour of `Time.instant`; both subtract to a `Time::Span`, so pick
  # whichever the compiler in use has and keep older toolchains warning-free.
  def self.clock
    {% if compare_versions(Crystal::VERSION, "1.21.0") >= 0 %}
      Time.instant
    {% else %}
      Time.monotonic
    {% end %}
  end

  # Run `cmd` and capture both streams. Never raises: a spawn failure comes
  # back as status 127 with the exception message on stderr.
  #
  # `timeout` kills the process (SIGKILL) once the budget elapses.
  def self.run(cmd : String,
               args : Array(String),
               env : Process::Env = nil,
               input : String? = nil,
               chdir : String? = nil,
               timeout : Time::Span? = nil) : Output
    stdout_io = IO::Memory.new
    stderr_io = IO::Memory.new
    stdin = input ? IO::Memory.new(input) : Process::Redirect::Close
    started = clock

    process = Process.new(cmd, args,
      env: env, chdir: chdir,
      input: stdin, output: stdout_io, error: stderr_io)

    timed_out = false
    status_ch = Channel(Process::Status).new(1)
    spawn { status_ch.send(process.wait) }

    status = if budget = timeout
               select
               when s = status_ch.receive
                 s
               when timeout(budget)
                 timed_out = true
                 process.signal(Signal::KILL) rescue nil
                 status_ch.receive
               end
             else
               status_ch.receive
             end

    # A signal-killed child has no exit code; report -1 rather than raising.
    code = begin
      status.exit_code
    rescue
      -1
    end
    Output.new(code, stdout_io.to_s, stderr_io.to_s, timed_out, clock - started)
  rescue ex
    Output.new(127, "", ex.message || "spawn failed", false, Time::Span.zero)
  end

  # True when the command ran and exited 0. Output is discarded.
  def self.run_quiet(cmd : String, args : Array(String), timeout : Time::Span? = nil) : Bool
    run(cmd, args, timeout: timeout).success?
  end

  # Stripped stdout, or "" on any failure. For version probes and the like.
  def self.capture(cmd : String, args : Array(String), timeout : Time::Span? = nil) : String
    run(cmd, args, timeout: timeout).stdout.strip
  end

  # Absolute path of `cmd` on PATH, or nil.
  def self.which(cmd : String) : String?
    path = capture("sh", ["-c", "command -v #{Process.quote(cmd)}"])
    path.empty? ? nil : path
  end

  # Fan `items` out over `workers` fibers, calling `block` for each, and return
  # the results in input order. The harnesses all want exactly this and each
  # was hand-rolling a Channel pair.
  def self.parallel_map(items : Array(T), workers : Int32, &block : T -> R) : Array(R) forall T, R
    return [] of R if items.empty?
    n = items.size
    jobs = Channel({Int32, T}).new(n)
    done = Channel({Int32, R}).new(n)
    items.each_with_index { |item, i| jobs.send({i, item}) }
    jobs.close

    Math.min(workers, n).times do
      spawn do
        while pair = jobs.receive?
          idx, item = pair
          done.send({idx, block.call(item)})
        end
      end
    end

    results = Array(R?).new(n, nil)
    n.times do
      idx, value = done.receive
      results[idx] = value
    end
    results.map(&.not_nil!)
  end

  # Same as `parallel_map` but reports `done/total` progress on one line.
  def self.parallel_map_progress(items : Array(T), workers : Int32, label : String, &block : T -> R) : Array(R) forall T, R
    total = items.size
    done_count = 0
    lock = Mutex.new
    result = parallel_map(items, workers) do |item|
      value = block.call(item)
      lock.synchronize do
        done_count += 1
        print "\r==> #{label} #{done_count}/#{total}"
      end
      value
    end
    puts "" unless total.zero?
    result
  end
end
