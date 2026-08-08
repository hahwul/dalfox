# Docker lifecycle helpers for harnesses that need a disposable lab container
# (XSSMaze today, whatever lab comes next tomorrow).
#
# The contract every caller wants: "make sure this thing is up; tell me whether
# *I* started it so I know whether to tear it down."

require "http/client"
require "./sh"

module Docker
  # A lab container the harness may or may not own.
  class Lab
    getter name : String
    getter image : String
    getter base_url : String
    getter started_here : Bool = false

    # `health_path` is polled until it answers 2xx.
    def initialize(@name : String,
                   @image : String,
                   @base_url : String,
                   @container_port : Int32 = 3000,
                   @health_path : String = "/health")
      @base_url = @base_url.rstrip("/")
    end

    def host_port : Int32
      URI.parse(@base_url).port || 80
    end

    def healthy? : Bool
      Docker.get(@base_url + @health_path) != nil
    end

    # Pull + run the image unless something already answers the health check.
    # Returns true when this call started the container. When `manage` is false
    # an unreachable lab aborts instead of touching docker.
    def ensure_up(manage : Bool = true, wait : Int32 = 60) : Bool
      return false if healthy?

      unless manage
        abort "#{@name}: nothing reachable at #{@base_url} and management is disabled."
      end
      unless Sh.which("docker")
        abort "#{@name}: docker not found on PATH and #{@base_url} is unreachable."
      end

      puts "==> pulling #{@image}"
      abort "docker pull failed for #{@image}" unless Sh.run_quiet("docker", ["pull", @image])
      Sh.run_quiet("docker", ["rm", "-f", @name])

      puts "==> starting #{@name} on port #{host_port}"
      unless Sh.run_quiet("docker", ["run", "-d", "--name", @name,
                                     "-p", "#{host_port}:#{@container_port}", @image])
        abort "docker run failed for #{@image}"
      end

      print "==> waiting for #{@health_path} "
      wait.times do
        if healthy?
          puts "ok"
          @started_here = true
          return true
        end
        print "."
        sleep 1.second
      end
      stop
      abort "\n#{@name} did not become healthy within #{wait}s."
    end

    def stop
      puts "==> stopping #{@name}"
      Sh.run_quiet("docker", ["rm", "-f", @name])
    end

    # Tear down only what this process started. Safe to call unconditionally
    # from an `ensure` block.
    def stop_if_owned
      stop if @started_here
    end

    def digest : String?
      Docker.image_digest(@image)
    end
  end

  # Repo-digest of a locally present image, or nil.
  def self.image_digest(image : String) : String?
    d = Sh.capture("docker", ["inspect", "--format", "{{index .RepoDigests 0}}", image])
    d.empty? || d.includes?("<no value>") ? nil : d
  end

  # Plain GET returning the body on 2xx, nil on anything else. Kept here so the
  # lab helpers have no dependency on a harness's own HTTP layer.
  def self.get(url : String) : String?
    resp = HTTP::Client.get(url)
    resp.success? ? resp.body : nil
  rescue
    nil
  end
end
