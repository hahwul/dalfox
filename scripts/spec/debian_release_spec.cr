require "file_utils"
require "spec"
require "yaml"
require "../lib/sh"

describe "Debian release asset validation" do
  it "requires a successful package listing and the exact generated asset paths" do
    workflow = YAML.parse(File.read(File.expand_path("../../.github/workflows/cd-release.yml", __DIR__)))
    step = workflow["jobs"]["build-and-upload"]["steps"].as_a.find! { |entry| entry["name"]? == "Build Debian package" }
    args = ["-eo", "pipefail", "-c", step["run"].as_s]
    fixture = File.tempname("dalfox-deb-release-", nil)
    Dir.mkdir(fixture, 0o700)
    begin
      archive = File.join(fixture, "target/debian/dalfox.deb")
      Dir.mkdir_p(File.dirname(archive))
      File.write(archive, "")
      cargo = File.join(fixture, "cargo")
      File.write(cargo, "#!/bin/sh\nexit 0\n")
      File.chmod(cargo, 0o700)
      dpkg = File.join(fixture, "dpkg-deb")
      File.write(dpkg, "#!/bin/sh\nprintf '%s\\n' \"$PACKAGE_LISTING\"\nexit \"$LIST_EXIT\"\n")
      File.chmod(dpkg, 0o700)

      listing = %w[
        man/man1/dalfox.1.gz
        bash-completion/completions/dalfox
        zsh/site-functions/_dalfox
        fish/vendor_completions.d/dalfox.fish
      ].join("\n") { |asset| "-rw-r--r-- root/root 0 2026-01-01 00:00 ./usr/share/#{asset}" }
      env = {"PATH" => "#{fixture}:#{ENV["PATH"]}", "PACKAGE_LISTING" => listing, "LIST_EXIT" => "0"}
      Sh.run("bash", args, env: env, chdir: fixture).success?.should be_true
      Sh.run("bash", args, env: env.merge({"LIST_EXIT" => "27"}), chdir: fixture).status.should eq(27)

      wrong_path = env.merge({"PACKAGE_LISTING" => listing.sub("_dalfox", "_dalfox.bak")})
      result = Sh.run("bash", args, env: wrong_path, chdir: fixture)
      result.status.should eq(1)
      result.stdout.should contain("missing an asset matching /usr/share/zsh/site-functions/_dalfox")

      File.delete(archive)
      no_archive = Sh.run("bash", args, env: env, chdir: fixture)
      no_archive.status.should eq(1)
      no_archive.stdout.should contain("No Debian package found")
    ensure
      FileUtils.rm_rf(fixture)
    end
  end
end
