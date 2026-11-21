require "file_utils"
require "spec"
require "../lib/sh"

describe "version_update.cr" do
  it "rejects malformed versions before writing and accepts a valid prerelease" do
    root = File.expand_path("../..", __DIR__)
    fixture = File.tempname("dalfox-version-", nil)
    Dir.mkdir(fixture, 0o700)
    begin
      files = %w[
        Cargo.toml Cargo.lock snap/snapcraft.yaml packaging/aur/PKGBUILD
        docs/data/dalfox.json
        docs/content/getting-started/installation.md
        docs/content/getting-started/installation.ko.md
        docs/content/guide/output.md docs/content/guide/output.ko.md
      ].to_h do |path|
        contents = File.read(File.join(root, path))
        destination = File.join(fixture, path)
        Dir.mkdir_p(File.dirname(destination))
        File.write(destination, contents)
        {destination, contents}
      end

      updater = ["run", File.join(root, "scripts/version_update.cr")]
      %w[03.2.4 3.2.4-rc..1 3.2.4-rc. 3.2.4-rc.01 18446744073709551616.0.0].each do |version|
        result = Sh.run("crystal", updater, chdir: fixture, input: "#{version}\n")
        result.status.should eq(1)
        result.stdout.should contain("Invalid version: #{version}")
        files.each { |path, contents| File.read(path).should eq(contents) }
      end

      version = "0.0.0-rc.01a.0"
      update = Sh.run("crystal", updater, chdir: fixture, input: "#{version}\n")
      update.success?.should be_true
      check = Sh.run("crystal", ["run", File.join(root, "scripts/version_check.cr")], chdir: fixture)
      check.success?.should be_true
      check.stdout.should contain("All versions match: #{version}")
    ensure
      FileUtils.rm_rf(fixture)
    end
  end
end
