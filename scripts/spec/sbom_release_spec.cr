require "file_utils"
require "spec"
require "yaml"
require "../lib/sh"

describe "SBOM release asset" do
  it "requires a nonempty file at the exact path the uploader uses" do
    workflow = YAML.parse(File.read(File.expand_path("../../.github/workflows/cd-release-asset.yml", __DIR__)))
    job = workflow["jobs"]["generate-sbom"]
    sbom_path = job["env"]["SBOM_PATH"].as_s
    sbom_path.should eq("dalfox.cdx.xml")
    steps = job["steps"].as_a
    generator = steps.find! { |step| step["name"]? == "Generate SBOM" }
    upload = steps.find! { |step| step["name"]? == "Upload SBOM to release" }
    upload["with"]["files"].as_s.should eq(%q[${{ env.SBOM_PATH }}])
    upload["with"]["fail_on_unmatched_files"].as_bool.should be_true

    fixture = File.tempname("dalfox-sbom-release-", nil)
    Dir.mkdir(fixture, 0o700)
    begin
      cargo = File.join(fixture, "cargo")
      File.write(cargo, <<-'SH')
        #!/bin/sh
        test "$1 $2 $3 $4 $5" = "cyclonedx --format xml --override-filename ${SBOM_PATH%.xml}" || exit 2
        case "$SBOM_FIXTURE" in
          missing) ;;
          empty) : > "$SBOM_PATH" ;;
          directory) mkdir "$SBOM_PATH" ;;
          complete|failure)
            printf '<bom xmlns="http://cyclonedx.org/schema/bom/1.3"/>\n' > "$SBOM_PATH"
            if [ "$SBOM_FIXTURE" = failure ]; then exit 27; fi
            ;;
        esac
        SH
      File.chmod(cargo, 0o700)
      args = ["-eo", "pipefail", "-c", generator["run"].as_s]
      artifact = File.join(fixture, sbom_path)
      env = {"PATH" => "#{fixture}:#{ENV["PATH"]}", "SBOM_PATH" => sbom_path}
      %w[missing empty directory].each do |kind|
        result = Sh.run("bash", args, env: env.merge({"SBOM_FIXTURE" => kind}), chdir: fixture)
        result.status.should eq(1)
        result.stdout.should contain("Generated SBOM #{sbom_path}")
        FileUtils.rm_rf(artifact)
      end
      Sh.run("bash", args, env: env.merge({"SBOM_FIXTURE" => "failure"}), chdir: fixture).status.should eq(27)
      File.delete(artifact)
      Sh.run("bash", args, env: env.merge({"SBOM_FIXTURE" => "complete"}), chdir: fixture).success?.should be_true
    ensure
      FileUtils.rm_rf(fixture)
    end
  end
end
