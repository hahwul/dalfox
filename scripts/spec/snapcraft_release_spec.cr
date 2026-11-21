require "spec"
require "yaml"

describe "Snapcraft publication" do
  it "limits automatic stable uploads to non-prerelease GitHub releases" do
    # Keep GitHub's `on` key as a string (YAML 1.1 core treats it as a boolean).
    workflow = YAML::Schema::FailSafe.parse(File.read(File.expand_path("../../.github/workflows/cd-snapcraft.yml", __DIR__)))
    workflow["on"]["release"]["types"].as_a.map(&.as_s).should eq(["published"])
    workflow["on"].as_h.has_key?(YAML::Any.new("workflow_dispatch")).should be_true

    job = workflow["jobs"]["snapcraft-releaser"]
    job["if"].as_s.should eq(%q[github.event_name == 'workflow_dispatch' || (github.event_name == 'release' && !github.event.release.prerelease)])
    publisher = job["steps"].as_a.find! do |step|
      step["uses"]?.try(&.as_s.starts_with?("canonical/action-publish@")) == true
    end
    publisher["with"]["release"].as_s.should eq("stable")
  end
end
