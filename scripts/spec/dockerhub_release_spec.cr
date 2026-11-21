require "spec"
require "yaml"
require "../lib/sh"

workflow = YAML.parse(File.read(File.expand_path("../../.github/workflows/cd-dockerhub.yml", __DIR__)))
dockerhub_steps = workflow["jobs"]["dockerhub-publish"]["steps"].as_a

describe "Docker Hub release tags" do
  it "emits release aliases only for tag pushes" do
    metadata = dockerhub_steps.find! { |step| step["id"]? == "meta" }
    rules = metadata["with"]["tags"].as_s.lines
    semver_rules = rules.select(&.starts_with?("type=semver,"))
    semver_rules.size.should eq(3)
    semver_rules.all?(&.ends_with?(%q[,enable=${{ github.event_name == 'push' }}])).should be_true
    rules.should contain(%q[type=raw,value=${{ inputs.tag }},enable=${{ github.event_name == 'workflow_dispatch' }}])
  end

  it "accepts only exact Docker image tags for manual publication" do
    validation = dockerhub_steps.find! { |step| step["id"]? == "manual-tag" }
    validation["if"].as_s.should eq("github.event_name == 'workflow_dispatch'")
    args = ["-euo", "pipefail", "-c", validation["run"].as_s]
    %w[manual v3.4.0-rc.1 _V3.4 latest].push("a" * 128).each do |tag|
      Sh.run("bash", args, env: {"LC_ALL" => "C", "MANUAL_TAG" => tag}).success?.should be_true
    end
    ["", ".leading", "bad/label", "bad,priority=1000", "bad\nlabel", "café", "a" * 129].each do |tag|
      result = Sh.run("bash", args, env: {"LC_ALL" => "C", "MANUAL_TAG" => tag})
      result.status.should eq(1)
      result.stdout.should contain("Enter a valid Docker image tag")
    end
  end
end
