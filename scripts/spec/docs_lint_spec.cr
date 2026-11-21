require "file_utils"
require "spec"
require "../lib/sh"

describe "docs_lint.cr" do
  it "ignores links inside fences and keeps checking after the matching closer" do
    script = File.expand_path("../docs_lint.cr", __DIR__)
    fixture = File.tempname("dalfox-docs-lint-", nil)
    Dir.mkdir(fixture, 0o700)
    begin
      content = File.join(fixture, "content")
      Dir.mkdir(content)
      fences = {
        "shorter"   => {"````markdown", "```", "````` \t"},
        "different" => {"~~~markdown", "```", "~~~"},
        "with-info" => {"```markdown", "```example", "```"},
      }
      fences.each do |name, (opener, example, closer)|
        File.write(File.join(content, "#{name}.md"), <<-MD)
          #{opener}
          #{example}
          [Example](../quoted-#{name}/)
          #{closer}
          [Broken link](../live-#{name}/)
          MD
      end
      File.write(File.join(content, "invalid-opener.md"), "```foo`bar\n[Broken link](../invalid-opener-link/)\n")

      result = Sh.run("crystal", ["run", script], env: {"DOCS_DIR" => fixture, "DOCS_LINT_ONLY" => "links"})
      result.status.should eq(1)
      fences.each_key do |name|
        result.stdout.should_not contain("../quoted-#{name}/")
        result.stdout.should contain("#{name}.md:5 → ../live-#{name}/")
      end
      result.stdout.should contain("invalid-opener.md:2 → ../invalid-opener-link/")
    ensure
      FileUtils.rm_rf(fixture)
    end
  end
end
