require "file_utils"
require "spec"
require "../lib/sh"

describe "docs_lint.cr" do
  it "ignores links inside code examples and reports live links at their original lines" do
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
      File.write(File.join(content, "inline.md"), <<-'MD')
        Example: ``[example](../quoted-double/)`` [real link](../live-double/)
        Example: ```[example](../quoted-triple/) `` ` ``` [real link](../live-triple/)
        Ordinary unmatched `` [real link](../live-unmatched/) `short code`
        Escaped \` [real link](../live-escaped/) \`
        Example: \``[example](../quoted-after-escape/)` [real link](../live-after-escape/)
        Example: \\``[example](../quoted-even/)`` [real link](../live-even/)
        Example: ``[example](../quoted-before-close/)\`` [real link](../live-after-close/)
        MD

      result = Sh.run("crystal", ["run", script], env: {"DOCS_DIR" => fixture, "DOCS_LINT_ONLY" => "links"})
      result.status.should eq(1)
      fences.each_key do |name|
        result.stdout.should_not contain("../quoted-#{name}/")
        result.stdout.should contain("#{name}.md:5 → ../live-#{name}/")
      end
      result.stdout.should contain("invalid-opener.md:2 → ../invalid-opener-link/")
      %w[double triple after-escape even before-close].each do |name|
        result.stdout.should_not contain("../quoted-#{name}/")
      end
      %w[double triple unmatched escaped after-escape even after-close].each_with_index(1) do |name, line|
        result.stdout.should contain("inline.md:#{line} → ../live-#{name}/")
      end
    ensure
      FileUtils.rm_rf(fixture)
    end
  end

  it "keeps inline code in heading slugs and ignores anchors inside examples" do
    script = File.expand_path("../docs_lint.cr", __DIR__)
    fixture = File.tempname("dalfox-docs-headings-", nil)
    Dir.mkdir(fixture, 0o700)
    begin
      content = File.join(fixture, "content")
      Dir.mkdir(content)
      File.write(File.join(content, "anchors.md"), <<-'MD')
        ## Open `spec`
        [Heading](#open-spec)
        ## ``status``
        [Code-only heading](#status)
        <div id="real-id"></div>
        [Explicit ID](#real-id)
        Example: ``<div id="quoted-id"></div>``.
        [Invalid example ID](#quoted-id)
        ```markdown
        ## Fake `heading`
        ```
        [Invalid fenced heading](#fake-heading)
        ## ``user_profile``
        [Code identifier](#user-profile)
        ## Literal `[name](url)`
        [Code resembling a link](#literal-nameurl)
        ## Print `--all`
        [Flag in a heading](#print-all)
        MD

      result = Sh.run("crystal", ["run", script], env: {"DOCS_DIR" => fixture, "DOCS_LINT_ONLY" => "links"})
      result.status.should eq(1)
      %w[open-spec status real-id user-profile literal-nameurl print-all].each do |slug|
        result.stdout.should_not contain("#" + slug)
      end
      result.stdout.should contain("anchors.md:8 → #quoted-id")
      result.stdout.should contain("anchors.md:12 → #fake-heading")
    ensure
      FileUtils.rm_rf(fixture)
    end
  end
end
