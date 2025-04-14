# frozen_string_literal: true

# This Jekyll plugin generates a combined document with all content
module Jekyll
  # This generator creates a full documentation file for LLMs
  class GenerateLLMsFullFile < Jekyll::Generator
    safe true
    priority :high

    def generate(site)
      # Target file path
      output_path = File.join(site.dest, 'llms-full.txt')

      # Prepare content
      content = "# Dalfox Full Documentation\n\n"
      content += "> This file contains the combined content of all Dalfox documentation pages for LLM context\n\n"

      # Add content from regular pages
      site.pages.each do |page|
        # Skip non-markdown files, index pages, and the llms.txt itself
        next if page.path.match?(/\.(xml|json|html|txt|js|css|scss|yaml|yml)$/)
        next if page.name == 'index.html'
        next if page.name == 'llms.txt'
        next if page.name == 'llms-full.txt'

        # Extract content (skip front matter)
        next unless page.content && !page.content.empty?

        # Add page title as heading
        content += "\n## #{page.data['title'] || File.basename(page.path, '.*').capitalize}\n\n"
        # Add page content
        content += page.content.strip
        content += "\n\n---\n\n"
      end

      # Add content from collections
      site.collections.each do |collection_name, collection|
        # Skip certain collections if needed
        next if ['posts'].include?(collection_name)

        collection.docs.each do |doc|
          # Skip certain files
          next if doc.path.match?(/\.(xml|json|html|txt|js|css|scss|yaml|yml)$/)

          next unless doc.content && !doc.content.empty?

          # Add document title as heading
          content += "\n## #{doc.data['title'] || File.basename(doc.path, '.*').capitalize} (#{collection_name})\n\n"
          # Add document content
          content += doc.content.strip
          content += "\n\n---\n\n"
        end
      end

      # Create the directory if it doesn't exist
      FileUtils.mkdir_p(File.dirname(output_path))

      # Write the content to the file in source directory so it gets committed
      source_path = File.join(site.source, 'llms-full.txt')
      File.write(source_path, content)

      # Ensure the file is in the destination directory
      begin
        FileUtils.cp(source_path, output_path)
      rescue StandardError => e
        Jekyll.logger.error "Error copying llms-full.txt: #{e.message}"
      end

      Jekyll.logger.info 'Generated:', 'llms-full.txt'
    end
  end

  # Also add a post-write hook to ensure the file exists in the _site directory
  class LLMsFullHook
    def self.register
      Jekyll::Hooks.register :site, :post_write do |site|
        source_path = File.join(site.source, 'llms-full.txt')
        output_path = File.join(site.dest, 'llms-full.txt')

        if File.exist?(source_path)
          FileUtils.mv(source_path, output_path)
          Jekyll.logger.info 'Moved to _site directory:', 'llms-full.txt'
        else
          Jekyll.logger.warn 'Cannot find source file:', 'llms-full.txt'
        end
      end
    end
  end

  LLMsFullHook.register
end
