# frozen_string_literal: true

namespace :docs do
  desc 'Serve the documentation site'
  task :serve do
    within_docs_directory do
      unless system('bundle check')
        puts "Bundler is not installed or dependencies are not met. Please run 'rake docs:install'."
        exit 1
      end

      sh 'bundle exec jekyll s'
    end
  end

  desc 'Install dependencies for the documentation site'
  task :install do
    within_docs_directory do
      sh 'bundle install'
    end
  end

  def within_docs_directory(&block)
    Dir.chdir('docs', &block)
  rescue Errno::ENOENT => e
    puts "Directory 'docs' not found: #{e.message}"
    exit 1
  rescue StandardError => e
    puts "An error occurred: #{e.message}"
    exit 1
  end
end

namespace :test do
  desc 'Set up the test environment'
  task :setup do
    sh 'gem install rspec aruba'
  end

  desc 'Run the functional tests'
  task :functional do
    sh 'rspec'
  end

  desc 'Run the unit tests'
  task :unit do
    sh 'go test ./...'
  end

  desc 'Run all tests'
  task :all do
    Rake::Task['test:functional'].invoke
    Rake::Task['test:unit'].invoke
  end
end
