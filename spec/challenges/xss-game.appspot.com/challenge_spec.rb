# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'xss-game.appspot.com', type: :aruba do
  before(:all) do
    @binary_path = File.expand_path('../../../dalfox', __dir__)
  end

  it 'level1' do
    run_command("#{@binary_path} url 'https://xss-game.appspot.com/level1/frame?query=a'")
    expect(last_command_started).to have_output(/\[V\]/)
    expect(last_command_started).to be_successfully_executed
  end

  it 'level2' do
    # DOM Based XSS - Currently not detected
  end

  it 'level3' do
    # Fragment Based XSS - Currently not detected
  end
end