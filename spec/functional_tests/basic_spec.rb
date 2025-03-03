# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Basic Run', type: :aruba do
  before(:all) do
    @binary_path = File.expand_path('../../dalfox', __dir__)
  end

  it 'prints the help' do
    run_command("#{@binary_path} -h")
    expect(last_command_started).to have_output(/Usage:/)
    expect(last_command_started).to be_successfully_executed
  end

  it 'prints the help url mode' do
    run_command("#{@binary_path} help url")
    expect(last_command_started).to have_output(/Usage:/)
    expect(last_command_started).to be_successfully_executed
  end

  it 'returns an error for unknown commands' do
    run_command("#{@binary_path} invalid-command")
    expect(last_command_started).to have_output(/unknown command/i)
    expect(last_command_started).not_to be_successfully_executed
  end
end
