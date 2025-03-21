# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'testphp.vulnweb.com', type: :aruba do
  before(:all) do
    @binary_path = File.expand_path('../../../dalfox', __dir__)
  end

  it 'listproducts.php - cat param' do
    run_command("#{@binary_path} url 'http://testphp.vulnweb.com/listproducts.php?cat='")
    expect(last_command_started).to have_output(/\\[V\\]/)
    expect(last_command_started).to be_successfully_executed
  end

  it 'listproducts.php - artist param' do
    run_command("#{@binary_path} url 'http://testphp.vulnweb.com/listproducts.php?artist='")
    expect(last_command_started).to have_output(/\\[V\\]/)
    expect(last_command_started).to be_successfully_executed
  end

  it 'hpp - pp param' do
    run_command("#{@binary_path} url 'http://testphp.vulnweb.com/hpp/?pp='")
    expect(last_command_started).to have_output(/\\[V\\]/)
    expect(last_command_started).to be_successfully_executed
  end

  it 'params.php - p param' do
    run_command("#{@binary_path} url 'http://testphp.vulnweb.com/hpp/params.php?p='")
    expect(last_command_started).to have_output(/\\[V\\]/)
    expect(last_command_started).to be_successfully_executed
  end

  it 'search.php - searchFor body param' do
    run_command("#{@binary_path} url 'http://testphp.vulnweb.com/search.php' -d 'searchFor=' -X POST")
    expect(last_command_started).to have_output(/\\[V\\]/)
    expect(last_command_started).to be_successfully_executed
  end

  it 'guestbook.php - name body param' do
    run_command("#{@binary_path} url 'http://testphp.vulnweb.com/guestbook.php' -d 'name=' -X POST")
    expect(last_command_started).to have_output(/\\[V\\]/)
    expect(last_command_started).to be_successfully_executed
  end
end
