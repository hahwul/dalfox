require 'net/http'
require 'json'

def check(endpoint)
    url = URI("https://assets.hahwul.com/#{endpoint}.json")
    response = Net::HTTP.get(url)

    data = JSON.parse(response)
    puts data
end

endpoints = [
    'xss-portswigger',
    'xss-payloadbox',
    'wl-params',
    'wl-assetnote-params'
]

endpoints.each do | target |
    check target
end
