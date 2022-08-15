require 'java'
require 'time'
require 'securerandom'
java_import 'burp.IBurpExtender'
java_import 'burp.IHttpListener'

class BurpExtender
  include IBurpExtender
  include IHttpListener

  def initialize
    @message= ""
    @requests = Dir["./requests/*"].map {|r| r = File.basename(r, ".*")}
    @is_subrequest = false
    @jwt = ""
    @update_time = 0
  end

  def registerExtenderCallbacks(callbacks)
    @callbacks = callbacks
    @helpers = callbacks.getHelpers
    callbacks.setExtensionName("jwt_fetcher")
    callbacks.registerHttpListener self
  end

  def fetch_jwt
    return if Time.now.to_i < @update_time
    @is_subrequest = true

    name = /^Acc: (.+?)\r\n/.match @helpers.bytesToString(@message.getRequest)

    if !name
      puts "no Acc header found in request"
      return
    end

    begin
      request_file = @requests.find {|r| r == name[1]}
      request_file = File.read("requests/#{request_file}.txt").split("\n")

      host = request_file.find {|h| h.match "^Host:.*$"}.split(" ")[-1]
      port = 443
      message = @helpers.buildHttpMessage(request_file, nil)

      if !request_file
        puts "request_file is empty"
        return
      end

      response = @callbacks.makeHttpRequest(host, port, true, message)

      jwt = /\r\n\r\n(.*)/.match @helpers.bytesToString(response)

      if !jwt
        puts "No response body found"
        return
      end
      @jwt = jwt[1]
    end
  end

  def processHttpMessage(toolFlag, messageIsRequest, message)
    return if !messageIsRequest
    return if @is_subrequest
    @message = message

    fetch_jwt
    @is_subrequest = false

    req = @helpers.analyzeRequest(message.getRequest)
    headers = req.getHeaders
    headers = headers.filter {|r| !r.match?(/^Authorization:.*$/)}.push("Authorization: Bearer #{@jwt}")

    final_req = @helpers.buildHttpMessage(headers, nil)
    message.setRequest(final_req) 

    minutes = 20 * 60
    @update_time = Time.now.to_i + minutes.to_i
  end
end
