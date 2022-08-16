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
    @jwt = {}
    @minutes = 20 * 60
    @update_time = Time.now.to_i + @minutes
    @acc_name = ""
  end

  def registerExtenderCallbacks(callbacks)
    @callbacks = callbacks
    @helpers = callbacks.getHelpers
    callbacks.setExtensionName("jwt_fetcher")
    callbacks.registerHttpListener self
  end

  def fetch_jwt
    @is_subrequest = true
    @requests = Dir["./requests/*"].map {|r| r = File.basename(r, ".*")}

    begin
      request_file = @requests.find {|r| r == @acc_name}
      request_file = File.read("requests/#{request_file}.txt").split("\n")

      host = request_file.find {|h| h.match "^Host:.*$"}.split(" ")[-1]
      port = 443
      message = @helpers.buildHttpMessage(request_file, nil)

      if !request_file
        puts "request_file is empty"
        return
      end

      response = @callbacks.makeHttpRequest(host, port, true, message)

      _jwt = /\r\n\r\n(.*)/.match @helpers.bytesToString(response)

      if !_jwt
        puts "No response body found"
        return
      end
      @jwt[@acc_name][:token] = _jwt[1]
    end
  end

  def processHttpMessage(toolFlag, messageIsRequest, message)
    return if !messageIsRequest
    return if @is_subrequest

    @message = message
    @acc_name = (/^Acc: (.+?)\r\n/.match @helpers.bytesToString(@message.getRequest))[1]
    @jwt[@acc_name] ||= {}

    if @acc_name
      @jwt[@acc_name][:update_time] = Time.now.to_i + @minutes if !@jwt[@acc_name].key? :update_time

      if (Time.now.to_i >= @jwt[@acc_name][:update_time]) || (!@jwt[@acc_name].key? :token)
        fetch_jwt 
        @is_subrequest = false
      end

      req = @helpers.analyzeRequest(message.getRequest)
      body_offset = req.getBodyOffset
      body = message.getRequest()[body_offset..-1]
      
      headers = req.getHeaders
      headers = headers.filter {|r| !r.match?(/^Authorization:.*$/)}
        .push("Authorization: Bearer #{@jwt[@acc_name][:token]}")

      final_req = @helpers.buildHttpMessage(headers, body)
      message.setRequest(final_req) 
    else
      return
    end
  end
end
