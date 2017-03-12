require 'ipaddress'

module BotDetector
  class PerimeterX
    module API
      class RiskResponseError < StandardError
        attr_reader :json_response
        attr_reader :inner_exception

        def initialize(json_response, inner_exception = nil)
          @json_response = json_response
          @inner_exception = inner_exception
        end
      end

      class RiskResponseStatusError < StandardError
        attr_reader :returned_status

        def initialize(returned_status)
          @returned_status = returned_status
        end
      end

      class BaseRequest
        def to_s
          request_body.to_s
        end

        def query_perimeterx
          BotDetector::PerimeterX.post(perimeterx_route, request_body, { 'headers' => auth_headers } )
        end

        def run
          raise RuntimeError.new("#{__method__} should not be accessed for #{self.class}")
        end

        protected

        def request_body
          {}
        end

        def perimeterx_route
          raise RuntimeError.new("#{__method__} should not be accessed for #{self.class}")
        end

        private

        def auth_headers
          { "Authorization" => "Bearer #{ BotDetector::PerimeterX.perimeterx_token}" }
        end
      end

      class BaseRiskRequest < BaseRequest
        #
        # The IP address of the requesting browser
        attr_reader :ip

        #
        # The header information of the request
        attr_reader :headers

        #
        # The URI of the requesting browser
        attr_reader :uri

        #
        # The full URL with protocol and path
        attr_reader :url

        def initialize(ip, url, headers)
          self.ip      = ip
          self.headers = sanitize_headers(headers)
          self.url     = url
        end

        def uri=(value)
          raise ArgumentError.new("#{__method__}: invalid uri (#{value}). Must be String") unless value.nil? || value.is_a?(String)
          @uri = value
        end

        protected

        def request_body
          super.deep_merge( { request: { ip: ip, uri: uri, url: url, headers: headers } } )
        end

        private

        def ip=(value)
          raise ArgumentError.new("#{__method__}: Invalid IP (#{value})") unless IPAddress.valid?(value)
          @ip = value
        end

        def url=(value)
          raise ArgumentError.new("#{__method__}: invalid px_cookie (#{value}). Must be String") unless value.is_a?(String)
          @url = value
        end

        def headers=(value)
          raise ArgumentError.new("#{__method__}: Invalid header format (#{value.class} instead of Array") unless value.is_a?(Array)
          raise ArgumentError.new("#{__method__}: Invalid header format (array's items are not all pairs of keys and values)") unless value.all? { |header| header.is_a?(Hash) && header.has_key?(:name) && header.has_key?(:value) }
          @headers = value
        end

        def sanitize_headers(headers)
          headers.map { |header| { name: header[:name], value: header[:value] } }
        end
      end

      class RiskRequest < BaseRiskRequest
        CUSTOM_PARAM_MIN =  1
        CUSTOM_PARAM_MAX = 10

        S2sCallReasons = %w(none expired_cookie no_cookie cookie_decryption_failed cookie_verification_failed)
        HttpMethods    = %w(POST GET PUT DELETE OPTIONS HEAD TRACE CONNECT UNKNOWN PATCH)
        HttpVersions   = %w(1.0 1.1 2.0)

        #
        # This field provides the reason for calling the API.
        # Possible values are
        # expired_cookie             - The PerimeterX risk cookie is expired.
        # no_cookie                  - The PerimeterX risk cookie is not present.
        # cookie_decryption_failed   - Failed to decrypt the PerimeterX cookie.
        # cookie_verification_failed - The PerimeterX risk cookie has an invalid HMAC signature.
        # none                       - No specific reason
        attr_reader :s2s_call_reason

        #
        # PerimeterX visitor ID. It can be obtained from the risk cookie on field "v"
        attr_reader :vid

        #
        # Value of the PerimeterX cookie, should be send when cookie exists but invalid
        attr_reader :px_cookie

        #
        # The incoming request method
        # Possible values are: GET, POST, PUT, DELETE, OPTIONS, HEAD, TRACE, CONNECT, UNKNOWN
        attr_reader :http_method

        #
        # The http version used by the client who made the request
        # Possible values are: 1.0, 1.1, 2.0
        attr_reader :http_version

        #
        # Any custom parameter can be passed (user id/campaign id/app id/etc)
        attr_accessor :custom_params

        def initialize(ip, url, headers)
          super(ip, url, headers)
          @custom_params = []
        end

        def s2s_call_reason=(value)
          raise ArgumentError.new("#{__method__}: invalid s2s_call_reason (#{value}). Options are #{S2sCallReasons.join('/')}") unless value.nil? || S2sCallReasons.include?(value.to_s.downcase)
          @s2s_call_reason = value.nil? ? nil : value.to_s.downcase
        end

        def vid=(value)
          raise ArgumentError.new("#{__method__}: invalid vid (#{value}). Must be a String") unless value.nil? || value.is_a?(String)
          @vid = value
        end

        def px_cookie=(value)
          raise ArgumentError.new("#{__method__}: invalid px_cookie (#{value}). Must be String") unless value.nil? || value.is_a?(String)
          @px_cookie = value
        end

        def http_method=(value)
          raise ArgumentError.new("#{__method__}: invalid http_method (#{value}). Options are #{HttpMethods.join('/')}") unless value.nil? || HttpMethods.include?(value.to_s.upcase)
          @http_method = value.nil? ? nil : value.to_s.upcase
        end

        def http_version=(value)
          raise ArgumentError.new("#{__method__}: invalid http_version (#{value}). Options are #{HttpVersions.join('/')}") unless value.nil? || HttpVersions.include?(value.to_s.downcase)
          @http_version = value.nil? ? nil : value.to_s.downcase
        end

        def run
          RiskResponse.new(query_perimeterx)
        end

        protected

        def perimeterx_route
          'risk'
        end

        def request_body
          result = { additional: request_body_additional }
          result[:vid] = vid unless vid.nil?
          super.deep_merge(result)
        end

        private

        def request_body_additional
          additional = {}
          additional[:s2s_call_reason] = s2s_call_reason.to_s unless s2s_call_reason.nil?
          additional[:px_cookie      ] = px_cookie            unless px_cookie.nil?
          additional[:http_version   ] = http_version         unless http_version.nil?
          additional[:http_method    ] = http_method.to_s     unless http_method.nil?
          (CUSTOM_PARAM_MIN..CUSTOM_PARAM_MAX).each { |i| additional["custom_param#{i}".to_sym] = custom_params[i - CUSTOM_PARAM_MIN] unless custom_params[i - CUSTOM_PARAM_MIN].nil? }
          additional
        end
      end

      class RiskResetRequest < BaseRiskRequest
        ResetReasons = %w(captcha_solved customer_support other)

        #
        # PerimeterX visitor ID. It can be obtained from the risk cookie on field "v". Sending the VID will clear the visitor's bad score.
        attr_reader :vid

        #
        # The reason for calling the reset api:
        # :captcha_solved - reset_api
        # :customer_support other
        attr_reader :reset_reason

        def initialize(ip, url, headers, reset_reason)
          super(ip, url, headers)
          self.reset_reason = reset_reason
        end

        def vid=(value)
          raise ArgumentError.new("#{__method__}: invalid vid (#{value}). Must be a String") unless value.nil? || value.is_a?(String)
          @vid = value
        end

        def run
          RiskResetResponse.new(query_perimeterx)
        end

        protected

        def perimeterx_route
          'risk/reset'
        end

        def request_body
          result = { additional: request_body_additional }
          result[:vid] = vid unless vid.nil?
          super.deep_merge(result)
        end

        private

        def reset_reason=(value)
          raise ArgumentError.new("#{__method__}: invalid reset_reason (#{value}). Options are #{ResetReasons.join('/')}") unless ResetReasons.include?(value.to_s.downcase)
          @reset_reason = value.to_s.downcase
        end

        def request_body_additional
          additional = {}
          additional[:reset_reason] = reset_reason.to_s unless reset_reason.nil?
          additional
        end
      end

      class RiskResetReqRequest < BaseRequest
        #
        # A unique request id for the reset operation
        attr_reader :uuid

        #
        # The period of time, in seconds, to clear the visitor
        attr_reader :period

        def initialize(uuid, period)
          self.uuid   = uuid
          self.period = period
        end

        def run
          RiskResetReqResponse.new(query_perimeterx)
        end

        protected

        def perimeterx_route
          'risk/reset/req_id'
        end

        def request_body
          super.deep_merge( { request: { uuid: uuid, period: period } } )
        end

        private

        def uuid=(value)
          raise ArgumentError.new("#{__method__}: invalid uuid (#{value}). Must be String") unless value.is_a?(String)
          @uuid = value.to_s.downcase
        end

        def period=(value)
          raise ArgumentError.new("#{__method__}: invalid period (#{value}). Must be Fixnum") unless value.is_a?(Fixnum)
          @period = value
        end
      end

      class RiskResetVisitorRequest < BaseRequest
        #
        # The period of time, in seconds, to clear the visitor
        attr_reader :vid, :period

        def initialize(vid, period)
          self.vid    = vid
          self.period = period
        end

        def run
          RiskResetVisitorResponse.new(query_perimeterx)
        end

        protected

        def perimeterx_route
          'risk/reset/visitor_id'
        end

        def request_body
          super.deep_merge( { request: { vid: vid, period: period } } )
        end

        private

        def vid=(value)
          raise ArgumentError.new("#{__method__}: invalid vid (#{value}). Must be String") unless value.is_a?(String)
          @vid = value.to_s.downcase
        end

        def period=(value)
          raise ArgumentError.new("#{__method__}: invalid period (#{value}). Must be Fixnum") unless value.is_a?(Fixnum)
          @period = value
        end
      end

      class BaseResponse
        def initialize(json_response)
          parse_options!(json_response)
        rescue => e
          raise RiskResponseError.new(json_response, e)
        end

        private

        def parse_options!(options)
          options.each { |k, v| self.send("#{k}=", v)}
        end

        # This does not set anything but rather called by parse_options! and validates that the status is okay
        def status=(value)
          raise RiskResponseStatusError.new(value) unless value == 0
        end
      end

      class RiskResponse < BaseResponse
        attr_reader :uuid, :score, :action

        def initialize(json_response)
          super(json_response)
        end

        private

        ACTION_MAPPING = {
          'b' => BotDetector::PerimeterX::Actions::Block,
          'c' => BotDetector::PerimeterX::Actions::Captcha
        }

        def action=(value)
          action = ACTION_MAPPING[value]
          raise ArgumentError.new("#{__method__}: action (#{action}) is invalid") if action.nil?
          @action = action
        end

        def score=(value)
          raise ArgumentError.new("#{__method__}: score (#{value}) is invalid") unless value.is_a?(Fixnum) && value.between?(0, 100)
          @score = value
        end

        def uuid=(value)
          raise ArgumentError.new("#{__method__}: uuid (#{value}) is invalid") unless value.is_a?(String)
          @uuid = value
        end
      end

      class RiskResetResponse < BaseResponse
        attr_reader :uuid, :vid, :cid

        def initialize(json_response)
          super(json_response)
        end

        def cid=(value)
          raise ArgumentError.new("#{__method__}: cid (#{value}) is invalid") unless value.is_a?(String)
          @cid = value
        end

        def vid=(value)
          raise ArgumentError.new("#{__method__}: vid (#{value}) is invalid") unless value.is_a?(String)
          @vid = value
        end

        def uuid=(value)
          raise ArgumentError.new("#{__method__}: uuid (#{value}) is invalid") unless value.is_a?(String)
          @uuid = value
        end
      end

      class RiskResetReqResponse < BaseResponse
        def initialize(json_response)
          super(json_response)
        end
      end

      class RiskResetVisitorResponse < BaseResponse
        def initialize(json_response)
          super(json_response)
        end
      end
    end
  end
end
