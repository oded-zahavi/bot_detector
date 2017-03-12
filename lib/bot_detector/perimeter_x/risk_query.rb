module BotDetector
  class PerimeterX
    class RiskQuery
      attr_reader :score, :uuid, :action

      def initialize(request, env, headers, status, use_cookie, px_cookie = nil)
        if use_cookie
          @valid = false
        else
          @valid, @score, @uuid, @action = query(request, env, headers, status, px_cookie)
        end
      end

      def valid?
        @valid
      end

      def query(request, env, headers, status, px_cookie)
        valid  = false
        score  = nil
        uuid   = nil
        action = Actions::None

        begin
          risk_request = API::RiskRequest.new(request.remote_ip, request.url, headers)
          risk_request.uri             = request.path
          risk_request.s2s_call_reason = status
          risk_request.px_cookie       = px_cookie if px_cookie.present?
          risk_request.http_method     = request.method
          risk_request.http_version    = env['HTTP_VERSION'].gsub('HTTP/', '')
          risk_response = risk_request.run
          score  = risk_response.score
          uuid   = risk_response.uuid
          action = risk_response.action if risk_response.score >= BotDetector::PerimeterX.score_threshold
          valid  = true
        rescue API::RiskResponseError => e
          BotDetector::PerimeterX.log_error("BotDetector::PerimeterX", "Error Accessing PerimeterX API (request: #{risk_request}, response: #{e.json_response})", e)
        end

        [valid, score, uuid, action]
      end

      def to_h
        valid? ? { valid: true, uuid: uuid, score: score, action: action.to_s } : { valid: false }
      end
    end
  end
end
