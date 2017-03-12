module BotDetector
  class PerimeterX
    class RiskReset
      module ResetReasons
        CaptchaSolved   = :captcha_solved
        CustomerSupport = :customer_support
        Other           = :other
      end

      attr_reader :uuid

      def initialize(request, headers, vid)
        risk_request = API::RiskResetRequest.new(request.remote_ip, request.url, headers, ResetReasons::CaptchaSolved)
        risk_request.uri = request.path
        risk_request.vid = vid
        risk_response = risk_request.run
        @uuid = risk_response.uuid
      end
    end
  end
end
