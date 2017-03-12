module BotDetector
  class PerimeterX
    class Config
      attr_accessor :perimeterx_app_id
      attr_accessor :perimeterx_secret
      attr_accessor :perimeterx_cookie_name
      attr_accessor :perimeterx_token

      def initialize(&config)
        self.instance_eval(&config) unless config.nil?
      end

      def time_measure_method(&block)
        @time_measure = block if block_given?
        @time_measure
      end

      def post_method(&block)
        @post_method = block if block_given?
        @post_method
      end

      def log_error_method(&block)
        @log_error_method = block if block_given?
        @log_error_method
      end

      def score_threshold_method(&block)
        @score_threshold_method = block if block_given?
        @score_threshold_method
      end

      def enabler_method(&block)
        @enabler_method = block if block_given?
        @enabler_method
      end
    end

    attr_reader :cookie_info
    attr_reader :xquery_info
    attr_reader :xreset_info

    @@settings = nil

    def initialize(request, env, headers, cookies)
      raise ArgumentError if request.nil?

      encrypted_cookie = (cookies || {})[BotDetector::PerimeterX.cookie_name]
      @cookie_info = RiskCookie.new(request.remote_ip, request.user_agent, encrypted_cookie)
      BotDetector::PerimeterX.time_measure('bot_detection.xquery') do
        @xquery_info = @cookie_info.query(request, env, headers)
      end
    end

    def self.configure(&config)
      @@config = Config.new(&config) unless config.nil?
      @@config
    end

    def self.time_measure(name, &block)
      @@config.time_measure_method.call(name, &block) unless @@config.time_measure_method.nil?
    end

    def self.post(perimeterx_route, request_body, auth_headers)
      @@config.post_method.call(perimeterx_route, request_body, auth_headers) unless @@config.post_method.nil?
    end

    def self.log_error(klass, message, exception = nil)
      @@config.log_error_method.call(klass, message, exception) unless @@config.log_error_method.nil?
    end

    def self.score_threshold
      @@config.score_threshold_method.call
    end

    def self.enabled?
      @@config.enabler_method.call
    end

    def self.app_id
      @@config.perimeterx_app_id
    end

    def self.secret_key
      @@config.perimeterx_secret
    end

    def self.cookie_name
      @@config.perimeterx_cookie_name
    end

    def self.perimeterx_token
      @@config.perimeterx_token
    end

    def self.delete_cookie!(cookies)
      cookies.delete(self.cookie_name)
    end

    def to_h
      { action: action.to_s, cookie_info: cookie_info.to_h, xquery_info: xquery_info.to_h }
    end

    def reset(request, headers)
      @xreset_info = cookie_info.reset(request, headers)
    end

    def exec_action(&block)
      klass = Kernel.eval('self', block.binding)
      action.run(klass, ActionCallback.new(&block))
    end

    private

    def action
      return cookie_info.action unless xquery_info.action.present?

      xquery_info.action
    end
  end
end
