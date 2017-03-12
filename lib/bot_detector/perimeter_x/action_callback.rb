module BotDetector
  class PerimeterX
    class ActionCallback
      def initialize(&block)
        self.instance_eval(&block)
      end

      def captcha(&block)
        @captcha = block if block_given?
        @captcha
      end

      def block(&block)
        @block = block if block_given?
        @block
      end

      def none(&block)
        @none = block if block_given?
        @none
      end
    end
  end
end

