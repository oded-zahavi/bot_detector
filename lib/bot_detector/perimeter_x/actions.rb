module BotDetector
  class PerimeterX
    module Actions
      class None
        def self.to_s
          'none'
        end

        def self.run(klass, action)
          klass.instance_eval(&action.none) unless action.none.nil?
        end
      end

      class Query
        def self.to_s
          'query'
        end

        def self.run(klass, action)
          raise RuntimeError.new("#{__method__}: invalid action (Query)")
        end
      end

      class Block
        def self.to_s
          'block'
        end

        def self.run(klass, action)
          klass.instance_eval(&action.block) unless action.block.nil?
        end
      end

      class Captcha
        def self.to_s
          'captcha'
        end

        def self.run(klass, action)
          klass.instance_eval(&action.captcha) unless action.captcha.nil?
        end
      end
    end
  end
end
