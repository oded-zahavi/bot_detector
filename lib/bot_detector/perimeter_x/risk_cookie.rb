module BotDetector
  class PerimeterX
    class RiskCookie
      module Status
        CookieOkay               = :none
        ExpiredCookie            = :expired_cookie
        NoCookie                 = :no_cookie
        CookieDecryptionFailed   = :cookie_decryption_failed
        CookieVerificationFailed = :cookie_verification_failed
      end

      class RiskCookieError < StandardError
        attr_reader :status

        def initialize(status)
          @status = status
        end
      end

      class RiskScore
        attr_reader :app
        attr_reader :bot

        def initialize(app, bot)
          @app = app.to_i
          @bot = bot.to_i
        end

        def to_h
          { app: app, bot: bot }
        end
      end

      attr_reader :status
      attr_reader :score
      attr_reader :uuid
      attr_reader :vid

      def initialize(ip, user_agent, encrypted_cookie)
        raise RiskCookieError.new(Status::NoCookie) if encrypted_cookie.nil?

        @status           = Status::CookieOkay
        decrypted_cookie = decrypt(encrypted_cookie)
        @px_cookie = encrypted_cookie
        @timestamp = decrypted_cookie['t']
        @score     = RiskScore.new(decrypted_cookie['s']['a'], decrypted_cookie['s']['b'])
        @uuid      = decrypted_cookie['u']
        @vid       = decrypted_cookie['v']
        validate_cookie(user_agent, decrypted_cookie['h'])

      rescue RiskCookieError => e
        @status = e.status
      rescue => e
        Rails.logger.error {"Unexpected #{e.message} (ip: #{ip}, ua: #{user_agent})"}
      end

      def exists?
        @status != Status::NoCookie
      end

      def valid?
        @status == Status::CookieOkay
      end

      def use_cookie?
        valid? && score.bot < BotDetector::PerimeterX.score_threshold
      end

      def timestamp
        Time.at(@timestamp / 1000)
      end

      def to_h
        valid? ? { status: status, score: score.to_h, uuid: uuid, vid: vid, timestamp: timestamp } : { status: status }
      end

      def query(request, env, headers)
        RiskQuery.new(request, env, headers, status, use_cookie?, @px_cookie)
      end

      def reset(request, headers)
        # TODO: Send to rabbit and handle offline
        RiskReset.new(request, headers, vid)
      end

      def action
        return Actions::None if use_cookie?

        Actions::Query
      end

      private

      def validate_cookie(user_agent, hash)
        msg = [ @timestamp, score.app, score.bot, uuid, vid, user_agent ].join
        calculated_digest = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, BotDetector::PerimeterX.secret_key, msg)
        raise RiskCookieError.new(Status::CookieVerificationFailed) unless hash == calculated_digest.to_s
        raise RiskCookieError.new(Status::ExpiredCookie) if expired?
      end

      def expired?
        timestamp < Time.now.utc
      end

      def decrypt(px_cookie)
        return if px_cookie.nil?

        px_cookie = px_cookie.gsub(' ', '+')
        salt, iterations, cipher_text = px_cookie.split(':')
        iterations = iterations.to_i
        salt = Base64.decode64(salt)
        cipher_text = Base64.decode64(cipher_text)
        digest = OpenSSL::Digest::SHA256.new
        value = OpenSSL::PKCS5.pbkdf2_hmac(BotDetector::PerimeterX.secret_key, salt, iterations, 48, digest)
        key = value[0..31]
        iv = value[32..-1]
        cipher = OpenSSL::Cipher::AES256.new(:CBC)
        cipher.decrypt
        cipher.key = key
        cipher.iv = iv
        plaintext = cipher.update(cipher_text) + cipher.final
        Oj.load(plaintext)
      rescue
        raise RiskCookieError.new(Status::CookieDecryptionFailed)
      end
    end
  end
end
