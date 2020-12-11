# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'bot_detector/version'

Gem::Specification.new do |spec|
  spec.name          = 'bot_detector'
  spec.version       = BotDetector::VERSION
  spec.authors       = ['Oded Zahavi']
  spec.email         = ['oded.z@fiverr.com']
  spec.description   = %q{This gem wraps perimeterx restful api to provide it with a ruby interface }
  spec.summary       = %q{This gem wraps perimeterx restful api to provide it with a ruby interface }
  spec.homepage      = 'https://github.com/oded-zahavi/bot_detector'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 2.2'
  spec.add_development_dependency 'rake'
end
