# frozen_string_literal: true

# Ruby SDK for SecretSpec, a declarative secrets manager.
#
# A thin client over the secretspec-ffi C ABI, loaded at runtime via the stdlib
# Fiddle (dlopen, no native gem). Resolution happens entirely in the Rust core,
# so the SDK inherits every provider with no Ruby-side logic. Mirrors the Rust
# derive crate's vocabulary.
#
# The native library is located via SECRETSPEC_FFI_LIB, or a Cargo target
# directory found by searching up from the working directory.

require "fiddle"
require "json"
require "rbconfig"

module Secretspec
  # A resolution failure (bad manifest, provider error, reason policy).
  class Error < StandardError
    attr_reader :kind

    def initialize(kind, message)
      @kind = kind
      super("#{message} (kind: #{kind})")
    end
  end

  # One or more required secrets were not found anywhere.
  class MissingRequiredError < Error
    attr_reader :missing

    def initialize(missing)
      @missing = missing
      super("missing_required", "missing required secret(s): #{missing.join(', ')}")
    end
  end

  # One resolved secret. Exactly one of +value+ / +path+ is set.
  ResolvedSecret = Struct.new(:value, :path, :as_path, :source, :source_provider) do
    # The usable string: the file path for as_path secrets, else the value.
    def get
      as_path ? path : value
    end
  end

  # A successful resolution, mirroring the Rust Resolved wrapper.
  Resolved = Struct.new(:provider, :profile, :secrets, :missing_optional) do
    # Export each resolved secret into ENV by its declared name.
    def set_as_env!
      secrets.each { |name, secret| ENV[name] = secret.get }
    end

    # Flat { "SECRET_NAME" => value } hash (the file path for as_path). Feed this
    # to a quicktype-generated deserializer (e.g. from_dynamic!). See
    # `secretspec schema`.
    def fields
      secrets.transform_values(&:get)
    end
  end

  # The narrow C ABI, loaded lazily via Fiddle.
  module Native
    class << self
      def resolve(request_json)
        ensure_loaded
        ptr = @resolve.call(request_json)
        raise Error.new("ffi", "secretspec_resolve returned null") if ptr.null?

        begin
          ptr.to_s
        ensure
          @free.call(ptr)
        end
      end

      def abi_version
        ensure_loaded
        @abi.call.to_s
      end

      private

      def ensure_loaded
        return if @loaded

        handle = Fiddle.dlopen(find_library)
        @resolve = Fiddle::Function.new(
          handle["secretspec_resolve"], [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOIDP
        )
        @free = Fiddle::Function.new(
          handle["secretspec_free"], [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOID
        )
        @abi = Fiddle::Function.new(
          handle["secretspec_abi_version"], [], Fiddle::TYPE_VOIDP
        )
        @loaded = true
      end

      def lib_names
        case RbConfig::CONFIG["host_os"]
        when /darwin/ then ["libsecretspec_ffi.dylib"]
        when /mswin|mingw/ then ["secretspec_ffi.dll"]
        else ["libsecretspec_ffi.so"]
        end
      end

      def find_library
        env = ENV["SECRETSPEC_FFI_LIB"]
        return env if env && !env.empty?

        dir = Dir.pwd
        loop do
          %w[release debug].each do |profile|
            lib_names.each do |name|
              candidate = File.join(dir, "target", profile, name)
              return candidate if File.exist?(candidate)
            end
          end
          parent = File.dirname(dir)
          break if parent == dir

          dir = parent
        end
        raise Error.new("load",
                        "could not locate the secretspec-ffi library; set SECRETSPEC_FFI_LIB")
      end
    end
  end

  # Entry point mirroring the derive crate's SecretSpec::builder().
  class SecretSpec
    def self.builder
      Builder.new
    end
  end

  # Fluent builder for a resolution.
  class Builder
    def initialize
      @request = {}
    end

    def with_path(path)
      @request["path"] = path if path
      self
    end

    def with_provider(provider)
      @request["provider"] = provider if provider
      self
    end

    def with_profile(profile)
      @request["profile"] = profile if profile
      self
    end

    def with_reason(reason)
      @request["reason"] = reason if reason
      self
    end

    # Resolve the secrets. Raises MissingRequiredError if a required secret is
    # missing, and Error for any other failure.
    def load
      envelope = JSON.parse(Native.resolve(JSON.generate(@request)))

      unless envelope["ok"]
        err = envelope["error"] || {}
        raise Error.new(err["kind"] || "unknown", err["message"] || "")
      end

      response = envelope["response"]
      missing = response["missing_required"] || []
      raise MissingRequiredError.new(missing) unless missing.empty?

      secrets = {}
      (response["secrets"] || {}).each do |name, entry|
        secrets[name] = ResolvedSecret.new(
          entry["value"], entry["path"], entry["as_path"] || false,
          entry["source"], entry["source_provider"]
        )
      end

      Resolved.new(
        response["provider"], response["profile"], secrets,
        response["missing_optional"] || []
      )
    end
  end

  def self.abi_version
    Native.abi_version
  end
end
