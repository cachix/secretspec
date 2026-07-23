# frozen_string_literal: true

# Ruby SDK for SecretSpec, a declarative secrets manager.
#
# A thin client over the secretspec-ffi C ABI. The Rust resolver is statically
# linked into a native extension (secretspec_ext), so the SDK inherits every
# provider with no Ruby-side logic and there is nothing to locate at runtime.
# Mirrors the Rust derive crate's vocabulary.

require "json"

# The compiled extension lives next to this file in a source/dev checkout, but in
# an installed gem RubyGems places it in a separate extensions dir already on
# $LOAD_PATH. Put this file's dir on the path so the absolute require resolves in
# both layouts.
$LOAD_PATH.unshift(__dir__) unless $LOAD_PATH.include?(__dir__)
require "secretspec/secretspec_ext"

module Secretspec
  # Response wire-format version this SDK understands. Tracks secretspec-ffi's
  # RESOLVE_SCHEMA_VERSION; a mismatch means the loaded library is incompatible.
  RESOLVE_SCHEMA_VERSION = 2

  # Wire-format version of the value-free report. Tracks secretspec's
  # RESOLUTION_REPORT_SCHEMA_VERSION.
  REPORT_SCHEMA_VERSION = 1

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
  Resolved = Struct.new(:provider, :profile, :secrets, :missing_optional, :scope) do
    # Export each resolved secret into ENV by its declared name. Secrets with no
    # usable value (e.g. under no_values) are skipped rather than deleted from
    # ENV (assigning nil would remove the variable).
    def set_as_env!
      secrets.each do |name, secret|
        value = secret.get
        ENV[name] = value unless value.nil?
      end
    end

    # Flat { "SECRET_NAME" => value } hash (the file path for as_path). A secret
    # with no usable value (e.g. under no_values) maps to nil, matching the null
    # the other SDKs emit. Feed this to a quicktype-generated deserializer (e.g.
    # from_dynamic!). See `secretspec schema`.
    def fields
      secrets.transform_values(&:get)
    end

    # Remove the temp files backing any as_path secrets in this result. The
    # resolver persists those files (mode 0400) so their paths stay valid after
    # resolve returns; the caller owns their lifetime. Call #close (or pass a
    # block to Builder#load, which closes automatically) when done so secret
    # files do not accumulate in the temp dir. A file already gone is not an
    # error.
    def close
      secrets.each_value do |secret|
        next unless secret.as_path && secret.path

        File.delete(secret.path) if File.exist?(secret.path)
      end
      nil
    end
  end

  # Value-free resolution outcome for one declared secret: how it would resolve
  # and from where, never the value itself.
  SecretReport = Struct.new(:name, :status, :required, :source_provider,
                            :default_applied, :generated, :as_path)

  # A value-free resolution snapshot. Unlike Resolved, a missing required secret
  # is a "missing_required" status here, not an error, so a report describes a
  # profile even when its secrets are not all available.
  Report = Struct.new(:provider, :profile, :secrets, :scope)

  # The narrow C ABI, statically linked into the secretspec_ext extension. The
  # Native.c_resolve / c_abi_version C functions are defined in
  # ext/secretspec/secretspec_ext.c; these wrappers add the Ruby-side error type.
  module Native
    class << self
      def resolve(request_json)
        result = c_resolve(request_json)
        raise Error.new("ffi", "secretspec_resolve returned null") if result.nil?

        result
      end

      def abi_version
        c_abi_version
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

    # Limit resolution to a named manifest scope (SecretSpec 0.17+).
    def with_scope(scope)
      @request["scope"] = scope if scope
      self
    end

    def with_reason(reason)
      @request["reason"] = reason if reason
      self
    end

    # Omit secret values, returning only structure and provenance.
    def with_no_values(no_values = true)
      @request["no_values"] = no_values
      self
    end

    # Resolve the secrets. Raises MissingRequiredError if a required secret is
    # missing, and Error for any other failure.
    #
    # Without a block, returns the Resolved (the caller should #close it when
    # done to clean up any as_path temp files). With a block, yields the Resolved
    # and closes it afterwards, returning the block's value.
    def load
      response = parse_response(JSON.generate(@request), "resolve", RESOLVE_SCHEMA_VERSION)

      missing = response["missing_required"] || []
      raise MissingRequiredError.new(missing) unless missing.empty?

      secrets = {}
      (response["secrets"] || {}).each do |name, entry|
        secrets[name] = ResolvedSecret.new(
          entry["value"], entry["path"], entry["as_path"] || false,
          entry["source"], entry["source_provider"]
        )
      end

      resolved = Resolved.new(
        response["provider"], response["profile"], secrets,
        response["missing_optional"] || [], response["scope"]
      )
      return resolved unless block_given?

      begin
        yield resolved
      ensure
        resolved.close
      end
    end

    # Resolve a value-free Report (the inventory/preflight view, the same one the
    # CLI exposes as `check --json`). Unlike #load, never raises
    # MissingRequiredError: a missing required secret appears as a SecretReport
    # with status "missing_required".
    def report
      request = @request.merge("mode" => "report")
      response = parse_response(JSON.generate(request), "report", REPORT_SCHEMA_VERSION)

      secrets = (response["secrets"] || []).map do |s|
        SecretReport.new(s["name"], s["status"], s["required"],
                         s["source_provider"], s["default_applied"],
                         s["generated"], s["as_path"])
      end
      Report.new(response["provider"], response["profile"], secrets, response["scope"])
    end

    private

    # Resolve a JSON request payload and return the validated "response" hash, or
    # raise. +kind+ is "resolve" or "report"; it selects the schema version to
    # enforce and labels the version-mismatch message.
    def parse_response(payload, kind, expected_version)
      envelope = JSON.parse(Native.resolve(payload))

      unless envelope["ok"]
        err = envelope["error"] || {}
        raise Error.new(err["kind"] || "unknown", err["message"] || "")
      end

      response = envelope["response"]
      raise Error.new("ffi", "secretspec_resolve reported ok with no response") if response.nil?

      version = response["schema_version"]
      unless version == expected_version
        raise Error.new("version",
                        "unsupported #{kind} schema version #{version} " \
                        "(expected #{expected_version}); the secretspec-ffi " \
                        "library and this SDK are out of sync")
      end

      response
    end
  end

  def self.abi_version
    Native.abi_version
  end
end
