# frozen_string_literal: true

# Resolved#close must attempt every as_path file.
#
# The method exists so secret-bearing temp files do not outlive the result.
# Stopping at the first file the OS refuses to remove leaves every later secret
# on disk -- the exact outcome it is meant to prevent -- and the caller has no
# way to know which ones survived.
#
# The Go SDK (firstErr) and the .NET SDK (firstError) already clean up
# everything and report the first failure afterwards; .NET catches IOException
# specifically, which is the ordinary Windows sharing violation raised when
# another process still holds the file open. These tests hold the Ruby SDK to
# the same contract.

require "tmpdir"
require "minitest/autorun"

def ensure_ext
  pkg = File.expand_path("..", __dir__)
  return unless Dir[File.join(pkg, "lib", "secretspec", "secretspec_ext.{so,bundle}")].empty?

  system("bash", File.join(pkg, "scripts", "build-ext.sh")) || raise("build-ext.sh failed")
end

ensure_ext
require_relative "../lib/secretspec"

class TestClose < Minitest::Test
  def setup
    @dir = Dir.mktmpdir("secretspec-close")
  end

  def teardown
    FileUtils.rm_rf(@dir) if @dir
  end

  # A Resolved over `count` real as_path files.
  def build(count = 3)
    paths = (0...count).map do |i|
      path = File.join(@dir, "secret#{i}")
      File.write(path, "super-secret-value")
      path
    end
    secrets = {}
    paths.each_with_index do |path, i|
      secrets["S#{i}"] = Secretspec::ResolvedSecret.new(nil, path, true, "provider", "dotenv")
    end
    [Secretspec::Resolved.new("dotenv", "default", secrets, [], nil), paths]
  end

  def test_close_removes_every_as_path_file
    resolved, paths = build
    resolved.close
    paths.each { |path| refute File.exist?(path), "#{path} was left behind" }
  end

  def test_close_is_idempotent
    resolved, = build
    resolved.close
    resolved.close # a file already gone is not an error
  end

  # The regression: one refusal must not strand the other secrets.
  def test_close_removes_the_rest_when_one_file_cannot_be_removed
    resolved, paths = build
    blocked = paths[1]

    File.singleton_class.prepend(Module.new do
      define_method(:delete) do |*args|
        raise Errno::EACCES, args.first if args.first == blocked

        super(*args)
      end
    end)

    assert_raises(Errno::EACCES) { resolved.close }

    refute File.exist?(paths[0]), "file before the failure was not removed"
    refute File.exist?(paths[2]), "file after the failure was stranded on disk"
    assert File.exist?(blocked), "the blocked file should still be there"
  end

  def test_close_closes_from_the_load_block
    resolved, paths = build
    # Builder#load closes automatically when given a block; close is what it calls.
    resolved.close
    paths.each { |path| refute File.exist?(path) }
  end
end
