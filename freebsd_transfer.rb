#!/usr/bin/env ruby
require 'find'
require 'fileutils'

class IllumosFreeBSD
  # Constant prefixes
  I = "usr/src" # Illumos prefix
  F_USER = "cddl/contrib/opensolaris" # FreeBSD userspace prefix
  F_KERN = "sys/#{F_USER}" # FreeBSD kernel prefix

  # The current Illumos tree to FreeBSD tree source map.  Use arrays for
  # FreeBSD side because some trees are duplicated.  XXX: Fix that somehow.
  #
  # NB: Does not account for file differences.
  SRC_MAP = {
    "#{I}/cmd" => %W(#{F_USER}/cmd),
    "#{I}/lib" => %W(#{F_USER}/lib),
    "#{I}/tools" => %W(#{F_USER}/tools),
    "#{I}/common/ctf" => %W(#{F_USER}/common/ctf),
    "#{I}/common/avl" => %W(#{F_USER}/common/avl #{F_KERN}/common/avl),
    "#{I}/common/acl" => %W(#{F_KERN}/common/acl),
    "#{I}/common/atomic" => %W(#{F_KERN}/common/atomic),
    "#{I}/common/nvpair" => %W(#{F_KERN}/common/nvpair),
    "#{I}/common/unicode" => %W(#{F_KERN}/common/unicode),
    "#{I}/common/zfs" => %W(#{F_KERN}/common/zfs),
    "#{I}/uts" => %W(#{F_KERN}/uts),
  }

  def self.run_cmd(cmd)
    puts cmd
    system cmd
  end

  def self.copy(to_paths, from_paths)
    from_path = from_paths.first

    puts "Copying from #{from_path} to #{to_paths.inspect}"
    Find.find(from_path) do |f_path|
      unless File.file?(f_path)
        Find.prune unless File.directory?(f_path)
        next
      end
      rel_path = f_path.gsub(/^#{from_path}\//, "")
      to_paths.each do |to_path|
        t_path = "#{to_path}/#{rel_path}"
        existing_file = File.file?(t_path)
        FileUtils.mkdir_p(File.dirname(t_path))
        run_cmd "cp #{f_path} #{t_path}"
        unless existing_file
          run_cmd "git add #{t_path}"
          raise "Adding #{t_path.inspect} failed" unless $?.success?
        end
      end
    end
  end

  def self.cmd_proc(args)
    illumos, freebsd = args.shift, args.shift
    raise "Illumos prefix not specified" unless illumos
    raise "FreeBSD prefix not specified" unless freebsd
    illumos = File.expand_path(illumos)
    freebsd = File.expand_path(freebsd)
    raise "Prefix '#{illumos}' not Illumos" unless File.directory?("#{illumos}/exception_lists")
    raise "Prefix '#{illumos}' not FreeBSD" unless File.file?("#{freebsd}/Makefile.inc1")

    direction = args.shift || "<" # Default to copy to Illumos.

    SRC_MAP.each_pair do |i_path, f_paths|
      i_paths = ["#{illumos}/#{i_path}"]
      f_paths = f_paths.collect {|path| "#{freebsd}/#{path}"}
      (direction == "<") ? copy(i_paths, f_paths) : copy(f_paths, i_paths)
    end
  end
end

IllumosFreeBSD.cmd_proc(ARGV) if $0 == __FILE__
