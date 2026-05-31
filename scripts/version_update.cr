# Bumps the dalfox version across every file that hardcodes it
# (Cargo.toml, Cargo.lock, flake.nix, snap/snapcraft.yaml, aur/PKGBUILD).
# Prompts for the new version interactively and prints a per-file checkmark.
#
# Pre-release suffixes are allowed (e.g. 3.0.0-dev.1, 3.1.0-rc.1).

CARGO_TOML   = "Cargo.toml"
CARGO_LOCK   = "Cargo.lock"
FLAKE_NIX    = "flake.nix"
SNAP_YAML    = "snap/snapcraft.yaml"
AUR_PKGBUILD = "aur/PKGBUILD"

# Read helpers (mirror version_check.cr).

def cargo_toml_version : String?
  content = File.read(CARGO_TOML)
  pkg = content.match(/^\[package\][\s\S]*?(?=^\[|\z)/m)
  return nil unless pkg
  match = pkg[0].match(/^version\s*=\s*"([^"]+)"/m)
  match ? match[1] : nil
rescue
  nil
end

def cargo_lock_version : String?
  content = File.read(CARGO_LOCK)
  match = content.match(/name\s*=\s*"dalfox"\s*\nversion\s*=\s*"([^"]+)"/)
  match ? match[1] : nil
rescue
  nil
end

def flake_version : String?
  content = File.read(FLAKE_NIX)
  match = content.match(/version\s*=\s*"([^"]+)"\s*;/)
  match ? match[1] : nil
rescue
  nil
end

def snap_version : String?
  content = File.read(SNAP_YAML)
  match = content.match(/^version:\s*['"]?v?([^'"\s]+)['"]?\s*$/m)
  match ? match[1] : nil
rescue
  nil
end

def aur_version : String?
  content = File.read(AUR_PKGBUILD)
  match = content.match(/^pkgver=([^\s]+)/m)
  match ? match[1].gsub('_', '-') : nil
rescue
  nil
end

# Write helpers — surgical regex replace, only the package's own version
# line (Cargo.toml's [package] block, the dalfox entry in Cargo.lock).
# Other dependencies and lockfile entries are left alone.

def update_cargo_toml(new_version : String) : Bool
  content = File.read(CARGO_TOML)
  pkg_match = content.match(/^\[package\][\s\S]*?(?=^\[|\z)/m)
  return false unless pkg_match
  pkg_block = pkg_match[0]
  updated_pkg = pkg_block.sub(/^(version\s*=\s*")[^"]+(")/m, "\\1#{new_version}\\2")
  return false if updated_pkg == pkg_block
  File.write(CARGO_TOML, content.sub(pkg_block, updated_pkg))
  true
rescue ex
  puts "  error: #{ex.message}"
  false
end

def update_cargo_lock(new_version : String) : Bool
  content = File.read(CARGO_LOCK)
  updated = content.sub(
    /(name\s*=\s*"dalfox"\s*\nversion\s*=\s*")[^"]+(")/,
    "\\1#{new_version}\\2",
  )
  return false if updated == content
  File.write(CARGO_LOCK, updated)
  true
rescue ex
  puts "  error: #{ex.message}"
  false
end

def update_flake(new_version : String) : Bool
  content = File.read(FLAKE_NIX)
  updated = content.sub(/(version\s*=\s*")[^"]+("\s*;)/, "\\1#{new_version}\\2")
  return false if updated == content
  File.write(FLAKE_NIX, updated)
  true
rescue ex
  puts "  error: #{ex.message}"
  false
end

# snap convention here keeps the `v` prefix (matches release tags).
# NOTE: Crystal's `/m` flag is MULTILINE *and* DOTALL, so `.` matches
# newlines. Match the value with `[^\n]*` to stay on a single line —
# `.*` would swallow the rest of the file.
def update_snap(new_version : String) : Bool
  content = File.read(SNAP_YAML)
  updated = content.sub(/^(version:[ \t]*)[^\n]*/m, "\\1v#{new_version}")
  return false if updated == content
  File.write(SNAP_YAML, updated)
  true
rescue ex
  puts "  error: #{ex.message}"
  false
end

# AUR pkgver disallows hyphens; rewrite `-` as `_` so dev/rc tags remain
# valid for `makepkg --printsrcinfo`. Also resets pkgrel=1 on bump.
# `[^\n]*` (not `.*`) — see the DOTALL note on update_snap above.
def update_aur(new_version : String) : Bool
  content = File.read(AUR_PKGBUILD)
  aur_ver = new_version.gsub('-', '_')
  updated = content.sub(/^pkgver=[^\n]*/m, "pkgver=#{aur_ver}")
                   .sub(/^pkgrel=[^\n]*/m, "pkgrel=1")
  return false if updated == content
  File.write(AUR_PKGBUILD, updated)
  true
rescue ex
  puts "  error: #{ex.message}"
  false
end

# Loose semver — allow numeric pre-release suffix (`-dev.1`, `-rc.2`,
# `-alpha`).
def valid_version?(version : String) : Bool
  !!(version =~ /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?$/)
end

# Status report.

cargo_v = cargo_toml_version
lock_v  = cargo_lock_version
flake_v = flake_version
snap_v  = snap_version
aur_v   = aur_version

puts "Current versions:"
puts "  #{CARGO_TOML.ljust(22)} #{cargo_v || "Not found"}"
puts "  #{CARGO_LOCK.ljust(22)} #{lock_v || "Not found"}"
puts "  #{FLAKE_NIX.ljust(22)} #{flake_v || "Not found"}"
puts "  #{SNAP_YAML.ljust(22)} #{snap_v || "Not found"}"
puts "  #{AUR_PKGBUILD.ljust(22)} #{aur_v || "Not found"}"
puts

versions = [cargo_v, lock_v, flake_v, snap_v, aur_v].compact
unique = versions.uniq

if unique.size > 1
  puts "Warning: versions disagree (#{unique.join(", ")})"
  puts
end

current = cargo_v || lock_v || flake_v || snap_v || aur_v || "unknown"
puts "Current: #{current}"
print "New version (Enter to cancel): "
input = gets
new_version = input.try(&.strip) || ""

if new_version.empty?
  puts "Cancelled."
  exit 0
end

unless valid_version?(new_version)
  puts "Invalid version: #{new_version} (expected X.Y.Z or X.Y.Z-suffix)"
  exit 1
end

if new_version == current && unique.size == 1
  puts "No change."
  exit 0
end

puts
puts "Updating to #{new_version}..."

ok = 0
total = 0

[
  {CARGO_TOML, ->{ update_cargo_toml(new_version) }, !cargo_v.nil?},
  {CARGO_LOCK, ->{ update_cargo_lock(new_version) }, !lock_v.nil?},
  {FLAKE_NIX, ->{ update_flake(new_version) }, !flake_v.nil?},
  {SNAP_YAML, ->{ update_snap(new_version) }, !snap_v.nil?},
  {AUR_PKGBUILD, ->{ update_aur(new_version) }, !aur_v.nil?},
].each do |tuple|
  path, fn, present = tuple
  next unless present
  total += 1
  print "  #{path.ljust(22)} "
  if fn.call
    puts "ok"
    ok += 1
  else
    puts "FAIL"
  end
end

puts
if ok == total
  puts "Updated #{ok} files to #{new_version}."
else
  puts "Updated #{ok}/#{total} files."
  exit 1
end
