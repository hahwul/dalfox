# Reports the version string declared in each file dalfox keeps in lockstep
# (Cargo.toml, Cargo.lock, flake.nix, snap/snapcraft.yaml, aur/PKGBUILD,
# docs/data/dalfox.json, docs/content/getting-started/installation.md).
# Exits non-zero when they disagree so it can gate a release.

CARGO_TOML  = "Cargo.toml"
CARGO_LOCK  = "Cargo.lock"
FLAKE_NIX   = "flake.nix"
SNAP_YAML   = "snap/snapcraft.yaml"
AUR_PKGBUILD = "aur/PKGBUILD"
DOCS_DATA   = "docs/data/dalfox.json"
INSTALL_DOC = "docs/content/getting-started/installation.md"

# Cargo.toml: top-level `version = "X"` inside [package].
def cargo_toml_version : String?
  content = File.read(CARGO_TOML)
  pkg = content.match(/^\[package\][\s\S]*?(?=^\[|\z)/m)
  return nil unless pkg
  match = pkg[0].match(/^version\s*=\s*"([^"]+)"/m)
  match ? match[1] : nil
rescue
  nil
end

# Cargo.lock: the `name = "dalfox"` entry's version line.
def cargo_lock_version : String?
  content = File.read(CARGO_LOCK)
  match = content.match(/name\s*=\s*"dalfox"\s*\nversion\s*=\s*"([^"]+)"/)
  match ? match[1] : nil
rescue
  nil
end

# flake.nix: any `version = "X";` (the file only has one such line for
# the dalfox derivation).
def flake_version : String?
  content = File.read(FLAKE_NIX)
  match = content.match(/version\s*=\s*"([^"]+)"\s*;/)
  match ? match[1] : nil
rescue
  nil
end

# snap/snapcraft.yaml: `version: vX` — strip the `v` for comparison.
def snap_version : String?
  content = File.read(SNAP_YAML)
  match = content.match(/^version:\s*['"]?v?([^'"\s]+)['"]?\s*$/m)
  match ? match[1] : nil
rescue
  nil
end

# aur/PKGBUILD: `pkgver=X`. AUR forbids hyphens in pkgver, so pre-release
# versions are stored with `_` (e.g. 3.0.0_dev.1); normalize back to `-`
# so it compares equal to the other files.
def aur_version : String?
  content = File.read(AUR_PKGBUILD)
  match = content.match(/^pkgver=([^\s]+)/m)
  match ? match[1].gsub('_', '-') : nil
rescue
  nil
end

# docs/data/dalfox.json: `"version": "X"`. Surfaced in the docs sidebar via
# hwaro's data model (site.data.dalfox.version).
def docs_data_version : String?
  content = File.read(DOCS_DATA)
  match = content.match(/"version"\s*:\s*"([^"]+)"/)
  match ? match[1] : nil
rescue
  nil
end

# docs/content/getting-started/installation.md: the `dalfox X.Y.Z` sample in
# the Verify section ("You should see something like `dalfox 3.1.2`"). It
# mirrors `dalfox --version` output, so it carries any pre-release suffix too.
def install_doc_version : String?
  content = File.read(INSTALL_DOC)
  match = content.match(/`dalfox (\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?)`/)
  match ? match[1] : nil
rescue
  nil
end

cargo_v   = cargo_toml_version
lock_v    = cargo_lock_version
flake_v   = flake_version
snap_v    = snap_version
aur_v     = aur_version
docs_v    = docs_data_version
install_v = install_doc_version

puts "#{CARGO_TOML.ljust(46)} #{cargo_v || "Not found"}"
puts "#{CARGO_LOCK.ljust(46)} #{lock_v || "Not found"}"
puts "#{FLAKE_NIX.ljust(46)} #{flake_v || "Not found"}"
puts "#{SNAP_YAML.ljust(46)} #{snap_v || "Not found"}"
puts "#{AUR_PKGBUILD.ljust(46)} #{aur_v || "Not found"}"
puts "#{DOCS_DATA.ljust(46)} #{docs_v || "Not found"}"
puts "#{INSTALL_DOC.ljust(46)} #{install_v || "Not found"}"
puts

versions = [cargo_v, lock_v, flake_v, snap_v, aur_v, docs_v, install_v].compact

if versions.empty?
  puts "No versions found!"
  exit 1
end

unique = versions.uniq

if unique.size == 1
  puts "All versions match: #{unique.first}"
else
  puts "Versions disagree: #{unique.join(", ")}"
  exit 1
end
