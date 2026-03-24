# Changelog

## [0.0.1] - 2026-03-24

### Added
- Version flag (-v, --version) to display program version

### Fixed
- Fixed error callback type from `NL_CB_DEBUG` to `NL_CB_CUSTOM` for proper error handling
- Fixed memory leak when callback allocation fails in scan trigger
- Added 5 second socket receive timeout to prevent indefinite blocking during scan results retrieval
