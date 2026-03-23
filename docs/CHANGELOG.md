# Changelog

## [Unreleased]

### Fixed
- Fixed error callback type from `NL_CB_DEBUG` to `NL_CB_CUSTOM` for proper error handling
- Fixed memory leak when callback allocation fails in scan trigger
- Added 5 second socket receive timeout to prevent indefinite blocking during scan results retrieval
