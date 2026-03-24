# Changelog

## [0.0.2] - 2026-03-24

### Added
- CSV output flag (-c, --csv <file>) to export scan results to CSV file

### Fixed
- Fixed IP array initialization in interface listing
- Fixed CSV/JSON escaping for SSIDs and vendors with special characters
- Fixed display_csv return type for proper error handling
- Fixed input buffer size in interface selection
- Fixed variable shadowing in live mode loop
- Fixed static policy array in scan callback

## [0.0.1] - 2026-03-24

### Added
- Version flag (-v, --version) to display program version

### Fixed
- Fixed error callback type from `NL_CB_DEBUG` to `NL_CB_CUSTOM` for proper error handling
- Fixed memory leak when callback allocation fails in scan trigger
- Added 5 second socket receive timeout to prevent indefinite blocking during scan results retrieval
