# Potential Low Severity Fixes

## Outstanding Issues

### 1. Unhandled pattern matching exceptions (line 338)
**Location:** `file_watcher.py:338` in `_should_process_file()`
**Issue:** `fnmatch.fnmatch()` could raise exceptions on malformed patterns
**Impact:** Individual file processing failures
**Solution:** Wrap pattern matching in try-catch blocks with error logging

### 2. Silent log failure (line 352, 221-222) 
**Location:** Multiple locations where log uploads occur
**Issue:** Silent exception swallowing during log uploads
**Impact:** Reduces observability and debugging capability
**Solution:** Add warning messages when log uploads fail

### 3. No log retry logic (line 351)
**Location:** Log collector upload calls throughout the code
**Issue:** Temporary network issues cause lost logs
**Impact:** Missing operational data during network hiccups
**Solution:** Implement retry mechanism with exponential backoff for log uploads

### 4. Rate limiting per-service instead of per-endpoint
**Location:** `FileChangeHandler._apply_rate_limit()` method
**Issue:** Global rate limiting across all API endpoints
**Impact:** Inefficient API usage, one slow endpoint affects others
**Solution:** Implement per-endpoint rate limiting with separate timers

## Implementation Priority
1. Pattern matching exceptions (most likely to cause failures)
2. Silent log failure (debugging impact)
3. Log retry logic (operational resilience)
4. Per-endpoint rate limiting (performance optimization)

## Notes
- These are all low severity issues that don't affect core functionality
- Can be implemented incrementally when time permits
- Each fix should include comprehensive testing and documentation