# Security Review

Given a package name and CVE ID, perform a full remediation pass:

1. Use codebase_search to find every usage of the affected package across the repo
2. Check the installed version in requirements/base.txt or superset-frontend/package.json
   against the patched version in the CVE advisory
3. Classify exposure: is the vulnerable code path actually reachable from our
   usage, or is it dead code we never call?
4. If a non-breaking patch exists, apply it and run the relevant test suite
5. If it requires a major version bump, stop and produce a written risk
   assessment instead of patching silently
6. Output a summary table: package | old version | new version | exposure
   classification | test results
