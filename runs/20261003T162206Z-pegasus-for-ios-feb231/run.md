# Pegasus for iOS

- run_id: `20261003T162206Z-pegasus-for-ios-feb231`
- terminal state: **judge_rejected**
- domains / attempts: mobile-attack (3)
- model: claude-code:claude-sonnet-5-5; judge: claude-code:claude-opus-5-5
- git: `6c4269f3e250-dirty`; prompt: `3bbb467e80b7`
- model calls: 54; tokens in/out: 2006561/21927; wall: 380.536s
- ERROR rules: E012
- WARN rules: none
- judge failed items: omission_check
- zero-hit searches: 0
- fetch failures: 1
  - Pegasus for iOS: not in frozen evidence
- unmatched actors: 0

## Attempts
- mobile-attack #1: lint ERROR E012
- mobile-attack #2: lint clean; judge failed omission_check
- mobile-attack #3: lint clean; judge failed omission_check

## Error
- attempts exhausted; the judge rejected the last lint-clean proposal
