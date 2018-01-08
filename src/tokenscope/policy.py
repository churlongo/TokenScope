"""Declared audit policy: the rules a token set is measured against.

A policy is a set of expectations the operator declares up front, separate from
whatever a token happens to assert. Keeping the policy in one place means the
auditor never has to guess what "too long" or "wrong algorithm" means; the
answer is stated once and applied uniformly.

