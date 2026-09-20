# Reading the claims report

The claims command prints one block per token, in input order.

- `exp` and `nbf` mark the validity window, rendered in UTC.
- Registered claims are typed and checked; private claims are listed under
  coverage so you can see what the application layer added.
- A missing `aud` is not automatically a finding: it depends on the policy
  profile, so the report prints the raw value and leaves the judgement.

Two runs over the same file are byte identical.
