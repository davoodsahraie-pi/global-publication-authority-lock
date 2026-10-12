# Officiality boundary

After branch protection is activated, only protected `main` is the public machine lock.

A chat may propose work, but it cannot make a publication state transition official by text alone.

A proposal is official only when:
1. it is merged to protected `main`;
2. required check `publication-authority` passed;
3. the validator code came from the trusted base branch;
4. every mutating action references a successful, manually triggered `authorize-next-action` workflow run;
5. the authorization artifact is bound to the exact current lock SHA, private state SHA, action ID, project, operations, and target scopes;
6. state transitions preserve append-only PASS/FAIL/frozen/blocked ledgers.

Changing the public lock SHA or private state SHA makes prior authorizations stale.
