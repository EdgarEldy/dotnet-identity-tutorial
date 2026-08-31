## Branch

<!-- e.g. feature/core-architecture -->

## Task checklist

<!-- Copy the relevant section's checklist from README.md and check off each item. -->

- [ ]

## Commit summary

<!-- One line per commit, summarizing what changed and why. -->

## Test checklist

- [ ] Unit tests pass
- [ ] Integration tests pass (where the branch's checklist calls for them)
- [ ] End-to-end tests pass (where the branch's checklist calls for them)
- [ ] `dotnet test` is green on the whole solution

## Code review checklist

- [ ] No business logic in controllers
- [ ] Every request DTO has a matching FluentValidation validator
- [ ] Success responses return the resource directly (`ActionResult<T>`, correct status codes), no `ApiResponse<T>` wrapper
- [ ] Errors are `ProblemDetails`/`ValidationProblemDetails`, nothing else
- [ ] Any expiry/lockout logic uses the injected `TimeProvider`, not `DateTime.UtcNow`
- [ ] Every RBAC mutation (role/permission/assignment/lock state) calls `IAuditService`
- [ ] `UserManager`/`RoleManager`/`SignInManager` are only called from `Services/Implementations`
- [ ] Commits are atomic (one commit per file added or modified), follow Conventional Commits, no em dash, no Claude/Anthropic mention
