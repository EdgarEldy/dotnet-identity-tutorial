# dotnet-identity-tutorial

A complete tutorial for building a full role-based access control (RBAC) system on **ASP.NET Core Identity**, on **.NET 10** (ASP.NET Core 10): users, roles, fine-grained resource/action permissions, MFA, external logins, JWT access tokens with rotating refresh tokens, rate limiting, and audit logging.

This document is the **complete specification** of the project: it is meant to be followed step by step to implement each branch.

## Table of contents

- [Design decisions around Identity's built-in mechanisms](#design-decisions-around-identitys-built-in-mechanisms)
- [Claims-based authorization: how permissions actually get checked](#claims-based-authorization-how-permissions-actually-get-checked)
- [Access tokens and refresh tokens](#access-tokens-and-refresh-tokens)
- [Success responses and error responses: minimal HTTP semantics + ProblemDetails](#success-responses-and-error-responses-minimal-http-semantics--problemdetails)
- [Tech stack](#tech-stack)
- [Data model](#data-model)
- [Branching strategy](#branching-strategy)
- [Project structure](#project-structure)
- [feature/core-architecture](#featurecore-architecture)
- [feature/identity-setup](#featureidentity-setup)
- [feature/rbac](#featurerbac)
- [feature/claims-and-authorization](#featureclaims-and-authorization)
- [feature/token-lifecycle](#featuretoken-lifecycle)
- [feature/auth-flows](#featureauth-flows)
- [feature/mfa](#featuremfa)
- [feature/audit-logging](#featureaudit-logging)
- [feature/external-logins (bonus)](#featureexternal-logins-bonus)
- [Order of work](#order-of-work)
- [Code conventions](#code-conventions)
- [Concepts covered](#concepts-covered)
- [How to follow this tutorial](#how-to-follow-this-tutorial)

## Design decisions around Identity's built-in mechanisms

ASP.NET Core Identity ships with its own schema (`AspNetUsers`, `AspNetRoles`, `AspNetUserRoles`, ...) and its own mechanisms for account confirmation, password reset, lockout, and multi-factor authentication - using it properly means building on what it already provides, rather than reimplementing it:

- **Users and roles** map directly onto Identity's own tables. `ApplicationUser : IdentityUser<int>` adds the extra columns this project needs (`FirstName`, `LastName`) that aren't part of the base class; `ApplicationRole : IdentityRole<int>` is used as-is. The many-to-many between users and roles is Identity's own `AspNetUserRoles` table.
- **Account activation and password reset are not backed by dedicated tables.** Identity's `UserManager<TUser>` generates these as stateless, cryptographically signed tokens (`GenerateEmailConfirmationTokenAsync`, `GeneratePasswordResetTokenAsync`), validated without a database lookup.
- **Account lockout uses Identity's own mechanism** (`options.Lockout.MaxFailedAccessAttempts`, `LockoutEnd`), not a custom boolean column.
- **Multi-factor authentication uses Identity's own TOTP support** (`GenerateAuthenticatorKeyAsync`, `VerifyTwoFactorTokenAsync`, recovery codes) - see [feature/mfa](#featuremfa).
- **`SecurityStamp`**: Identity automatically regenerates this value on password changes and other critical account events. This project ties it into refresh token validity - see [Access tokens and refresh tokens](#access-tokens-and-refresh-tokens).
- **Fine-grained permissions, refresh tokens, rate limiting, and audit logging are not part of Identity at all**, and are added as custom tables and services layered on top - this is the actual substance of this tutorial.

## Claims-based authorization: how permissions actually get checked

Identity's built-in authorization only goes as far as roles (`[Authorize(Roles = "Admin")]`). This tutorial adds resource/action permissions (`PRODUCT:WRITE`, `ORDER:READ`, ...), resolved **once, at sign-in time, into claims** - not with a database query on every authorized request.

- `ApplicationUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<ApplicationUser, ApplicationRole>` overrides `GenerateClaimsAsync`: after Identity's default claims are generated, it resolves every permission granted by the user's current roles (via `RolePermission`) and adds one `permission` claim per distinct permission
- `PermissionAuthorizationHandler` is a pure claims check: `context.User.HasClaim("permission", requirement.Permission)` - no database dependency at request time
- `PermissionPolicyProvider` (`IAuthorizationPolicyProvider`) builds a policy on demand for any `[Authorize(Policy = "RESOURCE:ACTION")]` an endpoint declares

**The trade-off, stated honestly**: permissions are baked into the access token at issuance, so a permission change on a role doesn't take effect for a user already holding a token until that token is refreshed. Given this tutorial's short access-token lifetime, the staleness window is small but not zero.

## Access tokens and refresh tokens

- **Access tokens** are short-lived (15 minutes, configurable), carry the claims described above, validated statelessly - except that the token's `jti` is also checked against `BlacklistedAccessToken`, so an explicit logout takes effect immediately
- **Refresh tokens** are long-lived (7 days, configurable), opaque, stored server-side (`RefreshToken`, hashed at rest), used exclusively to obtain a new access token
- **Rotation with reuse detection**: every refresh request revokes the token just used and issues a new one in the same family; presenting an already-revoked refresh token revokes the entire family, forcing a real re-login
- **Tied to `SecurityStamp`**: `RefreshAsync` compares the refresh token's stored `security_stamp_at_issuance` against the user's *current* `SecurityStamp` - if they differ (the password was changed, or Identity otherwise rotated the stamp), the refresh is rejected and the whole family is revoked, even if the refresh token itself hasn't expired. A password change invalidates every outstanding session, not just the credential.

## Success responses and error responses: minimal HTTP semantics + ProblemDetails

This project follows ASP.NET Core's own default idiom rather than introducing a custom response envelope:

- **Success**: an endpoint returns the resource itself - `ActionResult<T>` (or `TypedResults` equivalents) with the DTO directly as the body, `201 Created` via `CreatedAtAction` with a `Location` header for creation, `204 No Content` for a successful action with nothing to return. No `success: true` field, no wrapping object - the HTTP status code already carries that meaning, and duplicating it in the body is redundant. Paginated list endpoints return the collection directly in the body, with pagination metadata (`X-Total-Count`, a `Link` header for `next`/`prev`) carried in **response headers** rather than mixed into the payload.
- **Failure**: every non-2xx response is a `ProblemDetails`, per **RFC 9457** ("Problem Details for HTTP APIs", July 2023 - it obsoletes the older RFC 7807; ASP.NET Core 10's `AddProblemDetails()` produces RFC 9457-compliant output under the same `application/problem+json` media type and core fields: `type`, `title`, `status`, `detail`, `instance`, plus `extensions` for anything custom), produced automatically by `AddProblemDetails()` and a custom `IExceptionHandler`
- Validation failures (FluentValidation, or model-binding errors) are the `ValidationProblemDetails` variant specifically - same shape, with an added `errors` dictionary mapping field names to messages, produced natively by ASP.NET Core once `AddProblemDetails()` is configured
- **Why not a custom envelope for success too**: a generic `ApiResponse<T>` wrapper is a legitimate choice some teams make, but it isn't the ASP.NET Core idiom - the framework's own conventions (typed action results, status codes, `ProblemDetails` for errors) already cover the same need without inventing a parallel format. Introducing one anyway means every consumer of this API has to learn a project-specific convention instead of the one .NET already ships with.

## Tech stack

| Component | Choice |
|---|---|
| Framework | ASP.NET Core 10 (.NET 10 LTS) |
| Language | C# 13 |
| Identity | ASP.NET Core Identity (`Microsoft.AspNetCore.Identity.EntityFrameworkCore`) |
| Database | PostgreSQL 16 (via Docker Compose) |
| ORM | Entity Framework Core 10 |
| Migrations | EF Core Migrations |
| Authentication | Identity for credential validation and claims generation; `Microsoft.AspNetCore.Authentication.JwtBearer` for stateless access; custom refresh token issuance/rotation |
| Authorization | Claims-based permission checks (`IAuthorizationPolicyProvider`, `AuthorizationHandler<PermissionRequirement>`) |
| Validation | FluentValidation, wired as an `IAsyncActionFilter` producing `ValidationProblemDetails` on failure |
| Error handling | `IExceptionHandler` (built-in .NET 8+ pattern) + `AddProblemDetails()` |
| Time abstraction | `TimeProvider` (built-in .NET 8+), injected wherever expiry/lockout logic needs the current time |
| Rate limiting | `Microsoft.AspNetCore.RateLimiting` (built-in .NET 7+), applied to `Auth/Login`/`Auth/Register` |
| CORS | `Microsoft.AspNetCore.Cors`, configured for a named frontend origin policy |
| MFA | Identity's built-in TOTP support (`GenerateAuthenticatorKeyAsync`, recovery codes) |
| External logins *(bonus)* | `Microsoft.AspNetCore.Authentication.Google` |
| API documentation | Swashbuckle (Swagger UI), JWT Bearer scheme wired to the "Authorize" button |
| Tests | xUnit, Moq, Testcontainers for .NET, `WebApplicationFactory`, `Microsoft.Extensions.TimeProvider.Testing` (`FakeTimeProvider`) |
| CI/CD | GitHub Actions |
| Containerization | Docker, docker-compose |

## Data model

```
AspNetUsers (Identity-managed)                    ApplicationUser : IdentityUser<int>
    id, user_name, normalized_user_name, email, normalized_email,
    password_hash, security_stamp, lockout_enabled, lockout_end, access_failed_count,
    two_factor_enabled, ...
    + first_name, last_name                        (added by this project)

AspNetRoles (Identity-managed)                    ApplicationRole : IdentityRole<int>
    id, name, normalized_name

AspNetUserRoles (Identity-managed, N──N)
    user_id, role_id

AspNetUserLogins (Identity-managed)                external login provider keys - see feature/external-logins

permissions (id, resource, action)                 custom
role_permissions (role_id, permission_id)           custom join table, N──N

refresh_tokens (id, user_id, token_hash, family_id, security_stamp_at_issuance,
                 created_at, expires_at, revoked_at, replaced_by_token_id)   custom

blacklisted_access_tokens (id, user_id, jti, blacklisted_at, expires_at)     custom

audit_logs (id, actor_user_id, action, entity_type, entity_id, details, created_at)   custom
```

Not present as tables - replaced by Identity's own mechanisms: account confirmation and password-reset tokens (stateless, signed, see above), and MFA secrets/recovery codes (stored by Identity itself as user tokens, not a custom table).

## Branching strategy

| Branch | Role |
|---|---|
| `master` | Stable, production-ready code. No direct commits, only merges from `develop`. |
| `develop` | Integration branch. |
| `feature/core-architecture` | Project structure, EF Core/PostgreSQL configuration, CORS, validation pipeline, ProblemDetails/`IExceptionHandler`, `TimeProvider`, Docker, CI. |
| `feature/identity-setup` | `ApplicationUser`/`ApplicationRole`, Identity configuration, base migrations, seeded default roles. |
| `feature/rbac` | `Permission`/`RolePermission`, administration of users, roles, permissions, and their assignments. |
| `feature/claims-and-authorization` | Custom claims principal factory, claims-based `PermissionAuthorizationHandler`, dynamic policy provider. |
| `feature/token-lifecycle` | JWT issuance, refresh token rotation with reuse detection, `SecurityStamp`-aware invalidation, access-token blacklisting. |
| `feature/auth-flows` | Registration, email confirmation, login, forgot/reset password, logout, current-user endpoint, rate limiting on login/register. |
| `feature/mfa` | TOTP-based two-factor authentication and recovery codes. |
| `feature/audit-logging` | An audit trail for every RBAC and account-security change. |
| `feature/external-logins` | *Bonus*: sign in with Google, linked to an existing or newly created `ApplicationUser`. |

## Project structure

```
DotnetIdentityTutorial/
├── src/
│   └── DotnetIdentityTutorial/
│       ├── Program.cs
│       ├── appsettings.json
│       ├── Identity/
│       │   ├── ApplicationUser.cs
│       │   ├── ApplicationRole.cs
│       │   └── ApplicationUserClaimsPrincipalFactory.cs
│       ├── Models/
│       │   ├── Permission.cs, RolePermission.cs
│       │   ├── RefreshToken.cs, BlacklistedAccessToken.cs
│       │   └── AuditLog.cs
│       ├── Data/
│       │   ├── AppDbContext.cs               (: IdentityDbContext<ApplicationUser, ApplicationRole, int>)
│       │   └── Configurations/
│       ├── Dtos/
│       │   ├── (no Common/ApiResponse.cs - see "Success responses and error responses")
│       │   ├── Auth/ (RegisterRequest, LoginRequest, TokenResponse, RefreshRequest,
│       │   │          ConfirmEmailRequest, ForgotPasswordRequest, ResetPasswordRequest,
│       │   │          ChangePasswordRequest, VerifyTwoFactorRequest, ExternalLoginCallbackRequest)
│       │   ├── User/ (UserResponse, UpdateUserRequest, AssignRoleRequest)
│       │   └── Rbac/ (RoleRequest, RoleResponse, PermissionRequest, PermissionResponse)
│       ├── Validators/                          (FluentValidation, one per request DTO)
│       │   ├── RegisterRequestValidator.cs, LoginRequestValidator.cs, ...
│       ├── Services/
│       │   ├── Interfaces/
│       │   │   ├── IAuthService.cs, IUserAdminService.cs, IRbacService.cs,
│       │   │   │   ITokenService.cs, IMfaService.cs, IAuditService.cs, IEmailService.cs
│       │   └── Implementations/
│       │       ├── AuthService.cs, UserAdminService.cs, RbacService.cs,
│       │           TokenService.cs, MfaService.cs, AuditService.cs, EmailService.cs
│       ├── BackgroundServices/
│       │   └── ExpiredTokenCleanupService.cs      (IHostedService, purges expired refresh/blacklisted tokens)
│       ├── Authorization/
│       │   ├── PermissionRequirement.cs, PermissionAuthorizationHandler.cs, PermissionPolicyProvider.cs
│       ├── Filters/
│       │   └── ValidationFilter.cs               (IAsyncActionFilter, runs FluentValidation, short-circuits to ValidationProblemDetails)
│       ├── ErrorHandling/
│       │   └── GlobalExceptionHandler.cs          (IExceptionHandler)
│       ├── RateLimiting/
│       │   └── RateLimiterPolicies.cs             (named policies, applied via [EnableRateLimiting])
│       ├── Controllers/
│       │   ├── AuthController.cs, UsersController.cs, RolesController.cs, ExternalLoginController.cs
│       ├── Exceptions/
│       │   ├── ResourceNotFoundException.cs, BusinessRuleException.cs
│       └── Migrations/
├── tests/
│   └── DotnetIdentityTutorial.Tests/
│       ├── Authorization/, Tokens/ (using FakeTimeProvider), Validators/,
│       │   Controllers/, Services/, Repositories/
├── docker-compose.yml
├── Dockerfile
└── .github/workflows/ci.yml
```

## feature/core-architecture

### Tasks

- [x] Create the solution and Web API project (`dotnet new webapi` targeting .NET 10)
- [x] NuGet packages: `Microsoft.AspNetCore.Identity.EntityFrameworkCore`, `Microsoft.EntityFrameworkCore.Design`, `Npgsql.EntityFrameworkCore.PostgreSQL`, `Microsoft.AspNetCore.Authentication.JwtBearer`, `Swashbuckle.AspNetCore`, `FluentValidation.AspNetCore`
- [x] Test packages: `xunit`, `Moq`, `Microsoft.AspNetCore.Mvc.Testing`, `Testcontainers.PostgreSql`, `Microsoft.Extensions.TimeProvider.Testing`
- [x] Package layout above
- [x] Controllers use the default ASP.NET Core routing convention (`[Route("api/v1/[controller]")]`), action method names resolving naturally into their route segments - no `LowercaseUrls` override, no hand-typed kebab-case
- [x] Pagination helper for list endpoints: sets `X-Total-Count` and `Link` (`next`/`prev`) response headers rather than a body wrapper - see [above](#success-responses-and-error-responses-minimal-http-semantics--problemdetails)
- [x] `GlobalExceptionHandler` (`IExceptionHandler`), registered via `AddExceptionHandler<GlobalExceptionHandler>()` + `AddProblemDetails()`; maps `ResourceNotFoundException` → 404, `BusinessRuleException` → 422, anything unmapped → 500, each as a `ProblemDetails`
- [x] `ValidationFilter` (`IAsyncActionFilter`): resolves `IValidator<T>` for the action's request DTO, runs it before the action executes, short-circuits with a `ValidationProblemDetails` (400) on failure - registered globally so no controller needs to call it explicitly
- [x] `TimeProvider` registered as a singleton (`builder.Services.AddSingleton(TimeProvider.System)`), injected anywhere expiry or timestamp logic is needed, instead of calling `DateTime.UtcNow` directly
- [x] CORS: a named policy for the frontend origin(s), configured from `appsettings`, applied globally
- [x] `UseHttpsRedirection()` and `UseHsts()` (the latter outside the `Development` environment), applied before any other middleware in the pipeline
- [x] `IEmailService`/`EmailService` (contract/implementation, `Services/Interfaces`/`Services/Implementations`): `SendConfirmationEmailAsync`, `SendPasswordResetEmailAsync` - for this tutorial, the implementation logs the link rather than sending a real email, to stay self-contained without a mail provider dependency. This is a project-defined interface, distinct from Identity's own `IEmailSender<TUser>` extension point (relevant only to `MapIdentityApi`/the scaffolded Identity UI, neither of which this project uses, since `AuthController` calls `UserManager`'s token methods directly)
- [x] `appsettings.json`/`appsettings.Development.json`: PostgreSQL connection string, JWT signing key, access/refresh token lifetimes, allowed CORS origins
- [x] Swagger UI configuration with the JWT Bearer "Authorize" button
- [x] `docker-compose.yml` (API + PostgreSQL), `Dockerfile`
- [x] `.github/workflows/ci.yml`: `dotnet build` + `dotnet test`

## feature/identity-setup

### Tasks

- [x] `ApplicationUser : IdentityUser<int>` (adds `FirstName`, `LastName`), `ApplicationRole : IdentityRole<int>`
- [x] `AppDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, int>`
- [x] `Program.cs`: `AddIdentity<ApplicationUser, ApplicationRole>()`, password policy, lockout policy
- [x] Initial EF Core migration - Identity's own schema, plus `Permissions`/`RolePermissions` (pulled forward from `feature/rbac`'s entities, see the checklist note there and `.claude/CLAUDE.md`'s "Deviations")
- [x] Startup seeding: default roles (`ADMIN`, `USER`) via `RoleManager`
- [x] Startup seeding, continued: a baseline set of `Permission` rows covering every resource/action this project defines (`USER:READ`, `USER:WRITE`, `ROLE:READ`, `ROLE:WRITE`, `PERMISSION:READ`, `PERMISSION:WRITE`, `AUDIT:READ`, ...), each immediately assigned to `ADMIN` via `RolePermission` - without this, `[Authorize(Policy = "PERMISSION:WRITE")]` on `POST /api/v1/Permissions` (added in `feature/rbac`) can never be satisfied by anyone, since no account would hold that permission and the endpoint that grants it requires it circularly
- [x] Tests: migration applies cleanly against Testcontainers PostgreSQL, both seeding steps are idempotent (running startup twice doesn't duplicate roles or permissions, doesn't fail on an already-existing `RolePermission` row)

## feature/rbac

### Endpoints

| Method | URL | Description | Access |
|---|---|---|---|
| GET | `/api/v1/Users` | Paginated list | `[Authorize(Policy = "USER:READ")]` |
| GET | `/api/v1/Users/{id}` | Detail, including roles | `[Authorize(Policy = "USER:READ")]` |
| PATCH | `/api/v1/Users/{id}/Lock` | Locks the account | `[Authorize(Policy = "USER:WRITE")]` |
| PATCH | `/api/v1/Users/{id}/Unlock` | Unlocks the account | `[Authorize(Policy = "USER:WRITE")]` |
| POST | `/api/v1/Users/{id}/Roles/{roleId}` | Assign a role to a user | `[Authorize(Policy = "USER:WRITE")]` |
| DELETE | `/api/v1/Users/{id}/Roles/{roleId}` | Remove a role from a user | `[Authorize(Policy = "USER:WRITE")]` |
| GET | `/api/v1/Roles` | List, including permissions | `[Authorize(Policy = "ROLE:READ")]` |
| POST | `/api/v1/Roles` | Create | `[Authorize(Policy = "ROLE:WRITE")]` |
| POST | `/api/v1/Roles/{id}/Permissions/{permissionId}` | Assign a permission to a role | `[Authorize(Policy = "ROLE:WRITE")]` |
| DELETE | `/api/v1/Roles/{id}/Permissions/{permissionId}` | Remove a permission from a role | `[Authorize(Policy = "ROLE:WRITE")]` |
| GET | `/api/v1/Permissions` | List | `[Authorize(Policy = "PERMISSION:READ")]` |
| POST | `/api/v1/Permissions` | Create | `[Authorize(Policy = "PERMISSION:WRITE")]` |

### Tasks

- [x] `Permission`, `RolePermission` entities, Fluent API configuration (done early, in `feature/identity-setup`, since startup seeding there needed them to exist; see that branch's checklist note and `.claude/CLAUDE.md`)
- [x] `IRbacService`/`RbacService`: permission CRUD, role CRUD, assignment/removal operations - every assignment/removal call also writes an entry via `IAuditService` (from `feature/audit-logging`; stub the call now, wire the real implementation once that branch lands)
- [x] `IUserAdminService`/`UserAdminService`: user listing/detail, lock/unlock - same audit hook
- [x] `RegisterRequestValidator`-style `FluentValidation` validators for every new request DTO introduced in this branch
- [x] `UsersController`, `RolesController` (plus `PermissionsController`, needed for `/api/v1/Permissions` under the default routing convention)
- [x] Tests: assignment/removal operations against a real database, idempotency, validators rejecting malformed input - covered as `ValidationProblemDetails` isn't reachable through HTTP yet on this branch (see the `[Authorize]` deviation in `.claude/CLAUDE.md`), so validator rejection is tested directly against the validator instead

## feature/claims-and-authorization

### Tasks

- [x] `ApplicationUserClaimsPrincipalFactory`, registered in place of the default factory
- [x] `PermissionRequirement`, `PermissionAuthorizationHandler` (pure claims check), `PermissionPolicyProvider`
- [x] Tests: claims factory output for multi-role users (no duplicate permission claims), handler success/failure, policy provider building a policy for an arbitrary permission string

## feature/token-lifecycle

### Tasks

- [x] `RefreshToken`, `BlacklistedAccessToken` entities, both referencing `TimeProvider` (injected into `ITokenService`) rather than `DateTime.UtcNow` for every timestamp they record
- [x] `ITokenService`/`TokenService`: `IssueTokensAsync` (builds the claims principal, issues the JWT with a unique `jti`, issues and persists a refresh token capturing the user's *current* `SecurityStamp`), `RefreshAsync` (validates the token, compares its captured `SecurityStamp` against the user's current one - mismatch means revoke-and-reject regardless of expiry - then rotates), `RevokeAsync` (logout: blacklists the access token's `jti`, revokes the refresh token family)
- [x] JWT Bearer `OnTokenValidated` event: checks the `jti` against `BlacklistedAccessToken`
- [x] `ExpiredTokenCleanupService` (`IHostedService`/`BackgroundService`, using the injected `TimeProvider`): runs on a daily interval, deletes `RefreshToken` and `BlacklistedAccessToken` rows past their `expires_at` - without this, both tables grow unbounded, since revocation only marks a row, it never removes it. This is a housekeeping concern, not a security one: a revoked or expired token is already rejected regardless of whether its row still exists
- [x] Tests (using `FakeTimeProvider` to simulate elapsed time without real delays): issue → refresh → refresh again (rotation), reused refresh token triggering family revocation, a password change (simulated `SecurityStamp` rotation) invalidating an outstanding refresh token even before its natural expiry

## feature/auth-flows

### Endpoints

| Method | URL | Description | Access |
|---|---|---|---|
| POST | `/api/v1/Auth/Register` | Sign up | Public, rate-limited |
| GET | `/api/v1/Auth/ConfirmEmail` | Confirms the account | Public |
| POST | `/api/v1/Auth/Login` | Sign in (or a "2FA required" partial result - see `feature/mfa`) | Public, rate-limited |
| POST | `/api/v1/Auth/Refresh` | Exchanges a valid refresh token for a new pair | Public |
| POST | `/api/v1/Auth/ForgotPassword` | Generates a password-reset token | Public, rate-limited |
| POST | `/api/v1/Auth/ResetPassword` | Consumes the token, updates the password | Public |
| POST | `/api/v1/Auth/ChangePassword` | Changes the password for the currently authenticated user (requires the current password) | Authenticated |
| POST | `/api/v1/Auth/Logout` | Revokes the current access token and refresh token family | Authenticated |
| GET | `/api/v1/Auth/Me` | Current user profile, roles, and permissions | Authenticated |

### Tasks

- [x] `IAuthService`/`AuthService`: every flow above, delegating token issuance to `ITokenService`
- [x] `RegisterAsync` and `ForgotPasswordAsync` call `IEmailService` (from `feature/core-architecture`) to send the confirmation link and the reset link, respectively, instead of only generating a token that nothing ever delivers
- [x] `ChangePasswordAsync`: wraps `UserManager.ChangePasswordAsync(user, currentPassword, newPassword)` - distinct from `ResetPasswordAsync`, which is for a user who has lost access and can't provide a current password; a password change here also revokes every outstanding refresh token family for the user (the same `SecurityStamp`-comparison mechanism from `feature/token-lifecycle` handles this automatically, since `ChangePasswordAsync` rotates the stamp)
- [x] `Program.cs`: `options.SignIn.RequireConfirmedAccount = true` set explicitly on `AddIdentity<...>()` - without it, `Login` succeeds for an account that never completed `ConfirmEmail`, making the activation flow purely cosmetic
- [x] `ForgotPasswordAsync` returns the exact same response - same status code, same body - whether or not the submitted email matches an existing account, and takes roughly the same amount of time either way (no early return that skips the token-generation work); without this, the endpoint becomes a user-enumeration oracle, since a distinguishable response (or a measurably faster one) tells an attacker which emails are registered
- [x] `AuthController`
- [x] `RateLimiterPolicies`: a named fixed-window policy (`"auth"`, e.g. 5 requests/minute per IP) applied via `[EnableRateLimiting("auth")]` on `Register`, `Login`, and `ForgotPassword` - Identity's own lockout already protects a single account from brute force, this protects the endpoint itself from distributed attempts across many accounts; the same named policy is reused by `feature/mfa`'s `VerifyTwoFactor` endpoint
- [x] `Program.cs` finalized: `AddAuthentication().AddJwtBearer(...)`, `AddAuthorization`, `AddRateLimiter(...)`
- [x] End-to-end tests: full lifecycle (register → confirm → login → call a protected endpoint → refresh → logout → confirm rejection afterward), the rate limiter returning 429 past its threshold, an account-lockout test - `FakeTimeProvider` advances `ITokenService`'s own timestamps, but Identity's lockout clock isn't `TimeProvider`-seamed in this SDK version (confirmed, see `.claude/CLAUDE.md`), so the lockout test simulates elapsed time via `UserManager.SetLockoutEndDateAsync` instead, still without any real wait

## feature/mfa

### Endpoints

| Method | URL | Description | Access |
|---|---|---|---|
| POST | `/api/v1/Auth/Enable2fa` | Generates a TOTP secret (returned as a QR-code-ready URI) | Authenticated |
| POST | `/api/v1/Auth/Confirm2fa` | Verifies the first code, activates 2FA, returns recovery codes | Authenticated |
| POST | `/api/v1/Auth/VerifyTwoFactor` | Completes a login that returned "2FA required" | Public (requires the partial login ticket) |
| POST | `/api/v1/Auth/Disable2fa` | Disables 2FA | Authenticated |

### Tasks

- [x] `IMfaService`/`MfaService`: wraps `UserManager.GenerateAuthenticatorKeyAsync`, `VerifyTwoFactorTokenAsync`, `GenerateNewTwoFactorRecoveryCodesAsync`, `SetTwoFactorEnabledAsync`
- [x] `VerifyTwoFactor` is rate-limited via the same `"auth"` policy defined in `feature/auth-flows` - a 6-digit TOTP code has limited entropy, and this endpoint is exactly as brute-forceable as `Login` itself, so it gets the same protection rather than being overlooked as a follow-up step to an already-authenticated-feeling flow
- [x] `AuthService.LoginAsync` updated: if `TwoFactorEnabled` is true, returns a partial result (no tokens yet) instead of calling `ITokenService.IssueTokensAsync` directly; `VerifyTwoFactor` completes the flow and issues tokens only after a valid TOTP code or recovery code
- [x] `AuthController` extended with the four endpoints above
- [x] Tests: enabling 2FA, a login attempt correctly stopping short of issuing tokens, completing it with a valid code, rejecting an invalid one, and recovery-code login consuming a code so it can't be reused

## feature/audit-logging

### Tasks

- [x] `AuditLog` entity (`actor_user_id`, `action`, `entity_type`, `entity_id`, `details` as a JSON column, `created_at` via `TimeProvider`)
- [x] `IAuditService`/`AuditService`: a single `LogAsync(action, entityType, entityId, details)` method
- [x] Wired into every mutating operation in `RbacService` and `UserAdminService` (role/permission assignment and removal, user lock/unlock) - each call records who did what, to what, and when
- [x] `GET /api/v1/AuditLogs` - paginated, filterable by actor/entity type, `[Authorize(Policy = "AUDIT:READ")]`
- [x] Tests: every RBAC mutation from `feature/rbac`'s test suite re-run with an assertion that a matching audit entry now exists

## feature/external-logins (bonus)

### Endpoints

| Method | URL | Description | Access |
|---|---|---|---|
| GET | `/api/v1/ExternalLogin/Google` | Initiates the OAuth challenge, redirects to Google | Public |
| GET | `/api/v1/ExternalLogin/Google/Callback` | Handles Google's callback, links or creates the account, returns an access + refresh token pair | Public |

### Tasks

- [x] `Microsoft.AspNetCore.Authentication.Google`, configured with a client id/secret from configuration
- [x] `ExternalLoginController`: initiates the challenge, handles the callback (`UserManager.GetExternalLoginInfoAsync`, `AddLoginAsync` for a new user or `FindByLoginAsync` for a returning one), issues tokens via `ITokenService` on success - an external login still goes through the exact same claims/token pipeline as a password login, no separate code path
- [ ] Tests: a first-time external sign-in creating a linked `ApplicationUser`, a returning one resolving to the existing account

## Order of work

1. `feature/core-architecture` → Pull Request to `develop`
2. `feature/identity-setup` (depends on `core-architecture`) → Pull Request to `develop`
3. `feature/rbac` (depends on `identity-setup`) → Pull Request to `develop`
4. `feature/claims-and-authorization` (depends on `rbac`) → Pull Request to `develop`
5. `feature/token-lifecycle` (depends on `claims-and-authorization`) → Pull Request to `develop`
6. `feature/auth-flows` (depends on `token-lifecycle`) → Pull Request to `develop`
7. `feature/mfa` (depends on `auth-flows`) → Pull Request to `develop`
8. `feature/audit-logging` (depends on `rbac`, can be built in parallel with `claims-and-authorization` onward) → Pull Request to `develop`
9. `feature/external-logins` (bonus, depends on `token-lifecycle`) → Pull Request to `develop`
10. `develop` → `master`

## Code conventions

- Namespace root: `DotnetIdentityTutorial`
- Routing follows the default `[Route("api/v1/[controller]")]` convention throughout, with no manual casing override - every route segment traces directly to a C# identifier
- DTOs: C# `record` types
- **Contract/implementation services**: interfaces in `Services/Interfaces`, implementations in `Services/Implementations`, including a thin wrapper around Identity's own `UserManager`/`RoleManager`/`SignInManager`
- Every successful response returns the resource directly (`ActionResult<T>`, proper status codes, pagination via response headers); every error response is a `ProblemDetails` - no custom success envelope is introduced anywhere in the API
- Every request DTO has a corresponding `FluentValidation` validator, run automatically by `ValidationFilter` - no manual `ModelState.IsValid` checks in a controller
- All timestamp and expiry logic goes through the injected `TimeProvider`, never `DateTime.UtcNow` directly, so it can be controlled in tests
- Any operation that changes a role, a permission, a role-permission assignment, or a user's lock state calls `IAuditService` - this is not optional per-endpoint, it's a property of the service layer itself
- A raw refresh token value is never logged, returned in an error message, or stored unhashed
- No code outside `Services/Implementations` calls `UserManager`/`RoleManager`/`SignInManager` directly

## Concepts covered

- ASP.NET Core Identity fundamentals, including TOTP-based MFA and external login providers
- A custom `IUserClaimsPrincipalFactory` as the single source of truth for a user's claims, including derived permissions
- Policy-based authorization beyond roles: custom `IAuthorizationRequirement`, `AuthorizationHandler<T>`, dynamic `IAuthorizationPolicyProvider`
- JWT access tokens combined with rotating, revocable refresh tokens, including reuse detection and `SecurityStamp`-based invalidation on password change
- Following ASP.NET Core's own idiom for success responses (typed results, status codes, header-based pagination) instead of a custom envelope, and .NET's native `IExceptionHandler` + `AddProblemDetails()` pipeline for RFC 9457-compliant errors
- Request validation with FluentValidation as a cross-cutting action filter, not per-controller boilerplate
- `TimeProvider` as a testability seam for anything time-dependent
- Rate limiting (`Microsoft.AspNetCore.RateLimiting`) as a defense distinct from Identity's own per-account lockout
- CORS configuration for a browser-based client
- Audit logging as a first-class service-layer concern
- Testing Identity-based authentication, claims generation, custom authorization handlers, and time-dependent logic with `FakeTimeProvider`
- Containerization (Docker, docker-compose)
- Continuous integration (GitHub Actions)

## How to follow this tutorial

1. Clone the repository and check out `develop`
2. Follow the branches in order: `feature/core-architecture` → `feature/identity-setup` → `feature/rbac` → `feature/claims-and-authorization` → `feature/token-lifecycle` → `feature/auth-flows` → `feature/mfa` → `feature/audit-logging` → (bonus) `feature/external-logins`
3. Copy `.env.example` to `.env` and fill in real values. `docker-compose.yml` expects an
   external Docker network named `pg_net` with a reachable PostgreSQL container named
   `postgres_main` on it, matching `.env.example`'s default `POSTGRES_HOST` (this keeps
   one shared Postgres instance across this author's tutorials instead of a dedicated one
   per project); create your own with `docker network create pg_net` and a `postgres:16`
   container named `postgres_main` attached to it (or add your own `postgres` service to
   `docker-compose.yml` and point `POSTGRES_HOST` in `.env` at whatever you name it
   instead, if you'd rather have compose provision it directly)
4. Run the project with `docker-compose up`, then open Swagger UI at `http://localhost:8080/swagger`
