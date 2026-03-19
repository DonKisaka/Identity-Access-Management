# Identity & Access Management System

A production-ready Identity and Access Management (IAM) microservice built with Spring Boot 4. It provides centralized authentication, fine-grained authorization, and audit logging — the kind of service that sits at the foundation of any multi-service architecture.

## The Problem

Most applications need the same core identity infrastructure: user registration, secure login, role-based access control, password recovery, and an audit trail. Building this ad-hoc inside each service leads to inconsistent security policies, duplicated logic, and blind spots in compliance. This project extracts all of that into a single, well-tested service with a clean REST API.

Specific challenges this system addresses:

- **Token security** — Stateless JWTs are convenient but hard to revoke. A stolen refresh token can silently grant long-lived access.
- **Brute-force protection** — Without rate limiting at the identity layer, credential-stuffing attacks go unchecked.
- **Permission sprawl** — Simple role checks (`isAdmin`) don't scale. As features multiply, you need resource-level permissions that can be composed into roles.
- **Audit compliance** — Knowing *who did what and when* is a regulatory requirement in many domains, not an afterthought.

## Architectural Decisions

### Stateless JWT with Server-Side Refresh Token Rotation

Access tokens are short-lived, stateless JWTs (HS256). They carry the user's authorities in their claims so downstream services can authorize requests without a round-trip to this service. Refresh tokens, however, are **not** stored as plain JWTs — only their SHA-256 hash is persisted. This means a database breach does not directly expose usable tokens.

Refresh tokens implement **rotation with reuse detection**. Each time a refresh token is used, it is marked as replaced and a new one is issued. If the old token is ever presented again, the system assumes theft and **revokes all tokens for that user**. This is modeled via the `replaceBy` self-referential relationship on the `RefreshToken` entity, giving a full chain-of-custody for every token lineage.

### Resource–Action Permission Model

Rather than hard-coding role checks, the system uses a two-dimensional permission scheme: `resource:action` (e.g., `users:delete`, `audit:export`). Permissions are assigned to roles, and roles are assigned to users — classic RBAC, but with enough granularity to express real-world access policies. Spring Security's `@PreAuthorize` annotations enforce these at the method level.

Five default roles form a hierarchy of increasing privilege:

| Role | Scope |
|------|-------|
| `USER` | Self-service profile access |
| `MODERATOR` | User oversight + audit read |
| `MANAGER` | User/role management + audit export |
| `ADMIN` | Full system administration |
| `SUPER_ADMIN` | Unrestricted (receives all permissions) |

This hierarchy is seeded by `DataInitializer` on first startup but is fully extensible — new permissions and roles can be created at runtime through the API.

### Account Protection

Failed login attempts are tracked per user. After 5 consecutive failures, the account is automatically locked and an audit event is recorded. Administrators can unlock accounts through a dedicated endpoint. Accounts can also be manually disabled/enabled. Both states (`isLocked`, `enabled`) are checked on every authentication attempt before credentials are even verified, so locked or disabled accounts get a fast, clear rejection.

### Audit Logging

Every security-significant action (signup, login, logout, failed login, account lock) is recorded with the acting user, IP address, action type, status, and severity. Audit logs are queryable by user and by date range. This provides the forensic trail needed for incident response and compliance reporting.

### Structured Exception Handling

All exceptions funnel through a single `@RestControllerAdvice` handler that maps them to a consistent `ApiError` JSON envelope:

```json
{
  "path": "/api/v1/auth/login",
  "message": "Invalid username or password",
  "errorCode": "BAD_CREDENTIALS",
  "statusCode": 401,
  "timestamp": "2026-03-19T10:30:00",
  "validationErrors": null
}
```

Custom exceptions extend a `BaseException` that carries its own HTTP status and error code. This keeps controller code clean — services throw domain exceptions, and the handler translates them into the right HTTP response. Validation errors (from Jakarta Bean Validation) are returned with per-field detail.

### Password Reset Flow

Password reset uses a one-time token model. Calling `/forgot` generates a hashed token linked to the user. Calling `/reset` with that token and a new password completes the reset and invalidates all outstanding reset tokens for that user. The token has a configurable TTL and cannot be reused. The system also supports authenticated password change via `/change`, which requires the old password.

### MapStruct for Object Mapping

DTOs are Java records (immutable by design). Mapping between entities and DTOs is handled by MapStruct, which generates type-safe mapping code at compile time. This avoids the runtime reflection overhead and hidden bugs of alternatives like ModelMapper, and makes mapping logic easy to find and debug.

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Framework | Spring Boot 4.0.1 | Mature ecosystem, production-proven security integration |
| Language | Java 25 | Latest LTS features (records, pattern matching, virtual threads support) |
| Database | PostgreSQL 18 | ACID compliance, mature JSONB support, battle-tested at scale |
| ORM | Spring Data JPA / Hibernate | Reduces boilerplate, handles schema generation in dev |
| Security | Spring Security + jjwt 0.13 | Industry-standard auth framework + dedicated JWT library |
| Validation | Jakarta Bean Validation | Declarative constraints co-located with DTOs |
| Mapping | MapStruct 1.6 | Compile-time type-safe mapping, no runtime reflection |
| Build | Maven | Reproducible builds, well-supported in CI/CD |
| Testing | JUnit 5 + Mockito + H2 | Unit tests with mocks, repository tests with in-memory DB |

## Project Structure

```
src/main/java/.../
├── config/                  # Security, JWT, CORS, data seeding
│   ├── SecurityConfig       # Filter chain, session policy, public endpoints
│   ├── JwtService           # Token generation, validation, claim extraction
│   ├── JwtAuthenticationFilter  # Per-request JWT verification
│   ├── ApplicationConfig    # UserDetailsService, BCrypt encoder, AuthManager
│   ├── CorsProperties       # Externalized CORS origin config
│   └── DataInitializer      # Seeds permissions, roles, and default users
├── controller/              # REST endpoints (7 controllers)
├── dto/                     # Request/response records (13 DTOs)
├── exception/               # BaseException, ApiError, handler, 8 custom exceptions
├── mapper/                  # MapStruct interfaces (4 mappers)
├── model/                   # JPA entities (User, Role, Permission, AuditLog,
│                            #   RefreshToken, PasswordResetToken)
├── repository/              # Spring Data JPA repositories (6)
└── service/                 # Business logic (7 services)
```

## API Reference

### Authentication (`/api/v1/auth`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/signup` | No | Register a new user |
| POST | `/login` | No | Authenticate and receive tokens |
| POST | `/refresh` | No | Exchange refresh token for new token pair |
| POST | `/logout` | No | Revoke a specific refresh token |
| POST | `/logout-all` | Yes | Revoke all refresh tokens for the authenticated user |

### Users (`/api/v1/users`)

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/me` | `profile:read` | Get authenticated user's profile |
| GET | `/{username}` | `users:read` | Get user by username |
| GET | `/` | `users:read` | List users (paginated) |
| POST | `/{userId}/unlock` | `users:manage` | Unlock a locked account |
| POST | `/{userId}/disable` | `users:manage` | Disable a user account |
| POST | `/{userId}/enable` | `users:manage` | Enable a user account |

### Roles (`/api/v1/roles`)

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/` | `roles:read` | List all roles |
| GET | `/{id}` | `roles:read` | Get role by ID |
| GET | `/name/{name}` | `roles:read` | Get role by name |
| POST | `/` | `roles:create` | Create a new role |
| POST | `/{roleName}/permissions/{permissionId}` | `roles:update` | Add permission to role |

### Permissions (`/api/v1/permissions`)

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/` | `permissions:read` | List all permissions |
| POST | `/` | `permissions:create` | Create a new permission |

### Authorization (`/api/v1/authorization`)

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| POST | `/users/{userId}/roles/{roleName}` | `roles:assign` | Assign role to user |
| DELETE | `/users/{userId}/roles/{roleName}` | `roles:assign` | Remove role from user |
| GET | `/users/{userId}/roles` | `roles:read` | Get user's roles |

### Password (`/api/v1/password`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/forgot` | No | Request a password reset token |
| POST | `/reset` | No | Reset password using token |
| POST | `/change` | Yes (`profile:password`) | Change password (requires old password) |

### Audit Logs (`/api/v1/audit-logs`)

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/user/{userId}` | `audit:read` | Get audit logs for a user |
| GET | `/date-range` | `audit:read` | Get audit logs within a date range |

## Getting Started

### Prerequisites

- Java 25+
- Maven 3.9+
- PostgreSQL 18+ (or Docker)

### Run with Docker Compose

```bash
docker compose up --build
```

This starts PostgreSQL and the application on port `8080`. The database is automatically created and seeded with default users.

### Run Locally

1. Start a PostgreSQL instance on `localhost:5432` with database `identity_system`
2. Run the application:

```bash
./mvnw spring-boot:run
```

The app starts on port `8082` by default (local profile).

### Default Users

| Username | Password | Role |
|----------|----------|------|
| `superadmin` | `SuperAdmin@123!` | SUPER_ADMIN |
| `admin` | `Admin@123!` | ADMIN |
| `manager` | `Manager@123!` | MANAGER |
| `moderator` | `Moderator@123!` | MODERATOR |

> **Change these passwords immediately in any non-development environment.**

## Configuration

The application uses Spring profiles for environment-specific configuration:

| Profile | Database | Port | Use Case |
|---------|----------|------|----------|
| default | `localhost:5432` | 8082 | Local development |
| `docker` | `postgres-db:5432` | 8080 | Docker Compose |
| `prod` | env vars | env var | Production deployment |

Key environment variables for production:

| Variable | Description |
|----------|-------------|
| `SPRING_DATASOURCE_URL` | JDBC connection string |
| `SPRING_DATASOURCE_USERNAME` | Database username |
| `SPRING_DATASOURCE_PASSWORD` | Database password |
| `JWT_SECRET` | HMAC signing key (min 256 bits) |
| `JWT_ACCESS_TOKEN_EXPIRATION` | Access token TTL in ms (default: 86400000) |
| `JWT_REFRESH_TOKEN_EXPIRATION` | Refresh token TTL in ms (default: 604800000) |
| `APP_CORS_ALLOWED_ORIGINS` | Comma-separated allowed origins |

## Testing

Tests use an H2 in-memory database with `create-drop` DDL strategy.

```bash
./mvnw test
```

**Repository tests** (`@DataJpaTest`) verify query methods, custom queries, and entity relationships against a real (in-memory) database. **Service tests** (`@ExtendWith(MockitoExtension.class)`) mock the repository layer and verify business logic in isolation — edge cases like token reuse detection, account locking thresholds, and permission resolution are all covered here.

## Deployment

A multi-stage Dockerfile is provided:

- **Build stage**: Eclipse Temurin 25 JDK Alpine, downloads dependencies first (layer caching), then builds the JAR
- **Runtime stage**: Eclipse Temurin 25 JRE Alpine, runs as non-root `spring` user, includes a health check against `/actuator/health`
- JVM is configured with container-aware memory settings (`-XX:+UseContainerSupport`, `MaxRAMPercentage=75%`)

Azure deployment instructions are available in `azure/DEPLOYMENT.md`.
