# AGENTS.md - Compliance Auth Service

This document provides essential information for AI agents working on the compliance-auth-service project.

## Project Overview

- **Framework**: Spring Boot 4.0.0 with Java 21
- **Database**: PostgreSQL with Flyway migrations
- **Authentication**: OAuth2 Authorization Server (Spring Security)
- **API Documentation**: SpringDoc OpenAPI 3 (Swagger UI)
- **Build Tool**: Maven

## Build, Test, and Run Commands

### Basic Commands

```bash
# Clean and compile
mvn clean compile

# Run tests
mvn test

# Run a single test class
mvn test -Dtest=UserRepositoryIT

# Run a single test method
mvn test -Dtest=UserRepositoryIT#shouldSaveAndFindUser

# Package application (creates JAR)
mvn clean package

# Run application locally
mvn spring-boot:run
```

### Test Containers Integration Tests

Integration tests use TestContainers with PostgreSQL. The base class `AbstractIntegrationTest` provides container configuration:

```bash
# Run all integration tests
mvn test -Dtest="*IT"

# Run specific integration test
mvn test -Dtest=UserRepositoryIT

# Skip tests
mvn clean package -DskipTests
```

### Docker Commands

```bash
# Build Docker image
docker build -t compliance-auth-service .

# Run with Docker Compose (includes PostgreSQL)
docker-compose up -d

# View logs
docker-compose logs -f auth-service

# Stop services
docker-compose down
```

### Database Migrations

Flyway manages database migrations automatically when the application starts. Manual commands:

```bash
# Validate migrations (during application startup)
# Configured in application.yaml: spring.flyway.enabled=true

# Check migration status via actuator (if enabled)
curl http://localhost:9091/actuator/flyway
```

## Code Style Guidelines

### Package Structure

```
src/main/java/com/trustflow/compliance_auth_service/
├── config/           # Configuration classes
├── controller/       # REST controllers
├── domain/          # JPA entities
├── dto/             # Data Transfer Objects
├── repository/      # Spring Data repositories
└── service/         # Business logic services
```

### Naming Conventions

- **Classes**: PascalCase (UserController, TokenService)
- **Methods**: camelCase (getUserById, createUser)
- **Variables**: camelCase (userRepository, tokenService)
- **Constants**: UPPER_SNAKE_CASE (MAX_RETRY_COUNT)
- **Database Tables**: snake_case (users, user_roles)
- **Column Names**: snake_case (first_name, is_first_login)

### Import Organization

Group imports in this order:
1. Java standard library imports
2. Third-party library imports
3. Project-specific imports

Use explicit imports (avoid wildcards `*`).

### Entity and DTO Patterns

**Entities** (JPA):
- Use `@Entity`, `@Table`, `@Column` annotations
- Lombok annotations: `@Getter`, `@Setter`, `@NoArgsConstructor`, `@AllArgsConstructor`, `@Builder`
- Implement `equals()` and `hashCode()` using database ID (if needed)
- Use `@CreationTimestamp` and `@UpdateTimestamp` for audit fields

Example:
```java
@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true, length = 100)
    private String username;
    
    // ... other fields
}
```

**DTOs** (Data Transfer Objects):
- Use Lombok `@Data` or `@Getter`/`Setter`
- For builder pattern: `@Builder`, `@NoArgsConstructor`, `@AllArgsConstructor`
- Use `@JsonProperty` for JSON field naming
- No business logic in DTOs

Example:
```java
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenResponse {
    @JsonProperty("access_token")
    private String accessToken;
    
    @JsonProperty("refresh_token")
    private String refreshToken;
    
    @JsonProperty("token_type")
    private String tokenType = "Bearer";
}
```

### Service Layer

- **Interface/Implementation pattern**: Define interface, then implement
- Use `@Service` annotation on implementations
- Use `@Transactional` for database operations
- Inject dependencies via constructor (`@RequiredArgsConstructor`)
- Logging with SLF4J: `private static final Logger log = LoggerFactory.getLogger(ClassName.class)`

Example:
```java
public interface UserService {
    UserDto findById(Long id);
    UserDto create(UserDto userDto);
    // ...
}

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    @Override
    @Transactional
    public UserDto create(UserDto userDto) {
        log.info("Creating user: {}", userDto.getEmail());
        // ... implementation
    }
}
```

### Controller Guidelines

- Use `@RestController` with `@RequestMapping` at class level
- Keep controllers thin - delegate to services
- Use `@Operation` for OpenAPI documentation (keep concise)
- Use `@PreAuthorize` for method-level security
- Return `ResponseEntity<T>` for HTTP responses
- Use appropriate HTTP status codes:
  - `200 OK` for successful GET/PUT
  - `201 Created` for successful POST
  - `204 No Content` for successful DELETE
  - `400 Bad Request` for validation errors
  - `401 Unauthorized` for authentication failures
  - `403 Forbidden` for authorization failures
  - `404 Not Found` for missing resources
  - `409 Conflict` for duplicate resources (e.g., duplicate email)

Example:
```java
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Tag(name = "User Management")
@SecurityRequirement(name = "Bearer Authentication")
public class UserController {
    private final UserService userService;
    
    @Operation(summary = "Get user by ID")
    @PreAuthorize("hasAnyRole('SUPERVISOR', 'EXECUTIVE')")
    @GetMapping("/{id}")
    public ResponseEntity<UserDto> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(userService.findById(id));
    }
}
```

### Error Handling

- Use `@ControllerAdvice` with `@ExceptionHandler` for global exception handling
- Create custom exceptions extending `RuntimeException`
- Use `@ResponseStatus` for HTTP status mapping
- Return consistent error response format:

```java
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(DuplicateEmailException.class)
    public ResponseEntity<ErrorResponse> handleDuplicateEmail(DuplicateEmailException ex) {
        ErrorResponse error = new ErrorResponse(ex.getMessage(), "DUPLICATE_EMAIL");
        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }
}

@Data
@AllArgsConstructor
public class ErrorResponse {
    private String message;
    private String code;
}
```

### Security Implementation

- OAuth2 Authorization Server configuration in `AuthorizationServerConfig`
- JWT token generation and validation
- Role-based access control with `@PreAuthorize`
- Password encoding with BCrypt
- CORS configuration for trusted origins

### Testing Guidelines

**Unit Tests**:
- Test service layer in isolation
- Mock dependencies with Mockito
- Use `@ExtendWith(MockitoExtension.class)`

**Integration Tests**:
- Extend `AbstractIntegrationTest` for TestContainers setup
- Use `@DataJpaTest` for repository tests
- Use `@SpringBootTest` with `@AutoConfigureMockMvc` for controller tests
- Test real database interactions
- Clean up test data after each test

**Test Naming**:
- Use descriptive method names: `shouldSaveAndFindUser()`, `loginShouldReturnTokens()`
- Follow Given-When-Then pattern in test comments
- Use AssertJ for fluent assertions: `assertThat(actual).isEqualTo(expected)`

## API Endpoints

### Authentication (`/api/auth`)
- `POST /api/auth/login` - User login (returns tokens)
- `POST /api/auth/register` - User registration (new)
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/revoke` - Revoke token
- `GET /api/auth/validate` - Validate token

### User Management (`/api/users`)
- `GET /api/users` - Get all users (EXECUTIVE only)
- `GET /api/users/{id}` - Get user by ID (SUPERVISOR+)
- `POST /api/users` - Create user (EXECUTIVE only)
- `PUT /api/users/{id}` - Update user (SUPERVISOR+)
- `DELETE /api/users/{id}` - Delete user (EXECUTIVE only)
- `GET /api/users/me` - Get current user

### Token Management (`/api/tokens`)
- `GET /api/tokens/info` - Get token information
- `POST /api/tokens/revoke-all/{username}` - Revoke all user tokens (EXECUTIVE only)

## Database Schema

Key tables:
- `users` - User accounts with profile information
- `roles` - Available roles (MANAGER, SUPERVISOR, EXECUTIVE)
- `user_roles` - User-role mapping
- `oauth2_registered_client` - OAuth2 client configurations
- `oauth2_authorization` - Token storage

Migration files in `src/main/resources/db/migration/`:
- `V1__init_schema.sql` - Initial schema and seed data
- `V2__add_user_profile_fields.sql` - Added firstName, lastName, departmentId, isFirstLogin

## Development Workflow

1. **Create migration** for schema changes in `db/migration/V{version}__{description}.sql`
2. **Update JPA entities** to match schema
3. **Create/update DTOs** for API contracts
4. **Implement service layer** with business logic
5. **Add controller endpoints** with proper validation and security
6. **Write tests** (unit and integration)
7. **Run tests**: `mvn test`
8. **Verify API** via Swagger UI: `http://localhost:9091/swagger-ui.html`

## Common Issues and Solutions

### Lombok not working in IDE
- Ensure Lombok plugin is installed in IDE
- Enable annotation processing in IDE settings
- Run `mvn clean compile` to regenerate classes

### TestContainers timeout
- Increase timeout in test configuration
- Check Docker daemon is running
- Use `.withReuse(true)` for faster test cycles

### Flyway migration errors
- Check migration SQL syntax
- Ensure database user has necessary permissions
- Verify migration version numbers are sequential

### OAuth2 token issues
- Verify client configuration in `application.yaml`
- Check token expiration settings
- Validate JWT signature configuration

## Environment Configuration

- `application.yaml` - Main configuration
- `application-docker.yaml` - Docker-specific overrides
- Default port: 9091
- Database: PostgreSQL on localhost:5432 (auth_db)

## Monitoring and Health

Actuator endpoints (if enabled):
- `GET /actuator/health` - Application health status
- `GET /actuator/info` - Application information
- `GET /actuator/metrics` - Application metrics
- `GET /actuator/prometheus` - Prometheus metrics format

Health endpoint requires EXECUTIVE role (configured in application.yaml).

## Notes for AI Agents

- Always follow existing patterns and conventions
- Check similar files for implementation examples
- Run tests before making changes
- Use Lombok annotations consistently
- Maintain separation of concerns (controller/service/repository)
- Add appropriate logging (info for business events, error for exceptions)
- Handle edge cases and validate inputs
- Consider security implications of changes
- Update documentation when changing APIs