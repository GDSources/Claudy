# Test-Driven Development Methodology

This document outlines the comprehensive Test-Driven Development (TDD) methodology used for the Claudy project, which achieved 66 test cases with 100% pass rate and comprehensive edge case coverage.

## Core TDD Cycle

### RED → GREEN → REFACTOR Process
```
1. 🔴 RED   → Write failing tests first (test what should happen)
2. 🟢 GREEN → Implement minimal code to pass tests (make it work)
3. 🔵 REFACTOR → Improve code while keeping tests passing (make it clean)
4. 🔄 REPEAT → Continue with next feature/edge case
```

## Human Validation Requirements

**MANDATORY**: All TDD development must include human validation at critical checkpoints. Agents MUST NOT proceed without explicit human approval.

### Test Review Requirement
- **Before any implementation**: Present ALL planned tests for human review and approval
- **Test structure review**: Validate test organization, coverage, and edge cases
- **Acceptance criteria**: Confirm tests match requirements and cover all scenarios
- **No implementation without approval**: Agents must wait for explicit "proceed" instruction

### Single-Test Validation Cycle
- **After each test implementation**: Present test + implementation + refactoring for validation
- **Human checkpoint**: Request approval before proceeding to next test
- **Validation format**: Show test code, implementation code, test results, and refactoring changes
- **Iterative approval**: Each test-implement-refactor cycle requires separate approval

### Quality Validation Points
- **Test quality review**: Ensure test properly validates expected behavior
- **Implementation review**: Verify minimal, clean implementation
- **Refactoring review**: Confirm improvements don't break functionality
- **Progress validation**: Confirm overall progress aligns with requirements

## Single-Test Implementation Cycle

**CRITICAL**: Implement ONE test at a time with human validation at each step.

### Phase 1: Test Planning and Approval
1. **Define all tests** - List every test with clear descriptions
2. **Present for review** - Show complete test plan to human
3. **Wait for approval** - DO NOT proceed without explicit approval
4. **Clarify requirements** - Address any human feedback or questions

### Phase 2: Single-Test Cycle (Repeat for Each Test)
1. **🔴 RED** - Write one failing test
   - Write ONLY the current test
   - Run test to confirm it fails
   - Present test code and failure output
   - **STOP - Request approval to implement**

2. **🟢 GREEN** - Implement minimal code
   - Write minimal code to make ONLY this test pass
   - Run test to confirm it passes
   - Run all previous tests to ensure no regression
   - Present implementation code and test results
   - **STOP - Request approval to refactor**

3. **🔵 REFACTOR** - Improve code quality
   - Clean up code while keeping all tests passing
   - Run all tests to confirm no regression
   - Present refactored code and test results
   - **STOP - Request approval for next test**

4. **🔄 VALIDATE** - Human checkpoint
   - Present complete cycle results
   - Wait for approval to proceed to next test
   - Address any feedback or required changes

### Phase 3: Completion Validation
1. **Final review** - Present all implemented tests and code
2. **Integration check** - Verify all tests pass together
3. **Quality assessment** - Confirm implementation meets requirements
4. **Human sign-off** - Receive final approval for phase completion

## Phase-Based Development Structure

### Phase Planning Template
For each development phase, define:

1. **Happy Path Tests** (2-3 core scenarios)
   - Basic functionality working correctly
   - Expected normal operation flows
   - Core feature validation

2. **Edge Cases & Error Tests** (7-10 comprehensive scenarios)
   - Boundary conditions and limits
   - Error conditions and failure modes
   - Security and validation scenarios
   - Concurrency and race conditions
   - Resource exhaustion scenarios

3. **Implementation Requirements**
   - Technical specifications
   - Security requirements
   - Performance criteria
   - Integration points

## Validation Protocols

### When to Request Human Review
**MANDATORY review points:**
- Before implementing any tests (complete test plan review)
- After writing each individual test (before implementation)
- After implementing code for each test (before refactoring)
- After refactoring each test (before next test)
- Upon completion of all tests in a phase
- When encountering unexpected issues or errors
- When test requirements are unclear or ambiguous

### Validation Request Format
```markdown
## Test Validation Request

**Current Test**: [Test name and description]
**Phase**: [Current phase - RED/GREEN/REFACTOR]
**Progress**: [X of Y tests completed]

### Test Code
```go
[Show the current test code]
```

### Implementation Code (if GREEN/REFACTOR phase)
```go
[Show the minimal implementation or refactored code]
```

### Test Results
```
[Show test execution output - failures for RED, passes for GREEN/REFACTOR]
```

### Changes Made
- [Bullet points of what was implemented or refactored]

### Next Step
[What you plan to do next - implement/refactor/next test]

**Awaiting approval to proceed**
```

### Quality Criteria for Approval
**Test Quality:**
- [ ] Test clearly validates expected behavior
- [ ] Test includes proper setup and teardown
- [ ] Test has meaningful assertions
- [ ] Test covers edge cases appropriately
- [ ] Test is isolated and doesn't depend on other tests

**Implementation Quality:**
- [ ] Minimal code that makes test pass
- [ ] No unnecessary complexity
- [ ] Proper error handling
- [ ] Follows coding standards
- [ ] No breaking changes to existing functionality

**Refactoring Quality:**
- [ ] Code readability improved
- [ ] Performance maintained or improved
- [ ] All tests still pass
- [ ] No new technical debt introduced
- [ ] Architecture patterns followed

### Test Categories Per Phase

#### 1. Unit Tests
- **Purpose**: Test individual components in isolation
- **Dependencies**: All external dependencies mocked
- **Scope**: Single function/method/class behavior
- **Example**: JWT token generation with various user claims

#### 2. Integration Tests
- **Purpose**: Test component interactions with real services
- **Dependencies**: Real databases and external services
- **Scope**: Multiple components working together
- **Example**: WebSocket authentication flow with Redis state

#### 3. Security Tests
- **Purpose**: Validate security implementations
- **Dependencies**: Real crypto libraries and validation
- **Scope**: Authentication, authorization, input validation
- **Example**: Token tampering detection and rejection

#### 4. Concurrency Tests
- **Purpose**: Test thread safety and race conditions
- **Dependencies**: Multiple goroutines and shared state
- **Scope**: Concurrent access patterns
- **Example**: Multiple users connecting simultaneously

#### 5. Error Handling Tests
- **Purpose**: Validate graceful failure scenarios
- **Dependencies**: Simulated failure conditions
- **Scope**: Error recovery and cleanup
- **Example**: Database connection failures during authentication

## Comprehensive Edge Case Coverage

### Authentication (Phase 1) - 9 Tests
**Happy Path:**
- JWT token generation with valid user data
- JWT token validation and claims extraction

**Edge Cases:**
- Missing/corrupt signing keys → Handle gracefully
- Token tampering → Reject with proper error
- Expired tokens → Clear error messages
- Malformed tokens → Proper validation
- Wrong signing algorithms → Security enforcement
- Concurrent token generation → Thread safety
- Invalid user data → Input validation

### User Management (Phase 2) - 9 Tests
**Happy Path:**
- Create user from GitHub profile data
- Retrieve user by GitHub ID

**Edge Cases:**
- Malformed GitHub data → Validation and error handling
- Duplicate user creation → Conflict resolution
- Database unavailability → Graceful degradation
- Concurrent user updates → Data consistency
- Data validation limits → Boundary testing
- Invalid object IDs → Input sanitization

### WebSocket (Phase 3) - 12 Tests
**Happy Path:**
- Connection establishment and upgrade
- JWT authentication during handshake

**Edge Cases:**
- Unauthenticated connections → Security enforcement
- Expired JWT during connection → Token validation
- Messages before authentication → Protocol enforcement
- Connection drops during auth → State management
- Malformed message handling → Input validation
- Connection limits enforcement → Resource management
- Redis failures → Service degradation
- Origin validation → CORS security
- Graceful shutdown → Resource cleanup

### Claude Code Integration (Phase 4) - 13 Tests
**Happy Path:**
- Claude API token validation
- Process spawning and management

**Edge Cases:**
- Invalid API tokens → External API handling
- API unavailability → Service dependencies
- Process spawn failures → System resource handling
- Process crashes → Recovery mechanisms
- Resource exhaustion → Limit enforcement
- Workspace permission errors → Filesystem handling
- Disk space issues → Storage management
- Concurrent session conflicts → State management
- Encryption key failures → Security fallbacks

### File Management (Phase 5) - 13 Tests
**Happy Path:**
- Valid file upload and processing
- Workspace file listing

**Edge Cases:**
- File size limit exceeded → Validation enforcement
- Malicious content detection → Security scanning
- Invalid encoding → Content validation
- Nonexistent workspace → Error handling
- Disk space failures → Storage management
- Concurrent file operations → Thread safety
- Filesystem corruption → Error recovery
- Cleanup failures → Resource management

### Integration Testing (Phase 6) - 10 Tests
**Happy Path:**
- Full authentication flows with real databases
- WebSocket sessions with Redis state management
- Complete user session lifecycle

**Edge Cases:**
- Database failover scenarios → High availability
- Redis failover scenarios → State recovery
- Network partition recovery → Connectivity issues
- Resource exhaustion recovery → System limits
- Concurrent user sessions at scale → Performance
- Graceful shutdown procedures → Lifecycle management
- Corrupted session data → Data integrity

## Testing Infrastructure

### Mock Strategy
```go
// Unit Tests - Mock all external dependencies
type MockUserRepository struct {
    mock.Mock
}

func (m *MockUserRepository) CreateUser(ctx context.Context, user *User) error {
    args := m.Called(ctx, user)
    return args.Error(0)
}

// Integration Tests - Use real services with test containers
mongoContainer, _ := mongodb.RunContainer(ctx, 
    testcontainers.WithImage("mongo:7.0"),
    mongodb.WithUsername("testuser"),
    mongodb.WithPassword("testpass"),
)
```

### Test Container Usage
```go
// MongoDB Test Container
func setupMongoDB(t *testing.T) *mongo.Client {
    container, err := mongodb.RunContainer(ctx,
        testcontainers.WithImage("mongo:7.0"),
        mongodb.WithUsername("testuser"),
        mongodb.WithPassword("testpass"),
    )
    require.NoError(t, err)
    
    uri, err := container.ConnectionString(ctx)
    require.NoError(t, err)
    
    client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
    require.NoError(t, err)
    
    return client
}

// Redis Test Container
func setupRedis(t *testing.T) *redis.Client {
    container, err := redis.RunContainer(ctx,
        testcontainers.WithImage("redis:7.0-alpine"),
    )
    require.NoError(t, err)
    
    uri, err := container.ConnectionString(ctx)
    require.NoError(t, err)
    
    return redis.NewClient(&redis.Options{Addr: uri})
}
```

### Performance Benchmarking
```go
func BenchmarkJWTTokenGeneration(b *testing.B) {
    service := setupJWTService(b)
    claims := createTestUserClaims()
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := service.GenerateToken(claims, time.Hour)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

## Quality Gates

### Before Committing
- [ ] All tests pass (100% success rate)
- [ ] No panics or unhandled errors
- [ ] Security requirements validated
- [ ] Performance benchmarks met
- [ ] Integration tests with real dependencies pass
- [ ] Memory leaks checked
- [ ] Race condition testing completed

### Test Coverage Requirements
- **Unit Tests**: >90% line coverage
- **Edge Cases**: All identified failure modes tested
- **Integration**: All component interactions tested
- **Security**: All authentication/authorization paths tested
- **Performance**: All critical paths benchmarked

### Error Handling Standards
```go
// Good: Specific error handling
func (s *Service) ProcessRequest(req *Request) error {
    if err := s.validateRequest(req); err != nil {
        log.WithError(err).Error("Request validation failed")
        return fmt.Errorf("invalid request: %w", err)
    }
    
    if err := s.processRequest(req); err != nil {
        log.WithError(err).Error("Request processing failed")
        return fmt.Errorf("processing failed: %w", err)
    }
    
    return nil
}

// Bad: Generic error handling
func (s *Service) ProcessRequest(req *Request) error {
    // No validation, poor error messages
    return s.processRequest(req)
}
```

## Success Metrics Achieved

### Test Statistics
- **Total Test Cases**: 66 comprehensive tests
- **Phase Breakdown**: 6 phases with 9-13 tests each
- **Pass Rate**: 100% across all test suites
- **Edge Case Coverage**: 48 edge cases tested
- **Integration Scenarios**: 10 real-database scenarios

### Performance Results
- **JWT Generation**: ~35,315 ns/op
- **File Upload Processing**: ~12,430 ns/op
- **WebSocket Connection**: <200ms establishment
- **Database Operations**: <50ms for user queries
- **Concurrent Sessions**: 100+ users validated

### Security Validation
- **Token Security**: RS256 signing, tamper detection
- **Input Validation**: All user inputs sanitized
- **File Security**: Malicious content detection
- **Process Isolation**: Resource limits enforced
- **Data Encryption**: AES-256-GCM for sensitive data

## Best Practices

### Do:
- **Request human validation** at every mandatory checkpoint
- **Present complete test plans** before any implementation
- **Implement one test at a time** with approval between each
- **Show all code and results** in validation requests
- **Wait for explicit approval** before proceeding
- Write tests before implementation
- Test both happy path and edge cases
- Use real services for integration tests
- Mock external dependencies for unit tests
- Include performance benchmarks
- Validate security implementations
- Test concurrent scenarios
- Document test requirements clearly

### Don't:
- **Proceed without human approval** at validation checkpoints
- **Implement multiple tests** without validation between them
- **Skip validation requests** or assume approval
- **Hide failures or issues** from human reviewer
- **Rush through validation** without proper presentation
- Skip edge case testing
- Mock everything in integration tests
- Ignore performance implications
- Skip security validation
- Write tests after implementation
- Assume external services are reliable
- Ignore race conditions
- Skip error handling tests

## Agent Instructions for TDD Implementation

### MANDATORY Protocol for All Agents
1. **NEVER implement without test plan approval**
2. **ALWAYS implement one test at a time**
3. **ALWAYS request validation after each RED-GREEN-REFACTOR cycle**
4. **NEVER proceed to next test without explicit approval**
5. **ALWAYS present complete code and results in validation requests**
6. **STOP development if validation is not received**

### Validation Request Template for Agents
Use this exact format for all validation requests:

```markdown
🔴/🟢/🔵 **[PHASE] Validation Request**

**Test**: `[TestName]` ([X] of [Y] total tests)
**Status**: [RED - test written | GREEN - implementation complete | REFACTOR - code improved]

**Test Code**:
```go
[test code here]
```

**Implementation** (if GREEN/REFACTOR):
```go
[implementation code here]
```

**Results**:
```
[test execution output]
```

**Summary**: [Brief description of what was accomplished]
**Next**: [What will be done after approval]

**⏸️ Awaiting human approval to proceed**
```

### Enforcement
- Agents that proceed without validation will have their work rejected
- All validation checkpoints are mandatory, not optional
- Human approval must be explicit ("proceed", "approved", "continue")
- Silence or delay does not constitute approval

This TDD methodology ensures robust, secure, and maintainable code by systematically testing all scenarios before implementation, resulting in production-ready software with comprehensive edge case coverage.