# Subagent Development Patterns

This document outlines effective patterns for delegating development tasks to subagents (specialized AI assistants) for complex software projects. These patterns were successfully used in the Claudy project to implement 6 phases with 66 test cases and 100% pass rate.

## Overview

Subagent delegation allows breaking down complex development tasks into focused, manageable units that can be implemented by specialized assistants. This approach provides:

- **Focused Expertise**: Each subagent specializes in specific components
- **Parallel Development**: Multiple phases can be worked on simultaneously
- **Quality Consistency**: Standardized templates ensure consistent output
- **Reduced Context**: Smaller, focused tasks are easier to manage
- **Testable Units**: Each delegation produces testable, complete components

## Core Delegation Principles

### 1. Complete Phase Assignment
- **Delegate entire phases, not partial work**
- Each subagent receives a complete, self-contained development unit
- Phases should have clear boundaries and minimal dependencies
- Include all requirements: implementation, tests, documentation

### 2. Comprehensive Context Provision
- **Provide full context for each delegation**
- Include previous phase results and current system state
- Reference relevant PRD requirements and constraints
- Specify integration points with existing components

### 3. Test-Driven Requirements with Human Validation
- **Mandate TDD approach explicitly** with human validation checkpoints
- Require tests to be written before implementation WITH human approval
- Specify exact number and types of tests needed
- Include both happy path and comprehensive edge cases
- **ENFORCE single-test implementation cycle** with validation after each test
- **REQUIRE human approval** before proceeding between tests

### 4. Standardized Reporting
- **Require consistent reporting format**
- Implementation summary with key features
- Test results with pass/fail statistics
- Performance metrics and benchmarks
- Integration points and dependencies

## Subagent Task Template

### Standard Template Structure
```markdown
I need you to implement Phase X of the [component] system for [project].

Context: [Previous phases completed, current system state, dependencies]

Your task is to implement comprehensive [component] with test-driven development:

**Tests to implement (all in [file path]):**

Happy Path Tests:
1. [Test name] - [Description]
2. [Test name] - [Description]

Edge Cases & Error Tests:
3. [Test name] - [Description]
[... 7-10 comprehensive edge cases covering:]
- Error conditions and failure modes
- Security validation scenarios
- Boundary conditions and limits
- Concurrency and race conditions
- Resource exhaustion scenarios
- Input validation and sanitization
- External dependency failures

**Implementation requirements:**
- [Specific technical requirements]
- **MANDATORY**: Follow TDD methodology from @docs/TDD_METHODOLOGY.md
- **CRITICAL**: Present ALL planned tests for human approval before ANY implementation
- **REQUIRED**: Implement ONE test at a time with human validation after each RED-GREEN-REFACTOR cycle
- **STOP**: Request human approval before proceeding to next test
- Handle all error cases gracefully without panics
- [Security/integration/performance requirements]
- Use mocks for external dependencies (specify what to mock)
- Include proper error handling and logging

**Key behaviors to test:**
- [Specific behaviors and scenarios to validate]
- [Security requirements to verify]
- [Performance characteristics to measure]
- [Integration points to validate]

**[Component] Requirements (from PRD):**
- [Specific PRD requirements this phase addresses]
- [Security requirements to implement]
- [Performance targets to meet]

**IMPLEMENTATION PROCESS:**
1. **FIRST**: Present complete test plan for human approval
2. **THEN**: Implement ONE test at a time following TDD methodology
3. **AFTER EACH TEST**: Request human validation using the format from @docs/TDD_METHODOLOGY.md
4. **ONLY PROCEED**: After receiving explicit human approval for each test
5. **NEVER**: Implement multiple tests without validation checkpoints

**VALIDATION REQUIREMENTS:**
- Use the validation request template from @docs/TDD_METHODOLOGY.md
- Show test code, implementation code, and results for each cycle
- Wait for explicit "proceed" or "approved" response
- Address any human feedback before continuing

Return a summary of what was implemented and the test results ONLY after completing the full validation cycle for all tests.
```

## Successful Phase Examples

### Phase 1: JWT Authentication
```markdown
I need you to implement Phase 1 of the JWT authentication system for Claudy.

Context: You're working on a Go-based backend service for remote Claude Code access. The project structure is already created with internal/auth directory available.

Your task is to implement comprehensive JWT authentication with test-driven development:

**Tests to implement (all in internal/auth/jwt_test.go):**

Happy Path Tests:
1. `TestJWTTokenGeneration` - Generate valid JWT with user claims
2. `TestJWTTokenValidation` - Validate JWT and extract claims

Edge Cases & Error Tests:
3. `TestJWTGenerationWithMissingSigningKey` - Handle missing/corrupt signing keys
4. `TestJWTValidationWithTamperedToken` - Reject modified tokens
5. `TestJWTValidationWithExpiredToken` - Reject expired tokens
6. `TestJWTValidationWithMalformedToken` - Reject invalid format tokens
7. `TestJWTValidationWithWrongSigningAlgorithm` - Reject HS256/none algorithms
8. `TestConcurrentTokenGeneration` - Handle race conditions in token creation
9. `TestTokenGenerationWithInvalidUserData` - Handle nil/empty user claims

**Implementation requirements:**
- Use github.com/golang-jwt/jwt/v5 for JWT handling
- Follow TDD: Write failing tests first, then implement minimal code to pass
- Create JWT service in internal/auth/jwt.go
- Use RS256 signing algorithm (as specified in PRD)
- Handle all error cases gracefully without panics
- Include proper logging for security events
- User claims should include: UserID, GitHubID, Username, ExpiresAt

Return a summary of what was implemented and the test results.
```

**Result**: Successfully implemented with 9 test cases, RS256 security, concurrent safety

### Phase 3: WebSocket Management
```markdown
I need you to implement Phase 3 of the WebSocket connection management system for Claudy.

Context: You're working on a Go-based backend service for remote Claude Code access. Phase 1 (JWT authentication) and Phase 2 (User management) are already completed. Now we need WebSocket connection management functionality.

**Tests to implement (all in internal/websocket/handler_test.go):**

Happy Path Tests:
1. `TestWebSocketConnectionEstablishment` - Successful connection upgrade
2. `TestWebSocketJWTAuthentication` - Valid JWT authentication

Edge Cases & Error Tests:
3. `TestWebSocketConnectionWithoutJWT` - Reject unauthenticated connections
4. `TestWebSocketConnectionWithExpiredJWT` - Handle expired tokens during connection
5. `TestWebSocketMessageBeforeAuthentication` - Reject premature messages
6. `TestWebSocketConnectionDropDuringAuthentication` - Handle connection loss
7. `TestWebSocketMalformedMessageHandling` - Handle invalid JSON/message format
8. `TestWebSocketMaxConnectionsPerUser` - Enforce connection limits
9. `TestWebSocketRedisUnavailableDuringConnection` - Handle Redis failures
10. `TestWebSocketConcurrentConnectionsFromSameUser` - Handle multiple tabs/devices
11. `TestWebSocketOriginValidation` - Reject connections from unauthorized origins
12. `TestWebSocketConnectionCleanupOnProcessExit` - Handle ungraceful shutdowns

**Implementation requirements:**
- Use github.com/gorilla/websocket for WebSocket handling
- Create WebSocket handler in internal/websocket/handler.go
- Follow TDD: Write failing tests first, then implement minimal code to pass
- Handle all error cases gracefully without panics
- Include proper authentication flow using existing JWT service
- Mock Redis operations for testing (don't use real Redis yet)
- Implement proper connection cleanup and resource management

Return a summary of what was implemented and the test results.
```

**Result**: Successfully implemented with 12 test cases, Redis integration, connection limits

## Task Delegation Strategies

### 1. Phase Grouping Strategy
Group related phases for logical delegation:

**Group 1: Core Infrastructure (Phases 1-3)**
- Phase 1: Authentication (JWT)
- Phase 2: User Management
- Phase 3: WebSocket Handling

**Group 2: Business Logic (Phases 4-6)**
- Phase 4: Claude Code Integration
- Phase 5: File Management
- Phase 6: Integration Testing

### 2. Dependency Management
Structure phases to minimize dependencies:

```
Phase 1 (JWT) → Independent, foundational
    ↓
Phase 2 (Users) → Depends on JWT for authentication
    ↓
Phase 3 (WebSocket) → Depends on JWT + Users
    ↓
Phase 4 (Claude) → Depends on all previous
    ↓
Phase 5 (Files) → Depends on WebSocket + Claude
    ↓
Phase 6 (Integration) → Tests all components together
```

### 3. Parallel Development
Enable parallel work by creating independent branches:

```bash
# Phase Group 1 (can work in parallel with Group 2 planning)
git checkout -b feature/websocket-phase3

# Phase Group 2 (starts after Group 1 completion)
git checkout -b feature/claude-code-phase4
```

## Quality Assurance Patterns

### 1. Validation Requirements
Each subagent must deliver:
- **Complete test suite** with specified number of tests
- **100% test pass rate** before submission
- **Comprehensive edge case coverage** including error scenarios
- **Security validation** for all security-sensitive components
- **Performance benchmarks** for critical operations
- **Integration verification** with existing components

### 2. Reporting Standards
Standardized reporting format:

```markdown
## Summary
[Brief description of what was implemented]

### Files Created/Modified
- [List of files with brief descriptions]

### Test Results
- [X] tests passing ([detailed breakdown])
- [Performance metrics]
- [Security validations completed]

### Key Features Implemented
- [Bulleted list of major features]
- [Security implementations]
- [Error handling capabilities]

### Integration Points
- [How it integrates with existing components]
- [Dependencies satisfied]
- [Interfaces provided for future components]
```

### 3. Acceptance Criteria
Before accepting subagent deliverables:
- [ ] All specified tests implemented and passing
- [ ] Edge cases comprehensively covered
- [ ] Security requirements validated
- [ ] Performance benchmarks meet requirements
- [ ] Integration with existing components verified
- [ ] Error handling tested and verified
- [ ] Documentation complete and accurate

## Common Delegation Antipatterns

### ❌ Don't: Partial Task Assignment
```markdown
"Help me implement user authentication"
```
**Problem**: Too vague, unclear scope, missing context

### ✅ Do: Complete Phase Assignment
```markdown
"Implement Phase 1 of JWT authentication system with 9 specified tests including token generation, validation, and comprehensive edge cases"
```

### ❌ Don't: Missing Context
```markdown
"Create WebSocket handler"
```
**Problem**: No context about existing system, integration points

### ✅ Do: Full Context Provision
```markdown
"Implement Phase 3 WebSocket management. Context: JWT auth (Phase 1) and User management (Phase 2) completed. Need integration with existing JWT service and Redis state management."
```

### ❌ Don't: Vague Testing Requirements
```markdown
"Include some tests"
```
**Problem**: Unclear expectations, likely inadequate coverage

### ✅ Do: Specific Test Requirements
```markdown
"Implement 12 test cases: 2 happy path + 10 edge cases covering authentication failures, connection drops, malformed messages, Redis failures, origin validation, and graceful shutdown"
```

## Advanced Patterns

### 1. Multi-Agent Coordination
For complex systems, coordinate multiple agents:

```markdown
Agent A: Phases 1-3 (Infrastructure)
Agent B: Phases 4-6 (Business Logic)
Agent C: Integration Testing and Documentation
```

### 2. Iterative Refinement
Use subagents for iterative improvement:

```markdown
Round 1: Basic implementation
Round 2: Performance optimization
Round 3: Security hardening
Round 4: Error handling enhancement
```

### 3. Specialized Expertise
Assign agents based on specialization:

```markdown
Security Agent: Authentication, encryption, validation
Performance Agent: Optimization, benchmarking, profiling
Integration Agent: API design, component interfaces
Testing Agent: Comprehensive test suites, edge cases
```

## Success Metrics

The Claudy project achieved these results using subagent patterns:

- **66 test cases** implemented across 6 phases
- **100% pass rate** on all deliverables
- **Zero integration issues** between phases
- **Complete security implementation** with comprehensive validation
- **Production-ready code** with proper error handling
- **Comprehensive documentation** for each component

## Best Practices Summary

### Do:
- Assign complete, self-contained phases
- Provide comprehensive context and requirements
- Specify exact test requirements and edge cases
- Require TDD methodology explicitly
- Standardize reporting formats
- Validate all deliverables thoroughly
- Plan dependencies carefully
- Use mocks appropriately for unit tests

### Don't:
- Assign partial or unclear tasks
- Skip context provision
- Accept deliverables without full test coverage
- Allow implementation without tests first
- Skip edge case requirements
- Accept subpar error handling
- Ignore security requirements
- Mix testing strategies inappropriately

This subagent delegation methodology enables rapid, high-quality development of complex systems while maintaining consistency, security, and comprehensive testing throughout the implementation process.