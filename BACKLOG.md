# acme-gateway Implementation Backlog

## RFC 8555 Compliance

### Critical Issues

#### Missing Account Status Update Handler
- **Issue**: No handler for `POST /account/{id}` to process account operations
- **RFC Requirement**: RFC 8555 §7.3.8 specifies servers MUST support changing account status to "deactivated"
- **Current State**: Clients cannot deactivate accounts, violating RFC requirement
- **Impact**: Full RFC 8555 compliance requires this endpoint
- **Implementation Notes**:
  - Add `handleAccountUpdate()` handler
  - Support `POST /account/{id}` with JWS payload containing `status` field
  - Validate only "deactivated" status is allowed
  - Persist account deactivation state to database
  - Return updated account resource with new status

### Medium Priority

#### Account Key Rollover Support
- **Issue**: Key rotation endpoint (`POST /key-change`) currently returns 500 (Internal Server Error)
- **RFC Requirement**: RFC 8555 §7.3.6 specifies account key rollover support
- **Current State**: Endpoint is advertised but not implemented
- **Implementation Notes**:
  - Verify nested JWS signing (outer JWS signed with new key, inner JWS signed with old key)
  - Update account public key in database
  - Invalidate old nonces after key change

#### Certificate Revocation Enhancement
- **Issue**: Revocation may need additional validation paths
- **RFC Requirement**: RFC 8555 §7.6 specifies multiple revocation authorization methods
- **Current State**: Basic revocation implemented
- **Implementation Notes**:
  - Verify both certificate owner and account authorization paths work
  - Test revocation with different certificate chains
