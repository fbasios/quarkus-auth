package org.grnet.endpoint.scanner.runtime.entities;

import java.time.LocalDateTime;

public class RoleEndpoint {
    private Long id;
    private String roleId;
    private String roleName;
    private String securedEndpointId;
    private LocalDateTime createdAt;
    private String scope;

    public RoleEndpoint() {
    }

    public RoleEndpoint(Long id,String roleName, String roleId, String securedEndpointId, LocalDateTime createdAt, String scope) {
        this.id = id;
        this.roleId = roleId;
        this.roleName = roleName;
        this.securedEndpointId = securedEndpointId;
        this.createdAt = createdAt;
        this.scope = scope;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getRoleId() {
        return roleId;
    }

    public void setRoleId(String roleId) {
        this.roleId = roleId;
    }

    public String getSecuredEndpointId() {
        return securedEndpointId;
    }

    public void setSecuredEndpointId(String securedEndpointId) {
        this.securedEndpointId = securedEndpointId;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }
}
