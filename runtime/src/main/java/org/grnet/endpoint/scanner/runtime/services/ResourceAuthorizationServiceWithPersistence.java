package org.grnet.endpoint.scanner.runtime.services;

import jakarta.inject.Inject;
import jakarta.ws.rs.core.UriInfo;
import org.grnet.endpoint.scanner.runtime.ApiResourceMetadata;
import org.grnet.endpoint.scanner.runtime.EndpointMetadata;
import org.grnet.endpoint.scanner.runtime.clients.groupmanagement.response.Group;
import org.grnet.endpoint.scanner.runtime.clients.groupmanagement.response.GroupUserResponse;
import org.grnet.endpoint.scanner.runtime.clients.groupmanagement.response.UserGroupInfoDto;
import org.grnet.endpoint.scanner.runtime.dtos.AssignRoleRequest;
import org.grnet.endpoint.scanner.runtime.dtos.CreateRoleRequest;
import org.grnet.endpoint.scanner.runtime.dtos.RevokeRoleRequest;
import org.grnet.endpoint.scanner.runtime.dtos.RoleResponse;
import org.grnet.endpoint.scanner.runtime.dtos.UserProfileDto;
import org.grnet.endpoint.scanner.runtime.endpoints.InformativeResponse;
import org.grnet.endpoint.scanner.runtime.endpoints.PageResource;
import org.grnet.endpoint.scanner.runtime.entities.ResourceAuthorization;
import org.grnet.endpoint.scanner.runtime.entitlements.Entitlement;
import org.grnet.endpoint.scanner.runtime.entitlements.UserContextInterface;
import org.grnet.endpoint.scanner.runtime.entitlements.qualifiers.ExternalSystemAuthorization;
import org.grnet.endpoint.scanner.runtime.entitlements.qualifiers.PersistenceAuthorization;

import java.util.List;
import java.util.Map;

public class ResourceAuthorizationServiceWithPersistence implements ResourceAuthorizationService {

    @Inject
    UserContextInterface userContextInterface;

    @Inject
    @ExternalSystemAuthorization
    ResourceAuthorizationService externalSystemService;

    @Inject
    @PersistenceAuthorization
    ResourceAuthorizationService persistenceService;

    private ResourceAuthorizationService resolve() {
        if (userContextInterface.entitlementManagement().equalsIgnoreCase("database")) {
            return persistenceService;
        } else if (userContextInterface.entitlementManagement().equalsIgnoreCase("oidc")) {
            return externalSystemService;
        } else {
            return persistenceService;
        }
    }

    @Override
    public PageResource<EndpointMetadata> getSecuredEndpointsByPage(int page, int size, UriInfo uriInfo) {
        return resolve().getSecuredEndpointsByPage(page, size, uriInfo);
    }

    @Override
    public PageResource<ApiResourceMetadata> getApiResourcesByPage(int page, int size, UriInfo uriInfo) {
        return resolve().getApiResourcesByPage(page, size, uriInfo);
    }

    @Override
    public List<RoleResponse> getAllRoles() {
        return resolve().getAllRoles();
    }

    @Override
    public PageResource<RoleResponse> getAllRolesByPageAndSize(int page, int size, UriInfo uriInfo) {
        return resolve().getAllRolesByPageAndSize(page, size, uriInfo);
    }

    @Override
    public Object assignRoleToUser(AssignRoleRequest request) {
        return resolve().assignRoleToUser(request);
    }

    @Override
    public InformativeResponse revokeRoleFromUser(RevokeRoleRequest request) {
        return resolve().revokeRoleFromUser(request);
    }

    @Override
    public void createNewRole(CreateRoleRequest request) {
        resolve().createNewRole(request);
    }

    @Override
    public UserProfileDto getUserProfile() {
        return resolve().getUserProfile();
    }

    @Override
    public void assignUserTheMemberRole() {
        resolve().assignUserTheMemberRole();
    }

    @Override
    public void updateRoleAttributes(String role, Map<String, List<String>> attributes) {
        resolve().updateRoleAttributes(role, attributes);
    }

    @Override
    public void authorize(ResourceAuthorization re) {
        resolve().authorize(re);
    }

    @Override
    public List<ResourceAuthorization> findByEndpointSecuredEndpointId(String securedEndpointId) {
        return resolve().findByEndpointSecuredEndpointId(securedEndpointId);
    }

    @Override
    public List<ResourceAuthorization> findAllResourcesAuthorization() {
        return resolve().findAllResourcesAuthorization();
    }

    @Override
    public void delete(Long id) {
        resolve().delete(id);
    }

    @Override
    public ResourceAuthorization findById(Long id) {
        return resolve().findById(id);
    }

    @Override
    public void updateRule(Long id, String rule) {
        resolve().updateRule(id, rule);
    }

    @Override
    public PageResource<GroupUserResponse> getAllMembersByPageAndSize(int page, int size, String search, String resource, UriInfo uriInfo) {
        return resolve().getAllMembersByPageAndSize(page, size, search, resource, uriInfo);
    }

    @Override
    public Map<String, List<UserGroupInfoDto>> mapMemberships(List<Entitlement> entitlements) {
        return resolve().mapMemberships(entitlements);
    }

    @Override
    public Map<String, List<UserGroupInfoDto>> mapMemberships(List<Entitlement> entitlements, Map<String, Group> groups) {
        return resolve().mapMemberships(entitlements, groups);
    }

    @Override
    public void init() {
        resolve().init();
    }
}
