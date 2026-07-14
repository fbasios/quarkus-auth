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
import org.grnet.endpoint.scanner.runtime.entitlements.qualifiers.ExternalSystemAuthorization;

import java.util.List;
import java.util.Map;

public class ResourceAuthorizationServiceWithoutPersistence implements ResourceAuthorizationService {

    @Inject
    @ExternalSystemAuthorization
    ResourceAuthorizationService externalSystemService;

    @Override
    public PageResource<EndpointMetadata> getSecuredEndpointsByPage(int page, int size, UriInfo uriInfo) {
        return externalSystemService.getSecuredEndpointsByPage(page, size, uriInfo);
    }

    @Override
    public PageResource<ApiResourceMetadata> getApiResourcesByPage(int page, int size, UriInfo uriInfo) {
        return externalSystemService.getApiResourcesByPage(page, size, uriInfo);
    }

    @Override
    public List<RoleResponse> getAllRoles() {
        return externalSystemService.getAllRoles();
    }

    @Override
    public PageResource<RoleResponse> getAllRolesByPageAndSize(int page, int size, UriInfo uriInfo) {
        return externalSystemService.getAllRolesByPageAndSize(page, size, uriInfo);
    }

    @Override
    public Object assignRoleToUser(AssignRoleRequest request) {
        return externalSystemService.assignRoleToUser(request);
    }

    @Override
    public InformativeResponse revokeRoleFromUser(RevokeRoleRequest request) {
        return externalSystemService.revokeRoleFromUser(request);
    }

    @Override
    public void createNewRole(CreateRoleRequest request) {
        externalSystemService.createNewRole(request);
    }

    @Override
    public UserProfileDto getUserProfile() {
        return externalSystemService.getUserProfile();
    }

    @Override
    public void assignUserTheMemberRole() {
        externalSystemService.assignUserTheMemberRole();
    }

    @Override
    public void updateRoleAttributes(String role, Map<String, List<String>> attributes) {
        externalSystemService.updateRoleAttributes(role, attributes);
    }

    @Override
    public void authorize(ResourceAuthorization re) {
        externalSystemService.authorize(re);
    }

    @Override
    public List<ResourceAuthorization> findByEndpointSecuredEndpointId(String securedEndpointId) {
        return externalSystemService.findByEndpointSecuredEndpointId(securedEndpointId);
    }

    @Override
    public List<ResourceAuthorization> findAllResourcesAuthorization() {
        return externalSystemService.findAllResourcesAuthorization();
    }

    @Override
    public void delete(Long id) {
        externalSystemService.delete(id);
    }

    @Override
    public ResourceAuthorization findById(Long id) {
        return externalSystemService.findById(id);
    }

    @Override
    public void updateRule(Long id, String rule) {
        externalSystemService.updateRule(id, rule);
    }

    @Override
    public PageResource<GroupUserResponse> getAllMembersByPageAndSize(int page, int size, String search, String resource, UriInfo uriInfo) {
        return externalSystemService.getAllMembersByPageAndSize(page, size, search, resource, uriInfo);
    }

    @Override
    public Map<String, List<UserGroupInfoDto>> mapMemberships(List<Entitlement> entitlements) {
        return externalSystemService.mapMemberships(entitlements);
    }

    @Override
    public Map<String, List<UserGroupInfoDto>> mapMemberships(List<Entitlement> entitlements, Map<String, Group> groups) {
        return externalSystemService.mapMemberships(entitlements, groups);
    }

    @Override
    public void init() {
        externalSystemService.init();
    }
}
