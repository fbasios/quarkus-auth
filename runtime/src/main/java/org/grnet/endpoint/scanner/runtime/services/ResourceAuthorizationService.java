package org.grnet.endpoint.scanner.runtime.services;

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

import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import static java.lang.Math.min;
import static java.util.stream.Collectors.toMap;

public interface ResourceAuthorizationService {

    PageResource<EndpointMetadata> getSecuredEndpointsByPage(int page, int size, UriInfo uriInfo);
    PageResource<ApiResourceMetadata> getApiResourcesByPage(int page, int size, UriInfo uriInfo);

    List<RoleResponse> getAllRoles();
    PageResource<RoleResponse> getAllRolesByPageAndSize(int page, int size, UriInfo uriInfo);

    Object assignRoleToUser(AssignRoleRequest request);
    InformativeResponse revokeRoleFromUser(RevokeRoleRequest request);
    void createNewRole(CreateRoleRequest request);

    UserProfileDto getUserProfile();
    void assignUserTheMemberRole();
    void updateRoleAttributes(String role, Map<String, List<String>> attributes);

    void authorize(ResourceAuthorization re);
    List<ResourceAuthorization> findByEndpointSecuredEndpointId(String securedEndpointId);

    List<ResourceAuthorization> findAllResourcesAuthorization();
    void delete(Long id);
    ResourceAuthorization findById(Long id);
    void updateRule(Long id, String rule);

    PageResource<GroupUserResponse> getAllMembersByPageAndSize(int page, int size, String search, String resource, UriInfo uriInfo);

    Map<String, List<UserGroupInfoDto>> mapMemberships(List<Entitlement> entitlements);

    Map<String, List<UserGroupInfoDto>> mapMemberships(List<Entitlement> entitlements, Map<String, Group> groups);

    default  <T> Map<Integer, List<T>> partition(List<T> list, int pageSize) {
        return IntStream.iterate(0, i -> i + pageSize)
                .limit((list.size() + pageSize - 1) / pageSize)
                .boxed()
                .collect(toMap(i -> i / pageSize,
                        i -> list.subList(i, min(i + pageSize, list.size()))));
    }

    void init();
}