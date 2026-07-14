package org.grnet.endpoint.scanner.runtime.services;

import io.quarkus.cache.CacheInvalidateAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.UriInfo;
import org.apache.commons.lang3.StringUtils;
import org.grnet.endpoint.scanner.runtime.*;
import org.grnet.endpoint.scanner.runtime.clients.groupmanagement.AuthGroupManagement;
import org.grnet.endpoint.scanner.runtime.clients.groupmanagement.response.Group;
import org.grnet.endpoint.scanner.runtime.clients.groupmanagement.response.GroupUser;
import org.grnet.endpoint.scanner.runtime.clients.groupmanagement.response.GroupUserResponse;
import org.grnet.endpoint.scanner.runtime.clients.groupmanagement.response.UserGroupInfoDto;
import org.grnet.endpoint.scanner.runtime.dtos.AssignRoleRequest;
import org.grnet.endpoint.scanner.runtime.dtos.CreateRoleRequest;
import org.grnet.endpoint.scanner.runtime.endpoints.InformativeResponse;
import org.grnet.endpoint.scanner.runtime.endpoints.PageResource;
import org.grnet.endpoint.scanner.runtime.dtos.RevokeRoleRequest;
import org.grnet.endpoint.scanner.runtime.dtos.RoleResponse;
import org.grnet.endpoint.scanner.runtime.dtos.UserProfileDto;
import org.grnet.endpoint.scanner.runtime.entities.ResourceAuthorization;
import org.grnet.endpoint.scanner.runtime.entitlements.Entitlement;
import org.grnet.endpoint.scanner.runtime.entitlements.EntitlementProvider;
import org.grnet.endpoint.scanner.runtime.entitlements.EntitlementUtils;
import org.grnet.endpoint.scanner.runtime.entitlements.qualifiers.ExternalSystemAuthorization;
import org.grnet.endpoint.scanner.runtime.internal.AgmGroupCache;
import org.grnet.endpoint.scanner.runtime.repositories.ResourceAuthorizationRepository;
import org.grnet.endpoint.scanner.runtime.entities.pagination.Page;
import org.grnet.endpoint.scanner.runtime.entities.pagination.PageQueryImpl;
import org.grnet.endpoint.scanner.runtime.process.AfterProcessing;
import org.grnet.endpoint.scanner.runtime.process.BeforeProcessing;
import org.grnet.endpoint.scanner.runtime.process.Event;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import static java.lang.Math.min;
import static java.util.stream.Collectors.toMap;

@ExternalSystemAuthorization
public class OidcResourceAuthorizationService implements ResourceAuthorizationService{


    @Inject
    ResourceAuthorizationRepository repository;

    @Inject
    EndpointMetadataHolder endpointMetadataHolder;

    @Inject
    ApiResourceHolder apiResourceHolder;

    @Inject
    AuthGroupManagement authGroupManagement;

    @Inject
    jakarta.enterprise.event.Event<Event> event;

    @Inject
    Utility utility;

    @Inject
    EntitlementProvider entitlementProvider;

    @Inject
    AgmGroupCache agmGroupCache;

    private static final Logger LOG = Logger.getLogger(OidcResourceAuthorizationService.class);


    public PageResource<EndpointMetadata> getSecuredEndpointsByPage(int page, int size, UriInfo uriInfo) {

        var all = endpointMetadataHolder.getData() == null
                ? List.<EndpointMetadata>of()
                : endpointMetadataHolder.getData();

        var pages = partition(all, size);
        var content = pages.getOrDefault(page, List.of());

        var result = new PageQueryImpl<EndpointMetadata>();
        result.list = content;
        result.index = page;
        result.count = all.size();
        result.size = size;
        result.page = Page.of(page, size);

        return new PageResource<>(result, result.list, uriInfo);
    }

    public PageResource<ApiResourceMetadata> getApiResourcesByPage(int page, int size, UriInfo uriInfo) {

        var all = apiResourceHolder.getData() == null
                ? List.<ApiResourceMetadata>of()
                : apiResourceHolder.getData();

        var pages = partition(all, size);
        var content = pages.getOrDefault(page, List.of());

        var result = new PageQueryImpl<ApiResourceMetadata>();
        result.list = content;
        result.index = page;
        result.count = all.size();
        result.size = size;
        result.page = Page.of(page, size);

        return new PageResource<>(result, result.list, uriInfo);
    }

    public List<RoleResponse> getAllRoles() {

        return authGroupManagement.getAllRoles();

    }

    public PageResource<RoleResponse> getAllRolesByPageAndSize(int page, int size, UriInfo uriInfo) {

        var all = authGroupManagement.getAllRoles();

        var pages = partition(all, size);
        var content = pages.getOrDefault(page, List.of());

        var result = new PageQueryImpl<RoleResponse>();
        result.list = content;
        result.index = page;
        result.count = all.size();
        result.size = size;
        result.page = Page.of(page, size);

        return new PageResource<>(result, result.list, uriInfo);
    }

    public Object assignRoleToUser(AssignRoleRequest request){

        var roleEvent = new Event(request.extras);

        event.select(new BeforeProcessing.Literal("assign-role")).fire(roleEvent);

        if (!roleEvent.isSkipDefault()) {
            roleEvent.setResult(defaultLogic(request));
        }

        event.select(new AfterProcessing.Literal("assign-role")).fire(roleEvent);

        return roleEvent.getResult();
    }

    public InformativeResponse revokeRoleFromUser(RevokeRoleRequest request){

        var response = new InformativeResponse();
        response.code = 200;
        response.message = "Role revoked successfully!";

        if(StringUtils.isEmpty(request.apiResource)){

            authGroupManagement.revokeGlobalRoleFromUser(request.memberId, request.role);
        } else if(StringUtils.isNotEmpty(request.apiResource) && StringUtils.isEmpty(request.resourceId)) {

            throw new BadRequestException("api_resource exists and resource_id is empty!");
        } else {

            apiResourceHolder.getData()
                    .stream()
                    .filter(r -> r.getResourceName().equals(request.apiResource))
                    .findAny()
                    .orElseThrow(() -> new NotFoundException(request.apiResource + " not found!"));

            authGroupManagement.revokeResourceRoleFromUser(request.memberId, request.role, request.apiResource, request.resourceId);
            agmGroupCache.invalidate();
        }

        return response;
    }

    @CacheInvalidateAll(cacheName = "agm-groups")
    public void createNewRole(CreateRoleRequest request){

        authGroupManagement.createNewRole(request);

    }

    private InformativeResponse defaultLogic(AssignRoleRequest request){

        var response = new InformativeResponse();
        response.code = 200;
        response.message = "Role assigned successfully!";

        if(StringUtils.isEmpty(request.apiResource)){

            authGroupManagement.assignGlobalRoleToUser(request.username, request.role);
        } else if(StringUtils.isNotEmpty(request.apiResource) && StringUtils.isEmpty(request.resourceId)) {

            throw new BadRequestException("api_resource exists and resource_id is empty!");
        } else {

            apiResourceHolder.getData()
                    .stream()
                    .filter(r -> r.getResourceName().equals(request.apiResource))
                    .findAny()
                    .orElseThrow(() -> new NotFoundException(request.apiResource + " not found!"));

            authGroupManagement.assignResourceRoleToUser(request.username, request.role, request.apiResource, request.resourceId, request.attributes);
            agmGroupCache.invalidate();
        }

        return response;
    }

    public UserProfileDto getUserProfile() {

        var userProfile = new UserProfileDto();

        userProfile.id = utility.getUserUniqueIdentifier();
        userProfile.username = utility.getUsername();
        userProfile.email = utility.getUserEmail();
        userProfile.name = utility.getUserName();
        userProfile.surname = utility.getUserSurname();

        var entitlements = entitlementProvider.fetchEntitlements();

        userProfile.memberships = mapMemberships(entitlements);

        return userProfile;
    }

    public void assignUserTheMemberRole() {

        authGroupManagement.assignUserTheMemberRole(utility.getUsername());
    }

    public void updateRoleAttributes(String role, Map<String, List<String>> attributes) {
        authGroupManagement.updateRoleAttributes(role, attributes);
        agmGroupCache.invalidate();
    }

    public void authorize(ResourceAuthorization re) {

        repository.create(re);
    }

    public List<ResourceAuthorization> findByEndpointSecuredEndpointId(String securedEndpointId) {
        return repository.list("secured_endpoint_id", securedEndpointId);
    }

    public List<ResourceAuthorization> findAllResourcesAuthorization() {
        return repository.findAll();
    }

    public void delete(Long id) {
        repository.delete(id);
    }

    public ResourceAuthorization findById(Long id) {
        return repository.findById(id);
    }

    public void updateRule(Long id, String rule) {

        repository.update(id, rule);
    }

    public PageResource<GroupUserResponse> getAllMembersByPageAndSize(int page, int size, String search, String resource, UriInfo uriInfo) {

        var all = getApplicationMembers(
                authGroupManagement.getMembersGroupPath(),
                search
        );

        if (StringUtils.isNotBlank(resource)) {
            all = all.stream()
                    .filter(user -> user.memberships != null
                            && user.memberships.containsKey(resource))
                    .map(user -> {
                        user.memberships = Map.of(resource, user.memberships.get(resource));
                        return user;
                    })
                    .toList();
        }

        var pages = partition(all, size);
        var content = pages.getOrDefault(page, List.of());

        var result = new PageQueryImpl<GroupUserResponse>();
        result.list = content;
        result.index = page;
        result.count = all.size();
        result.size = size;
        result.page = Page.of(page, size);

        return new PageResource<>(result, result.list, uriInfo);
    }

    public List<GroupUserResponse> getApplicationMembers(String groupName, String search) {

        int first = 0;
        int size = 100;

        var groups = agmGroupCache.getGroups();

        var group = groups.get(groupName);
        var groupId = group == null ? null : group.id;

        if (groupId == null) {
            LOG.warnf("Group not found for path=%s", groupName);
            return List.of();
        }

        List<GroupUserResponse> users = new ArrayList<>();

        while (true) {

            var response = authGroupManagement.fetchGroupMembersByGroupId(groupId, first, size, search);


            if (response == null || response.results == null || response.results.isEmpty()) {
                break;
            }

            response.results.stream()
                    .map(member -> mapAllMember(member.user, groups))
                    .forEach(users::add);

            first += size;

            if (users.size() >= response.count) {
                break;
            }
        }

        return users;
    }

    @Override
    public Map<String, List<UserGroupInfoDto>> mapMemberships(List<Entitlement> entitlements) {
        return mapMemberships(entitlements, agmGroupCache.getGroups());
    }

    private GroupUserResponse mapAllMember(GroupUser gu, Map<String, Group> groups) {

        var user = new GroupUserResponse();
        user.id = gu.id;
        user.email = gu.email;
        user.username = gu.username;
        user.firstName = gu.firstName;
        user.lastName = gu.lastName;
        user.uid = gu.getUid();

        if (gu.attributes == null || gu.attributes.getLocalEntitlements() == null) {
            user.memberships = new HashMap<>();
            return user;
        }

        var parsedEntitlements = EntitlementUtils.parseEntitlements(
                gu.attributes.getLocalEntitlements()
        );

        user.memberships = mapMemberships(parsedEntitlements, groups);

        return user;
    }

    public Map<String, List<UserGroupInfoDto>> mapMemberships(List<Entitlement> entitlements, Map<String, Group> groups) {

        var memberships = new HashMap<String, List<UserGroupInfoDto>>();
        var parentGroup = authGroupManagement.getParentGroupPath();

        EntitlementUtils.extractResourceRoles(entitlements)
                .forEach(entitlement -> {
                    var dto = new UserGroupInfoDto();
                    dto.name = entitlement.resourceId();
                    dto.role = entitlement.role();

                    var groupPath = parentGroup + "/"
                            + entitlement.role() + "/"
                            + entitlement.resource() + "/"
                            + entitlement.resourceId();

                    var group = groups.get(groupPath);

                    if (group != null) {
                        dto.attributes = group.attributes;
                    }

                    memberships
                            .computeIfAbsent(entitlement.resource(), key -> new ArrayList<>())
                            .add(dto);
                });

        return memberships;
    }

    @Override
    public void init() {
        authGroupManagement.createParentGroup();
    }
}