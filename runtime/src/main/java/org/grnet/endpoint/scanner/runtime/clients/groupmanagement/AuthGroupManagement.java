package org.grnet.endpoint.scanner.runtime.clients.groupmanagement;

import io.quarkus.rest.client.reactive.QuarkusRestClientBuilder;
import org.grnet.endpoint.scanner.runtime.clients.groupmanagement.response.*;
import org.grnet.endpoint.scanner.runtime.dtos.CreateRoleRequest;
import org.grnet.endpoint.scanner.runtime.dtos.RoleResponse;
import org.jboss.logging.Logger;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static io.vertx.core.http.impl.HttpUtils.normalizePath;
import static java.lang.Math.min;
import static java.util.stream.Collectors.toMap;

/**
 * Implementation of {@link RoleManagement} that models group management structures as roles
 * using the Auth Group Management system.
 * Each group beneath a parent group functions as a role within this system.
 *
 * <p>There are two types of roles:
 * <ul>
 *   <li><b>Global Roles</b> - General-purpose roles that apply system-wide and do not
 *       contain any additional resource-specific information.</li>
 *   <li><b>Resource Roles</b> - Roles that are scoped to specific resources. Internally,
 *       they encapsulate the resource type and its associated ID, defining what a user
 *       has access to.</li>
 * </ul>
 */
public class AuthGroupManagement implements GroupManagement, RoleManagement {

    private static final Logger LOG = Logger.getLogger(AuthGroupManagement.class);

    private volatile KeycloakGroupManagementClient groupClient;

    private final String parentGroup;

    private final String url;

    private final BearerTokenRequestFilter filter;


    public AuthGroupManagement(String url, BearerTokenRequestFilter filter, String parentGroup) {
        this.parentGroup = parentGroup;
        this.url = url;
        this.filter = filter;
    }

    private KeycloakGroupManagementClient getGroupClient() {
        if (groupClient == null) {
            synchronized (this) {
                if (groupClient == null) {
                    groupClient = QuarkusRestClientBuilder.newBuilder()
                            .baseUri(URI.create(url))
                            .register(KeycloakExceptionMapper.class)
                            .register(filter)
                            .build(KeycloakGroupManagementClient.class);
                }
            }
        }
        return groupClient;
    }


    // ---------------------------------------------------------
    // CREATE GROUP
    // ---------------------------------------------------------

    public void createParentGroup(){

        LOG.info("Executing required steps for initializing necessary group management structure...");

        var parentId = getGroupIdByPath("/"+parentGroup);
        if (parentId == null) {

            LOG.info("Step 1 : Initialing parent level "+parentGroup+"...");

            var req = new GroupRequest();
            req.name = parentGroup;
            req.attributes = Map.of();

            getGroupClient().createParentGroup(req);

            LOG.info("Parent level "+parentGroup+" has been successfully initialized!");
        } else {

            LOG.info("Step 1 : Parent level "+parentGroup+" has already been initialized!");
        }

        var membershipGroupId = getGroupIdByPath("/"+parentGroup+"/members");

        if (membershipGroupId == null) {

            LOG.info("Step 2 : Initialing memberships ...");

            createGroup("/"+parentGroup, "members", null, null);

            LOG.info("Memberships have been successfully initialized!");
        } else {

            LOG.info("Step 2 : Memberships have already been initialized!");
        }

        LOG.info("Group management initialization has been successfully completed!");
    }

    @Override
    public void createGroup(String parentPath, String name, List<String> roles, Map<String, List<String>> attributes) {

        if (roles == null) roles = List.of();
        if (attributes == null) attributes = Map.of();

        // Build request
        var req = new GroupRequest();
        req.name = name;
        req.attributes = attributes;

        // Resolve parent group ID
        var parentId = getGroupIdByPath(parentPath);
        if (parentId == null)
            throw new IllegalStateException("Creating group failed. Parent group not found at path: " + parentPath);

        // Create child group
        getGroupClient().createSubGroup(parentId, req);

        // Resolve new group ID (path-based)
        var newGroupPath = parentPath + "/" + name;
        var newGroupId = getGroupIdByPath(newGroupPath);
        if (newGroupId == null)
            throw new IllegalStateException("Creating group failed. New group not found after creation: " + newGroupPath);

        LOG.infof("Group created: %s → ID: %s", newGroupPath, newGroupId);

        if(!roles.isEmpty()){

            // Assign roles
            for (String role : roles) {
                getGroupClient().addRole(newGroupId, role);
            }

            // Update the group configuration with roles
            updateGroupConfigurationRoles(newGroupId, roles);
        }
    }

    // ---------------------------------------------------------
    // DELETE GROUP
    // ---------------------------------------------------------
    @Override
    public void deleteGroup(String fullGroupPath) {
        try {
            var id = getGroupIdByPath(fullGroupPath);
            if (id != null) {
                getGroupClient().deleteGroup(id);
                LOG.infof("Group deleted: %s → ID: %s", fullGroupPath, id);
            } else {
                LOG.warnf("Group not found for deletion: %s", fullGroupPath);
            }
        } catch (Exception e) {
            LOG.errorf("Failed to delete group %s: %s", fullGroupPath, e.getMessage());
        }
    }

    /**
     * Creates a new group within the group management system.
     *
     * The created role represents a group beneath the parent group in the
     * group management structure. Once created, the role can be assigned to users
     * either as a global role or configured as a resource role with associated resources.
     *
     * @param request the unique name of the role to be created
     */
    @Override
    public void createNewRole(CreateRoleRequest request){

        var parentPath = "/" + parentGroup;
        createGroup(parentPath, request.name, List.of(), request.attributes);
    }

    /**
     * Assigns the default "members" role to the specified user,
     * effectively adding them to the members group in the Group Management system.
     *
     * <p>This serves as the entry-point role assignment for new users,
     * granting them base-level membership within the system.
     *
     * @param username the unique identifier of the user to be added to the members group
     */
    @Override
    public void assignUserTheMemberRole(String username) {

        var fullPath = "/" + parentGroup + "/members";

        var groupId = getGroupIdByPath(fullPath);

        var response = getGroupClient().getGroupMembers(groupId, 0, 10, username);

        if(response.count>0){
            return;
        }

        getGroupClient().addUserToGroup(groupId, new AddGroupMemberRequest(username, List.of("member")));
    }

    @Override
    public GroupMembersResponse fetchGroupMembers(String path, int first, int max, String search) {

        var fullPath = "/" + parentGroup + "/members";

        var groupId = getGroupIdByPath(fullPath);

        return getGroupClient().getGroupMembers(groupId, first, max, search);
    }

    /**
     * Retrieves all groups under the parent group available in the group management system.
     *
     * @return a list of {@link RoleResponse} objects representing all existing roles,
     *         or an empty list if no roles are defined
     */
    @Override
    public List<RoleResponse> getAllRoles(){

        var parentGroupId = "/" + parentGroup;

        var groupId = getGroupIdByPath(parentGroupId);

        var group = getGroupClient().getGroup(groupId);

        return group.extraSubGroups.stream().map(gr -> new RoleResponse(gr.id, gr.name, gr.attributes)).collect(Collectors.toList());
    }

    // ---------------------------------------------------------
    // ADD ROLE
    // ---------------------------------------------------------
    @Override
    public void addRole(String groupId, String role) {
        getGroupClient().addRole(groupId, role);
    }

    // ---------------------------------------------------------
    // UPDATE CONFIGURATION (ROLES)
    // ---------------------------------------------------------
    @Override
    public void updateConfiguration(String groupId, List<String> roles) {
        updateGroupConfigurationRoles(groupId, roles);
    }

    @Override
    public List<GroupUser> fetchGroupMembersByRole(String fullPath, String role) {

        var groupId = getGroupIdByPath(fullPath);

        LOG.infof("AGM getMembersByRole fullPath=%s groupId=%s role=%s", fullPath, groupId, role);


        var response = getGroupClient().getMembersByRole(groupId, role);

        if (response == null || response.results == null) {
            return List.of();
        }

        return response.results.stream()
                .map(entry -> entry.user)
                .toList();
    }

    @Override
    public void addGroupMember(String fullPath, String username, String role) {

        var groupId = getGroupIdByPath(fullPath);

        var response = getGroupClient().getGroupMembers(groupId, 0, 10, username);

        if(response.count>0){
            return;
        }

        getGroupClient().addUserToGroup(groupId, new AddGroupMemberRequest(username, List.of(role)));
    }

    @Override
    public void assignGlobalRoleToUser(String username, String role){

        var parentPath = "/" + parentGroup + "/" + role;

        addGroupMember(parentPath, username, "member");
    }

    @Override
    public void revokeGlobalRoleFromUser(String memberId, String role) {

        var parentPath = "/" + parentGroup + "/" + role;

        removeMemberFromGroup(parentPath, memberId);
    }

    @Override
    public void revokeResourceRoleFromUser(String memberId, String role, String resource, String id) {

        var parentPath = "/" + parentGroup + "/" + role + "/"+ resource+"/"+id;
        removeMemberFromGroup(parentPath, memberId);
    }

    @Override
    public void assignResourceRoleToUser(String username, String role, String resource, String id, Map<String, List<String>> attributes){

        var specificResourcePath = "/" + parentGroup + "/" + role + "/"+ resource+"/"+id;

        var specificResourceGroupId = getGroupIdByPath(specificResourcePath);

        if (specificResourceGroupId != null && attributes != null && !attributes.isEmpty()) {

            var group = getGroupClient().getGroup(specificResourceGroupId);

            if (needsAttributeUpdate(group.attributes, attributes)) {
                var merged = mergeAttributes(group.attributes, attributes);
                updateGroupAttributes(specificResourceGroupId, merged);
            }
        }

        if (Objects.isNull(specificResourceGroupId)){

            var resourcePath = "/" + parentGroup + "/" + role + "/"+ resource;

            var resourceGroupId = getGroupIdByPath(resourcePath);

            if(Objects.isNull(resourceGroupId)){

                createGroup("/" + parentGroup + "/" + role, resource, List.of(), attributes);
            }

            createGroup("/" + parentGroup + "/" + role + "/"+ resource, id, List.of(), attributes);
        }

        addGroupMember(specificResourcePath, username, "member");
    }

    @Override
    public void addMemberToGroupByGroupId(String id, String username, String role) {

        var response = getGroupClient().getGroupMembers(id, 0, 10, username);

        if (response.count>0) {
            return;
        }

        getGroupClient().addUserToGroup(id, new AddGroupMemberRequest(username, List.of(role)));
    }

    private void updateGroupConfigurationRoles(String groupId, List<String> roles) {

        // Fetch full group structure
        var group = getGroupClient().getGroup(groupId);

        // Obtain defaultConfiguration ID
        var configId = group.attributes
                .get("defaultConfiguration")
                .get(0);

        // Fetch complete configuration JSON object
        var config = getGroupClient().getConfiguration(groupId, configId);

        // Assign new roles
        config.setGroupRoles(roles);

        // Update configuration
        getGroupClient().updateConfiguration(groupId, config);

        LOG.infof("Updated roles for group %s → %s", groupId, roles);
    }

    // ---------------------------------------------------------
    // GROUP LOOKUP UTILITIES
    // ---------------------------------------------------------
    @Override
    public String getGroupId(String fullPath) {
        return getGroupIdByPath(fullPath);
    }

    // Internal lookup: resolves a group ID from the flattened groups map
    private String getGroupIdByPath(String fullPath) {
        var group = flattenGroups().get(fullPath);
        return group == null ? null : group.id;
    }

    // Builds a map of all groups (path → id, id → defaultConfigId) by flattening the Keycloak tree
    public Map<String, Group> flattenGroups() {

        var response = getGroupClient().getGroups("");

        Map<String, Group> map = new HashMap<>();

        for (Group group : response.results) {
            collectGroupRecursive(group, map);
        }

        return map;
    }

    @Override
    public List<PartialGroup> fetchGroups() {

        var groups = new ArrayList<PartialGroup>();

        var response = getGroupClient().getGroups("");

        for (Group group : response.results) {
            collectGroupRecursive(group, groups);
        }
        return groups;
    }

    @Override
    public void removeMemberFromGroup(String fullPath, String memberId) {

        var groupId = getGroupIdByPath(fullPath);

        getGroupClient().removeMemberFromGroup(groupId, memberId);
    }

    // Recursively adds a group's path, id, and default configuration to the lookup map
    private void collectGroupRecursive(Group group, Map<String, Group> map) {
        map.put(group.path, group);

        if (group.extraSubGroups != null) {
            for (Group child : group.extraSubGroups) {
                collectGroupRecursive(child, map);
            }
        }
    }


    public void updateRoleAttributes(String groupId, Map<String, List<String>> attributes) {

        var group = getGroupClient().getGroup(groupId);

        if (needsAttributeUpdate(group.attributes, attributes)) {

            var merged = mergeAttributes(group.attributes, attributes);
            updateGroupAttributes(groupId, merged);
        }
    }

    private void updateGroupAttributes(String groupId, Map<String, List<String>> attributes) {

        if (attributes == null || attributes.isEmpty()) { return; }

        getGroupClient().updateGroupAttributes(groupId, attributes);
    }

    private boolean needsAttributeUpdate(
            Map<String, List<String>> existing,
            Map<String, List<String>> incoming) {

        if (incoming == null || incoming.isEmpty()) { return false; }

        if (existing == null || existing.isEmpty()) { return true; }

        return incoming.entrySet()
                .stream()
                .anyMatch(entry -> !entry.getValue().equals(existing.get(entry.getKey())));
    }

    private Map<String, List<String>> mergeAttributes(
            Map<String, List<String>> existing,
            Map<String, List<String>> incoming) {

        var merged = new HashMap<String, List<String>>();

        if (existing != null) {
            merged.putAll(existing);
        }

        if (incoming != null) {
            merged.putAll(incoming);
        }

        return merged;
    }

    public String getParentGroupPath() {
        return normalizePath(parentGroup);
    }

    public String getMembersGroupPath() {
        return getParentGroupPath() + "/members";
    }

    public GroupMembersResponse fetchGroupMembersByGroupId(String groupId, int first, int max, String search) {
        return getGroupClient().getGroupMembers(groupId, first, max, search);
    }

    private <T> Map<Integer, List<T>> partition(List<T> list, int pageSize) {
        return IntStream.iterate(0, i -> i + pageSize)
                .limit((list.size() + pageSize - 1) / pageSize)
                .boxed()
                .collect(toMap(i -> i / pageSize,
                        i -> list.subList(i, min(i + pageSize, list.size()))));
    }
}

