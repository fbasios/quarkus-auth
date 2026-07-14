package org.grnet.endpoint.scanner.runtime.services;

import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.core.UriInfo;
import org.apache.commons.lang3.StringUtils;
import org.bson.types.ObjectId;
import org.grnet.endpoint.scanner.runtime.ApiResourceHolder;
import org.grnet.endpoint.scanner.runtime.ApiResourceMetadata;
import org.grnet.endpoint.scanner.runtime.EndpointMetadata;
import org.grnet.endpoint.scanner.runtime.EndpointMetadataHolder;
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
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Actor;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.ActorEntitlements;
import org.grnet.endpoint.scanner.runtime.entities.pagination.Page;
import org.grnet.endpoint.scanner.runtime.entities.pagination.PageQueryImpl;
import org.grnet.endpoint.scanner.runtime.entitlements.Entitlement;
import org.grnet.endpoint.scanner.runtime.entitlements.EntitlementProvider;
import org.grnet.endpoint.scanner.runtime.entitlements.EntitlementUtils;
import org.grnet.endpoint.scanner.runtime.entitlements.UserContextInterface;
import org.grnet.endpoint.scanner.runtime.entitlements.qualifiers.PersistenceAuthorization;
import org.grnet.endpoint.scanner.runtime.process.AfterProcessing;
import org.grnet.endpoint.scanner.runtime.process.BeforeProcessing;
import org.grnet.endpoint.scanner.runtime.process.Event;
import org.grnet.endpoint.scanner.runtime.repositories.PersistenceEntitlementRepository;
import org.grnet.endpoint.scanner.runtime.repositories.ResourceAuthorizationRepository;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static io.vertx.core.http.impl.HttpUtils.normalizePath;

@PersistenceAuthorization
public class PersistenceResourceAuthorizationService implements ResourceAuthorizationService{

    @Inject
    EndpointMetadataHolder endpointMetadataHolder;

    @Inject
    ApiResourceHolder apiResourceHolder;

    @Inject
    PersistenceEntitlementRepository persistenceEntitlementRepository;

    @Inject
    UserContextInterface userContextInterface;

    @Inject
    jakarta.enterprise.event.Event<Event> event;

    @Inject
    Utility utility;

    @Inject
    EntitlementProvider entitlementProvider;

    @Inject
    ResourceAuthorizationRepository repository;


    private final Map<String, Pattern> patternCache = new ConcurrentHashMap<>();

    @Override
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

    @Override
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

    @Override
    public List<RoleResponse> getAllRoles() {

        var entitlements = persistenceEntitlementRepository.fetchAll(org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Entitlement.class);

        return entitlements.stream()
                .map(e -> extractSubGroup(e, userContextInterface.getNamespace(), userContextInterface.getParent()))
                .filter(Objects::nonNull)
                .distinct()
                .collect(Collectors.toList());
    }

    @Override
    public PageResource<RoleResponse> getAllRolesByPageAndSize(int page, int size, UriInfo uriInfo) {

        var all = persistenceEntitlementRepository.fetchAll(org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Entitlement.class);

        var roles = all
                .stream()
                .map(e -> extractSubGroup(e, userContextInterface.getNamespace(), userContextInterface.getParent()))
                .filter(Objects::nonNull)
                .distinct()
                .collect(Collectors.toList());

        var pages = partition(roles, size);
        var content = pages.getOrDefault(page, List.of());

        var result = new PageQueryImpl<RoleResponse>();
        result.list = content;
        result.index = page;
        result.count = roles.size();
        result.size = size;
        result.page = Page.of(page, size);

        return new PageResource<>(result, result.list, uriInfo);
    }

    @Override
    public Object assignRoleToUser(AssignRoleRequest request) {

        var roleEvent = new Event(request.extras);

        event.select(new BeforeProcessing.Literal("assign-role")).fire(roleEvent);

        if (!roleEvent.isSkipDefault()) {
            roleEvent.setResult(defaultLogic(request));
        }

        event.select(new AfterProcessing.Literal("assign-role")).fire(roleEvent);

        return roleEvent.getResult();
    }

    private InformativeResponse defaultLogic(AssignRoleRequest request){

        var response = new InformativeResponse();
        response.code = 200;
        response.message = "Role assigned successfully!";

        var optActor = persistenceEntitlementRepository.findByIdOptional(request.username, Actor.class);

        var user = optActor.orElseThrow(()->new NotFoundException("There is no user : "+request.username));

        if(StringUtils.isEmpty(request.apiResource)){

            var opt = persistenceEntitlementRepository.findPersistenceEntitlementByName(buildRoleUrn(userContextInterface.getNamespace(), userContextInterface.getParent(), request.role));

            var role = opt.orElseThrow(()->new NotFoundException("There is no role : "+request.role));

            var exists = persistenceEntitlementRepository.findActorEntitlementByEntitlementAndActor(role.getId(), user.getId());

            if(exists.isEmpty()){

                var actorEntitlement = new ActorEntitlements();
                actorEntitlement.setEntitlementId(role.getId());
                actorEntitlement.setActorId(user.getId());
                actorEntitlement.setAssignedAt(LocalDateTime.now());
                actorEntitlement.setId(new ObjectId().toString());

                persistenceEntitlementRepository.add(actorEntitlement, ActorEntitlements.class);
            }

        } else if(StringUtils.isNotEmpty(request.apiResource) && StringUtils.isEmpty(request.resourceId)) {

            throw new BadRequestException("api_resource exists and resource_id is empty!");
        } else {

            apiResourceHolder.getData()
                    .stream()
                    .filter(r -> r.getResourceName().equals(request.apiResource))
                    .findAny()
                    .orElseThrow(() -> new NotFoundException(request.apiResource + " not found!"));


            var resourceRole = buildResourceUrn(userContextInterface.getNamespace(), userContextInterface.getParent(), request.role, request.apiResource, request.resourceId);

            var opt = persistenceEntitlementRepository.findPersistenceEntitlementByName(resourceRole);

            if(opt.isEmpty()){

                var entitlement = new org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Entitlement();

                entitlement.setName(buildResourceUrn(userContextInterface.getNamespace(), userContextInterface.getParent(), request.role, request.apiResource, request.resourceId));
                entitlement.setRegisteredOn(LocalDateTime.now());
                entitlement.setAttributes(request.attributes);
                entitlement.setId(new ObjectId().toString());
                persistenceEntitlementRepository.add(entitlement, org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Entitlement.class);

                var actorEntitlement = new ActorEntitlements();
                actorEntitlement.setEntitlementId(entitlement.getId());
                actorEntitlement.setActorId(user.getId());
                actorEntitlement.setAssignedAt(LocalDateTime.now());
                actorEntitlement.setId(new ObjectId().toString());

                persistenceEntitlementRepository.add(actorEntitlement, ActorEntitlements.class);
            } else {

                var actorEntitlement = new ActorEntitlements();
                actorEntitlement.setEntitlementId(opt.get().getId());
                actorEntitlement.setActorId(user.getId());
                actorEntitlement.setAssignedAt(LocalDateTime.now());
                actorEntitlement.setId(new ObjectId().toString());

                persistenceEntitlementRepository.add(actorEntitlement, ActorEntitlements.class);
            }
        }

        return response;
    }

    @Override
    public InformativeResponse revokeRoleFromUser(RevokeRoleRequest request) {

        var response = new InformativeResponse();
        response.code = 200;
        response.message = "Role revoked successfully!";

        var optActor = persistenceEntitlementRepository.findByIdOptional(request.memberId, Actor.class);

        var user = optActor.orElseThrow(()->new NotFoundException("There is no user : "+request.memberId));

        if(StringUtils.isEmpty(request.apiResource)){

            var opt = persistenceEntitlementRepository.findPersistenceEntitlementByName(buildRoleUrn(userContextInterface.getNamespace(), userContextInterface.getParent(), request.role));

            var role = opt.orElseThrow(()->new NotFoundException("There is no role : "+request.role));

            persistenceEntitlementRepository.deleteActorEntitlementByEntitlementAndActor(role.getId(), user.getId());

        } else if(StringUtils.isNotEmpty(request.apiResource) && StringUtils.isEmpty(request.resourceId)) {

            throw new BadRequestException("api_resource exists and resource_id is empty!");
        } else {

            apiResourceHolder.getData()
                    .stream()
                    .filter(r -> r.getResourceName().equals(request.apiResource))
                    .findAny()
                    .orElseThrow(() -> new NotFoundException(request.apiResource + " not found!"));

            var resourceRole = buildResourceUrn(userContextInterface.getNamespace(), userContextInterface.getParent(), request.role, request.apiResource, request.resourceId);

            var opt = persistenceEntitlementRepository.findPersistenceEntitlementByName(resourceRole);

            opt.ifPresent(entitlement -> persistenceEntitlementRepository.deleteActorEntitlementByEntitlementAndActor(entitlement.getId(), user.getId()));
        }

        return response;
    }

    @Override
    public void createNewRole(CreateRoleRequest request) {

        var entitlement = new org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Entitlement();

        var name = buildRoleUrn(userContextInterface.getNamespace(), userContextInterface.getParent(), request.name);

        var opt = persistenceEntitlementRepository.findPersistenceEntitlementByName(name);

        if (opt.isEmpty()) {

            entitlement.setName(name);
            entitlement.setRegisteredOn(LocalDateTime.now());
            entitlement.setAttributes(request.attributes);
            entitlement.setId(new ObjectId().toString());
            persistenceEntitlementRepository.add(entitlement, org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Entitlement.class);
        }
    }

    @Override
    public UserProfileDto getUserProfile() {

        var opt = persistenceEntitlementRepository.findActorByOidcIdAndIssuer(userContextInterface.getId(), userContextInterface.getIssuer());

        var actor = opt.orElseThrow(()->new ForbiddenException("The actor has not been registered yet!"));


        var userProfile = new UserProfileDto();

        userProfile.id = utility.getUserUniqueIdentifier();
        userProfile.username = actor.getId();
        userProfile.email = utility.getUserEmail();
        userProfile.name = utility.getUserName();
        userProfile.surname = utility.getUserSurname();

        var entitlements = entitlementProvider.fetchEntitlements();

        userProfile.memberships = mapMemberships(entitlements);

        return userProfile;
    }

    @Override
    public void assignUserTheMemberRole() {

        var opt = persistenceEntitlementRepository.findPersistenceEntitlementByName(membersEntitlement(userContextInterface.getNamespace(), userContextInterface.getParent()));

        var entitlement = opt.orElseThrow(()-> new ServerErrorException("The user cannot be registered! Please notify administrator! Necessary role members is missing!", 500));

        var dbActor = persistenceEntitlementRepository.findActorByOidcIdAndIssuer(userContextInterface.getId(), userContextInterface.getIssuer());

        if(dbActor.isEmpty()){

            var actor = new Actor();

            actor.setId(new ObjectId().toString());
            actor.setIssuer(userContextInterface.getIssuer());
            actor.setName(userContextInterface.getName().orElse(""));
            actor.setEmail(userContextInterface.getEmail().orElse(""));
            actor.setRegisteredOn(LocalDateTime.now());
            actor.setOidcId(userContextInterface.getId());

            persistenceEntitlementRepository.add(actor, Actor.class);

            var actorEntitlement = new ActorEntitlements();
            actorEntitlement.setEntitlementId(entitlement.getId());
            actorEntitlement.setActorId(actor.getId());
            actorEntitlement.setAssignedAt(LocalDateTime.now());
            actorEntitlement.setId(new ObjectId().toString());

            persistenceEntitlementRepository.add(actorEntitlement, ActorEntitlements.class);
        }
    }

    @Override
    public void updateRoleAttributes(String id, Map<String, List<String>> attributes) {

        persistenceEntitlementRepository.updateEntitlementAttributes(id, attributes);
    }

    @Override
    public void authorize(ResourceAuthorization re) {

        repository.create(re);
    }

    @Override
    public List<ResourceAuthorization> findByEndpointSecuredEndpointId(String securedEndpointId) {
        return repository.list("secured_endpoint_id", securedEndpointId);

    }

    @Override
    public List<ResourceAuthorization> findAllResourcesAuthorization() {
        return repository.findAll();
    }

    @Override
    public void delete(Long id) {
        repository.delete(id);
    }

    @Override
    public ResourceAuthorization findById(Long id) {
        return repository.findById(id);
    }

    @Override
    public void updateRule(Long id, String rule) {
        repository.update(id, rule);
    }

    @Override
    public PageResource<GroupUserResponse> getAllMembersByPageAndSize(int page, int size, String search, String resource, UriInfo uriInfo) {

        var members = persistenceEntitlementRepository
                .findPersistenceEntitlementByName(membersEntitlement(userContextInterface.getNamespace(),
                        userContextInterface.getParent())).orElseThrow(()-> new ServerErrorException("The user cannot be registered! Please notify administrator! Necessary role members is missing!", 500));

        var actors = persistenceEntitlementRepository.findAllActorsByEntitlementId(members.getId(), page, size);

        var count = persistenceEntitlementRepository.countAllActorByEntitlementId(members.getId());

        var list = actors.stream().map(actor->{

            var parts = splitName(actor.getName());

            var entitlements = persistenceEntitlementRepository.findActorEntitlements(actor.getId());

            var resp = new GroupUserResponse();
            resp.email = actor.getEmail();
            resp.firstName = parts[0];
            resp.lastName = parts.length > 1 ? parts[1] : "";
            resp.id = actor.getId();
            resp.username = actor.getId();
            resp.uid = actor.getOidcId();
            resp.memberships = mapMemberships(EntitlementUtils.parseEntitlements(entitlements));
            return resp;
        }).collect(Collectors.toList());

        var result = new PageQueryImpl<GroupUserResponse>();
        result.list = list;
        result.index = page;
        result.count = count;
        result.size = size;
        result.page = Page.of(page, size);

        return new PageResource<>(result, result.list, uriInfo);
    }

    public static String[] splitName(String name) {
        if (name == null || name.isBlank()) {
            return new String[]{"", ""};
        }
        String[] parts = name.trim().split("\\s+", 2);
        return parts.length > 1 ? parts : new String[]{parts[0], ""};
    }

    @Override
    public Map<String, List<UserGroupInfoDto>> mapMemberships(List<Entitlement> entitlements) {

        var dbEntitlements = persistenceEntitlementRepository.fetchAll(org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Entitlement.class);

        var groups = dbEntitlements
                .stream()
                .map(entitlement->{

                    var opt = extractPath(entitlement.getName(), userContextInterface.getNamespace(), userContextInterface.getParent(), "member");

                    if(opt.isPresent()){

                        var role = extractSubGroup(entitlement, userContextInterface.getNamespace(), userContextInterface.getParent());

                        var toGroup = new Group();
                        toGroup.id = entitlement.getId();
                        toGroup.path = opt.get();
                        toGroup.name = role.name;
                        toGroup.attributes = entitlement.getAttributes();
                        return toGroup;
                    }

                    return null;
                }).filter(Objects::nonNull).toList();



        return mapMemberships(entitlements, flattenGroups(groups));
    }

    public Map<String, Group> flattenGroups(List<Group> groups) {

        Map<String, Group> map = new HashMap<>();

        for (Group group : groups) {
            map.put(group.path, group);
        }

        return map;
    }

    @Override
    public Map<String, List<UserGroupInfoDto>> mapMemberships(List<Entitlement> entitlements, Map<String, Group> groups) {

        var memberships = new HashMap<String, List<UserGroupInfoDto>>();
        var parentGroup = normalizePath(userContextInterface.getParent());

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

        var members = persistenceEntitlementRepository
                .findPersistenceEntitlementByName(membersEntitlement(userContextInterface.getNamespace(),
                        userContextInterface.getParent()));

        if(members.isEmpty()){

            var request = new CreateRoleRequest();

            request.name = "members";

            createNewRole(request);
        }
    }

    private RoleResponse extractSubGroup(org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Entitlement entitlement, String namespace, String parentGroup) {
        var prefix = namespace + ":group:" + parentGroup + ":";
        var urn = entitlement.getName();

        if (urn == null || !urn.startsWith(prefix)) {
            return null;
        }

        var rest = urn.substring(prefix.length());
        var parts = rest.split(":");

        if (parts.length < 2 || parts[0].contains("=")) {
            return null;
        }

        var subGroup = parts[0];

        return new RoleResponse(entitlement.getId(), subGroup, entitlement.getAttributes());
    }

    private String buildRoleUrn(String namespace, String parentGroup, String name) {
        return namespace + ":group:" + parentGroup + ":" + name + ":role=member";
    }

    private String buildResourceUrn(String namespace, String parentGroup, String name, String resource, String id) {
        return namespace + ":group:" + parentGroup + ":" + name + ":"+resource+":"+id+":role=member";
    }

    private String membersEntitlement(String namespace, String parentGroup){

        return namespace + ":group:" + parentGroup + ":" + "members:role=member";
    }

    public Optional<String> extractPath(String entitlement, String urn, String groupType, String role) {
        if (entitlement == null || urn == null || groupType == null || role == null) {
            return Optional.empty();
        }

        var cacheKey = urn + "|" + groupType + "|" + role;
        var pattern = patternCache.computeIfAbsent(cacheKey, key -> buildPattern(urn, groupType, role));
        var matcher = pattern.matcher(entitlement);

        return matcher.find()
                ? Optional.of(groupType + "/" + matcher.group(1).replace(":", "/"))
                : Optional.empty();
    }

    private Pattern buildPattern(String urn, String groupType, String role) {
        var fullPrefix = urn + ":group:" + groupType + ":";
        return Pattern.compile(Pattern.quote(fullPrefix) + "(.+?):role=" + Pattern.quote(role) + "$");
    }
}
