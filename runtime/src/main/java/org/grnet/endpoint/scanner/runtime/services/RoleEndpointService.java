package org.grnet.endpoint.scanner.runtime.services;


import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.grnet.endpoint.scanner.runtime.Scope;
import org.grnet.endpoint.scanner.runtime.dtos.*;
import org.grnet.endpoint.scanner.runtime.entities.RoleEndpoint;
import org.grnet.endpoint.scanner.runtime.repositories.RoleEndpointRepository;

import java.util.*;
import java.util.stream.Collectors;

@ApplicationScoped
public class RoleEndpointService {

    @Inject
    RoleEndpointRepository roleEndpointRepository;
    @Inject
    ResourceAuthorizationService resourceAuthorizationService;

    public RoleEndpointAssignmentResponse getAssignedEndpoints() {

        List<RoleEndpoint> roleEndpoints = roleEndpointRepository.findAll();

        Map<String, List<RoleEndpoint>> grouped =
                roleEndpoints.stream()
                        .collect(Collectors.groupingBy(RoleEndpoint::getRoleId));

        List<RoleEndpointAssignmentResponse.RoleAssignment> assignments =
                grouped.entrySet().stream()
                        .map(entry -> {

                            List<RoleEndpoint> group = entry.getValue();
                            RoleEndpoint first = group.get(0);

                            RoleEndpointAssignmentResponse.RoleAssignment ra =
                                    new RoleEndpointAssignmentResponse.RoleAssignment();

                            ra.setRoleId(entry.getKey());
                            ra.setRoleName(first.getRoleName());

                            List<SecuredEndpointAssignment> endpoints =
                                    group.stream()
                                            .collect(Collectors.groupingBy(RoleEndpoint::getSecuredEndpointId))
                                            .entrySet()
                                            .stream()
                                            .map(e -> {

                                                SecuredEndpointAssignment dto =
                                                        new SecuredEndpointAssignment();

                                                dto.setSecuredEndpointId(e.getKey());

                                                List<Scope> scopes =
                                                        e.getValue().stream()
                                                                .map(RoleEndpoint::getScope)
                                                                .filter(s -> s != null && !s.isBlank())
                                                                .map(String::trim)
                                                                .distinct()
                                                                .map(scopeStr -> {
                                                                    try {
                                                                        return Scope.valueOf(scopeStr);
                                                                    } catch (IllegalArgumentException ex) {
                                                                        return null;
                                                                    }
                                                                })
                                                                .filter(Objects::nonNull)
                                                                .toList();

                                                dto.setScope(
                                                        scopes.stream()
                                                                .findFirst()
                                                                .orElse(null)
                                                );

                                                return dto;
                                            })
                                            .toList();

                            ra.setSecuredEndpoints(endpoints);

                            return ra;
                        })
                        .toList();

        RoleEndpointAssignmentResponse response = new RoleEndpointAssignmentResponse();
        response.setAssignments(assignments);

        return response;
    }

    public RoleEndpointAssignmentResponse getAssignedEndpointsByRoleId(String roleId) {

        List<RoleEndpoint> roleEndpoints = roleEndpointRepository.findAll()
                .stream()
                .filter(re -> re.getRoleId().equals(roleId))
                .toList();

        RoleEndpointAssignmentResponse response = new RoleEndpointAssignmentResponse();

        if (roleEndpoints.isEmpty()) {
            response.setAssignments(Collections.emptyList());
            return response;
        }

        RoleEndpoint first = roleEndpoints.get(0);

        RoleEndpointAssignmentResponse.RoleAssignment assignment =
                new RoleEndpointAssignmentResponse.RoleAssignment();

        assignment.setRoleId(roleId);
        assignment.setRoleName(first.getRoleName());

        assignment.setSecuredEndpoints(
                roleEndpoints.stream()
                        .collect(Collectors.groupingBy(RoleEndpoint::getSecuredEndpointId))
                        .entrySet()
                        .stream()
                        .map(entry -> {

                            SecuredEndpointAssignment dto = new SecuredEndpointAssignment();

                            dto.setSecuredEndpointId(entry.getKey());

                            // collect scope(s) for this endpoint
                            List<Scope> scopes =
                                    entry.getValue().stream()
                                            .map(RoleEndpoint::getScope)
                                            .filter(s -> s != null && !s.isBlank())
                                            .map(String::trim)
                                            .distinct()
                                            .map(scopeStr -> {
                                                try {
                                                    return Scope.valueOf(scopeStr);
                                                } catch (IllegalArgumentException e) {
                                                    return null; // or log it
                                                }
                                            })
                                            .filter(Objects::nonNull)
                                            .toList();
                            dto.setScope(scopes.isEmpty() ? null : scopes.get(0));
                            return dto;
                        })
                        .collect(Collectors.toList())
        );
        response.setAssignments(List.of(assignment));

        return response;
    }

    @Transactional
    public void assignRolesToEndpoints(RoleEndpointAssignmentRequest request) {

        List<RoleEndpoint> existing = roleEndpointRepository.findAll();

        Set<String> requestedRoleIds = request.getAssignments()
                .stream()
                .map(RoleEndpointAssignmentRequest.RoleAssignment::getRoleId)
                .collect(Collectors.toSet());

        Set<String> dbRoleIds = existing.stream()
                .map(RoleEndpoint::getRoleId)
                .collect(Collectors.toSet());

        // DELETE roles not in request
        Set<String> rolesToDelete = new HashSet<>(dbRoleIds);
        rolesToDelete.removeAll(requestedRoleIds);

        for (String roleId : rolesToDelete) {
            roleEndpointRepository.deleteByRoleId(roleId);
        }

        //  SYNC remaining roles
        for (var assignment : request.getAssignments()) {

            String roleId = assignment.getRoleId();
            String roleName = assignment.getRoleName();

            Set<String> incoming = new HashSet<>(assignment.getSecuredEndpointIds());

            List<RoleEndpoint> roleEntries =
                    roleEndpointRepository.list("role_id", roleId);

            Set<String> existingEndpoints = roleEntries.stream()
                    .map(RoleEndpoint::getSecuredEndpointId)
                    .collect(Collectors.toSet());

            // delete removed endpoints
            Set<String> toDelete = new HashSet<>(existingEndpoints);
            toDelete.removeAll(incoming);

            if (!toDelete.isEmpty()) {
                roleEndpointRepository.deleteByRoleIdAndEndpointIds(roleId, new ArrayList<>(toDelete));
            }

            // insert new endpoints
            Set<String> toInsert = new HashSet<>(incoming);
            toInsert.removeAll(existingEndpoints);

            for (String endpointId : toInsert) {
                RoleEndpoint re = new RoleEndpoint();
                re.setRoleId(roleId);
                re.setRoleName(roleName);
                re.setSecuredEndpointId(endpointId);
                roleEndpointRepository.create(re);
            }
        }
    }

    @Transactional
    public void assignRolesToEndpointsPerRole(String roleId, SecuredEndpointPerRoleRequest request) {

        RoleResponse role = resourceAuthorizationService
                .getAllRoles()
                .stream()
                .filter(r -> r.id.equals(roleId))
                .findFirst()
                .orElseThrow(() ->
                        new RuntimeException("Role not found: " + roleId)
                );

        List<RoleEndpoint> existing = roleEndpointRepository.list("role_id", roleId);

        // key = endpointId:scope
        Map<String, RoleEndpoint> existingMap =
                existing.stream()
                        .collect(Collectors.toMap(
                                e -> e.getSecuredEndpointId()
                                        + ":" +
                                        (e.getScope() != null
                                                ? e.getScope().toLowerCase()
                                                : ""),
                                e -> e,
                                (a, b) -> a
                        ));

        // incoming unique keys
        Set<String> incomingKeys =
                request.getAssignments().stream()
                        .map(a ->
                                a.getSecuredEndpointId()
                                        + ":" +
                                        (a.getScope() != null
                                                ? a.getScope().name().toUpperCase()
                                                : "")
                        )
                        .collect(Collectors.toSet());

        Map<String, SecuredEndpointAssignment> incomingMap =
                request.getAssignments().stream()
                        .collect(Collectors.toMap(
                                a -> a.getSecuredEndpointId()
                                        + ":" +
                                        (a.getScope() != null
                                                ? a.getScope().name().toUpperCase()
                                                : ""),
                                a -> a,
                                (a, b) -> a
                        ));

        // -------------------------------------------------
        // DELETE REMOVED
        // -------------------------------------------------

        Set<String> toDelete = new HashSet<>(existingMap.keySet());
        toDelete.removeAll(incomingKeys);

        for (String key : toDelete) {

            RoleEndpoint entity = existingMap.get(key);

            if (entity != null) {
                roleEndpointRepository.delete(entity.getId());
            }
        }

        // -------------------------------------------------
        // UPSERT
        // -------------------------------------------------

        for (String key : incomingKeys) {

            SecuredEndpointAssignment assignment =
                    incomingMap.get(key);

            RoleEndpoint existingEntry =
                    existingMap.get(key);

            RoleEndpoint entity =
                    existingEntry != null
                            ? existingEntry
                            : new RoleEndpoint();

            entity.setRoleId(roleId);
            entity.setRoleName(role.name);

            entity.setSecuredEndpointId(
                    assignment.getSecuredEndpointId()
            );

            entity.setScope(
                    assignment.getScope() != null
                            ? assignment.getScope().name().toUpperCase()
                            : null
            );

            if (existingEntry == null) {
                roleEndpointRepository.create(entity);
            } else {
                roleEndpointRepository.update(entity);
            }
        }
    }

}
