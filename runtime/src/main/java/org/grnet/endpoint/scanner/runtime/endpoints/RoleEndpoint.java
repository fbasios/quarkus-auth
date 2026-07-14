package org.grnet.endpoint.scanner.runtime.endpoints;

import io.quarkus.security.Authenticated;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.enums.SecuritySchemeIn;
import org.eclipse.microprofile.openapi.annotations.enums.SecuritySchemeType;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement;
import org.eclipse.microprofile.openapi.annotations.security.SecurityScheme;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.grnet.endpoint.scanner.runtime.ParamRef;
import org.grnet.endpoint.scanner.runtime.ParamType;
import org.grnet.endpoint.scanner.runtime.SecuredEndpoint;
import org.grnet.endpoint.scanner.runtime.dtos.*;
import org.grnet.endpoint.scanner.runtime.services.ResourceAuthorizationService;
import org.grnet.endpoint.scanner.runtime.services.RoleEndpointService;
import org.grnet.endpoint.scanner.runtime.validators.constraints.ValidRole;

import java.util.List;
import java.util.Map;

import static org.eclipse.microprofile.openapi.annotations.enums.ParameterIn.QUERY;

@Path("/roles")
@Authenticated
@SecurityScheme(securitySchemeName = "Authentication",
        description = "JWT token",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT",
        in = SecuritySchemeIn.HEADER)
public class RoleEndpoint {
    @Inject
    ResourceAuthorizationService resourceAuthorizationService;
    @Inject
    RoleEndpointService roleEndpointService;

    @Tag(name = "Quarkus Auth")
    @Operation(
            summary = "Create a new role.",
            description = "Creates a new role and associates it with the specified resource."
    )
    @APIResponse(
            responseCode = "200",
            description = "Role created successfully.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "401",
            description = "User has not been authenticated.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @APIResponse(
            responseCode = "403",
            description = "Not permitted.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @APIResponse(
            responseCode = "500",
            description = "Internal Server Error.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @SecuredEndpoint
    public Response createNewRole(@Valid @NotNull(message = "The request body is empty.") CreateRoleRequest request) {

        resourceAuthorizationService.createNewRole(request);

        var response = new InformativeResponse();
        response.code = 200;
        response.message = "Role created successfully.";

        return Response.ok().entity(response).build();
    }

    @Tag(name = "Quarkus Auth")
    @Operation(
            summary = "Update role attributes.",
            description = "Updates the attributes of an existing role."
    )
    @APIResponse(
            responseCode = "200",
            description = "Role attributes updated successfully.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "401",
            description = "User has not been authenticated.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @APIResponse(
            responseCode = "403",
            description = "Not permitted.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @APIResponse(
            responseCode = "404",
            description = "Role not found.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @APIResponse(
            responseCode = "500",
            description = "Internal Server Error.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @PUT
    @Path("/{id}/attributes")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @SecuredEndpoint
    public Response updateRoleAttributes(
            @PathParam("id") String id,
            @NotNull(message = "The request body is empty.")
            Map<String, List<String>> attributes) {

        resourceAuthorizationService.updateRoleAttributes(id, attributes);

        var response = new InformativeResponse();
        response.code = 200;
        response.message = "Role attributes updated successfully.";

        return Response.ok().entity(response).build();
    }

    @Tag(name = "Quarkus Auth")
    @Operation(
            summary = "List all roles.",
            description = "Returns a list of roles."
    )
    @APIResponse(
            responseCode = "200",
            description = "List of all roles.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = PageableRoleResponse.class)))
    @APIResponse(
            responseCode = "401",
            description = "User has not been authenticated.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @APIResponse(
            responseCode = "403",
            description = "Not permitted.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @APIResponse(
            responseCode = "500",
            description = "Internal Server Error.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @SecuredEndpoint
    public Response getAllRoles(
            @Parameter(name = "page", in = QUERY, description = "Indicates the page number. Page number must be >= 1.")
            @DefaultValue("1")
            @Min(value = 1, message = "Page number must be >= 1.")
            @QueryParam("page")
            int page,
            @Parameter(name = "size", in = QUERY, description = "The page size.")
            @DefaultValue("10")
            @Min(value = 1, message = "Page size must be between 1 and 100.")
            @Max(value = 100, message = "Page size must be between 1 and 100.")
            @QueryParam("size")
            int size, @Context UriInfo uriInfo) {

        var resources = resourceAuthorizationService.getAllRolesByPageAndSize(page - 1, size, uriInfo);

        return Response.ok().entity(resources).build();
    }

    @Tag(name = "Quarkus Auth")
    @Operation(
            summary = "Assign a new role to user.",
            description = "Assign a new role to user."
    )
    @APIResponse(
            responseCode = "200",
            description = "Role assigned successfully.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @APIResponse(
            responseCode = "401",
            description = "User has not been authenticated.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @APIResponse(
            responseCode = "403",
            description = "Not permitted.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @APIResponse(
            responseCode = "500",
            description = "Internal Server Error.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @POST
    @Path("/assign")
    @Produces(MediaType.APPLICATION_JSON)
    @SecuredEndpoint(
            params = {
                    @ParamRef(
                            param = "resource_id",
                            type = ParamType.BODY,
                            referToField = "api_resource"
                    )
            }
    )
    public Response assignRoleToUser(@Valid @NotNull(message = "The request body is empty.") AssignRoleRequest request) {

        var resources = resourceAuthorizationService.assignRoleToUser(request);

        return Response.ok().entity(resources).build();
    }

    @Tag(name = "Quarkus Auth")
    @Operation(
            summary = "Revoke a role from a member.",
            description = "Revoke a role from a member."
    )
    @APIResponse(
            responseCode = "200",
            description = "Role revoked successfully.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @APIResponse(
            responseCode = "401",
            description = "User has not been authenticated.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @APIResponse(
            responseCode = "403",
            description = "Not permitted.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @APIResponse(
            responseCode = "500",
            description = "Internal Server Error.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = Object.class)))
    @DELETE
    @Path("/revoke")
    @Produces(MediaType.APPLICATION_JSON)
    @SecuredEndpoint(
            params = {
                    @ParamRef(
                            param = "resource_id",
                            type = ParamType.BODY,
                            referToField = "api_resource"
                    )
            }
    )
    public Response revokeRoleFromUser(@Valid @NotNull(message = "The request body is empty.") RevokeRoleRequest request) {

        var response = resourceAuthorizationService.revokeRoleFromUser(request);

        return Response.ok().entity(response).build();
    }

    public static class PageableRoleResponse extends PageResource<RoleResponse> {

        private List<RoleResponse> content;

        @Override
        public List<RoleResponse> getContent() {
            return content;
        }

        @Override
        public void setContent(List<RoleResponse> content) {
            this.content = content;
        }
    }

    @Tag(name = "Quarkus Auth")
    @Operation(summary = "Assign secured endpoint to a specific role",
            description = "Assign secured endpoint to a specific role")
    @APIResponse(
            responseCode = "200",
            description = "Secured endpoints assigned successfully",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "401",
            description = "User has not been authenticated.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "403",
            description = "Not permitted.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "409",
            description = "Tenant already exists.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "500",
            description = "Internal Server Error.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "501",
            description = "Not Implemented.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @SecurityRequirement(name = "Authentication")
    @POST
    @Path("/{id}/assign-endpoints")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @SecuredEndpoint

    public Response bulkAssignPerRole(@Parameter(
                                              description = "The ID of the role.",
                                              required = true,
                                              example = "c242e43f-9869-4fb0-b881-631bc5746ec0",
                                              schema = @Schema(type = SchemaType.STRING)) @PathParam("id")
                                      @Valid @ValidRole String id,
                                      SecuredEndpointPerRoleRequest request) {

        roleEndpointService.assignRolesToEndpointsPerRole(id,request);
        var informativeResponse = new InformativeResponse();
        informativeResponse.code = 200;
        informativeResponse.message = "SecuredEndpoints assigned successfully";

        return Response.ok().entity(informativeResponse).build();
    }


    @Tag(name = "Quarkus Auth")
    @Operation(summary = "Retrieve assigned secured endpoints to roles",
            description = "Retrieve assigned secured endpoints to roles")
    @APIResponse(
            responseCode = "200",
            description = "Assigned secured endpoints retrieved successfully",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "401",
            description = "User has not been authenticated.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "403",
            description = "Not permitted.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "409",
            description = "SecuredEndpoint already exists.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "500",
            description = "Internal Server Error.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "501",
            description = "Not Implemented.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @SecurityRequirement(name = "Authentication")

    @GET
    @Path("/assigned-endpoints")
    @Produces(MediaType.APPLICATION_JSON)

    public Response getAssignedEndpointsPerRole() {

        RoleEndpointAssignmentResponse response =
                roleEndpointService.getAssignedEndpoints();

        return Response.ok(response).build();
    }



    @Tag(name = "Quarkus Auth")
    @Operation(summary = "Retrieve assigned secured endpoint to roles",
            description = "Retrieve assigned secured endpoint to roles")
    @APIResponse(
            responseCode = "200",
            description = "Assigned secured endpoints retrieved successfully",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "401",
            description = "User has not been authenticated.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "403",
            description = "Not permitted.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "409",
            description = "Secured Endpoint already exists.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "500",
            description = "Internal Server Error.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @APIResponse(
            responseCode = "501",
            description = "Not Implemented.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = InformativeResponse.class)))
    @SecurityRequirement(name = "Authentication")
    @GET
    @Path("/{id}/assigned-endpoints")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAssignedEndpointsPerRoleId(@Parameter(
            description = "The ID of the role.",
            required = true,
            example = "c242e43f-9869-4fb0-b881-631bc5746ec0",
            schema = @Schema(type = SchemaType.STRING)) @PathParam("id")
                                                  @Valid @ValidRole String id) {

        RoleEndpointAssignmentResponse response =
                roleEndpointService.getAssignedEndpointsByRoleId(id);

        return Response.ok(response).build();
    }

}


