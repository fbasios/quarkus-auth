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
import org.eclipse.microprofile.openapi.annotations.security.SecurityScheme;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.grnet.endpoint.scanner.runtime.EndpointMetadata;
import org.grnet.endpoint.scanner.runtime.SecuredEndpoint;
import org.grnet.endpoint.scanner.runtime.dtos.AuthorizationRequest;
import org.grnet.endpoint.scanner.runtime.dtos.EndpointResolverRequest;
import org.grnet.endpoint.scanner.runtime.entities.EndpointResolver;
import org.grnet.endpoint.scanner.runtime.entities.ResourceAuthorization;
import org.grnet.endpoint.scanner.runtime.services.EndpointResolverService;
import org.grnet.endpoint.scanner.runtime.services.ResourceAuthorizationService;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.eclipse.microprofile.openapi.annotations.enums.ParameterIn.QUERY;

@Path("/secured-endpoints")
@Authenticated
@Tag(name = "Quarkus Auth")
@SecurityScheme(securitySchemeName = "Authentication",
        description = "JWT token",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT",
        in = SecuritySchemeIn.HEADER)
public class SecuredEndpointResource {
    @Inject
    EndpointResolverService endpointResolverService;

    @Inject
    ResourceAuthorizationService resourceAuthorizationService;

    @Operation(
            summary = "List secured endpoints.",
            description = "Retrieves all registered secured endpoints, " +
                    "including their HTTP method, path, description, and required scopes."
    )
    @APIResponse(
            responseCode = "200",
            description = "List of all secured endpoints.",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = PageableSecuredEndpoints.class)))
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
    public Response getSecuredEndpoints(
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

        var securedEndpoints = resourceAuthorizationService.getSecuredEndpointsByPage(page - 1, size, uriInfo);

        return Response.ok().entity(securedEndpoints).build();
    }

    @Operation(
            summary = "Create/Update authorization rule for a secured endpoint.",
            description = "Create authorization rule."
    )
    @APIResponse(
            responseCode = "200",
            description = "Successfully created rule.",
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
            responseCode = "409",
            description = "Rule already exists.",
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
    @Path("/{secured-endpoint-id}/rules")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @SecuredEndpoint
    public List<ResourceAuthorization> addAuthorizations(@Parameter(
            description = "The unique secured endpoint id.",
            required = true,
            example = "d9ae97f603809444ad911be3b30596462003d11bb06e928ac005bf4b1bb8c4a9",
            schema = @Schema(type = SchemaType.STRING)) @PathParam("secured-endpoint-id") String id,
            @Valid @NotNull(message = "The request body is empty.") AuthorizationRequest request) {
// Existing rules for the endpoint
        List<ResourceAuthorization> existingRules =
                resourceAuthorizationService.findByEndpointSecuredEndpointId(id);

        Set<String> incomingRules = new HashSet<>(request.rules);

        // Existing regex values
        Set<String> existingRegexes = existingRules.stream()
                .map(ResourceAuthorization::getRule)
                .collect(Collectors.toSet());

        // Add new rules that do not already exist
        for (String regex : incomingRules) {
            if (!existingRegexes.contains(regex)) {
                ResourceAuthorization re = new ResourceAuthorization();
                re.setSecuredEndpointId(id);
                re.setRule(regex);
                re.setCreatedAt(LocalDateTime.now());

                resourceAuthorizationService.authorize(re);
            }
        }

        // Remove rules that are no longer included in the request
        for (ResourceAuthorization existing : existingRules) {
            if (!incomingRules.contains(existing.getRule())) {
                resourceAuthorizationService.delete(existing.getId());
            }
        }


        return resourceAuthorizationService.findByEndpointSecuredEndpointId(id);
    }

    @Operation(
            summary = "Create mapping between entity fields for endpoint  in order to resolve.",
            description = "Create mapping between entity fields for endpoint in order to resolve."
    )
    @APIResponse(
            responseCode = "200",
            description = "Successfully updated rules.",
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
            responseCode = "409",
            description = "Rule already exists.",
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
    @Path("/{secured-endpoint-id}/resolved")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @SecuredEndpoint
    public List<EndpointResolver> addResolvedField(@Parameter(
            description = "The unique secured endpoint id.",
            required = true,
            example = "d9ae97f603809444ad911be3b30596462003d11bb06e928ac005bf4b1bb8c4a9",
            schema = @Schema(type = SchemaType.STRING)) @PathParam("secured-endpoint-id") String id,
            @Valid @NotNull(message = "The request body is empty.") EndpointResolverRequest request) {

        var e = new EndpointResolver();
        e.setResource(request.resource);
        e.setMappedField(request.mapped_field);
        e.setOriginalField(request.original_field);
        e.setSecuredEndpointId(id);
        e.setCreatedAt(LocalDateTime.now());
        endpointResolverService.addResolvedField(e);

        return endpointResolverService.findAllEndpointResolverByEndpoint(id);
    }

    @Operation(
            summary = "Get authorization resource rules for a secured endpoint",
            description = "CGet authorization resource rules"
    )
    @APIResponse(
            responseCode = "200",
            description = "List of authorization resource rules",
            content = @Content(schema = @Schema(
                    type = SchemaType.ARRAY,
                    implementation = ResourceAuthorization.class)))
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
            responseCode = "409",
            description = "Rule already exists.",
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
    @Path("/{secured-endpoint-id}/rules")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public List<ResourceAuthorization> getResourceAuthorizationList(
            @PathParam("secured-endpoint-id") String id) {
        return resourceAuthorizationService.findByEndpointSecuredEndpointId(id);
    }

    @Operation(
            summary = "Get a specific resource authorization  rule by id",
            description = "Get resource authorization rule"
    )
    @APIResponse(
            responseCode = "200",
            description = "Resource authorization rule",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = ResourceAuthorization.class)))
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
            responseCode = "409",
            description = "Rule already exists.",
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
    @Path("/resource-authorizations/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public ResourceAuthorization getResourceAuthorizationById(
            @PathParam("id") Long id) {
        return resourceAuthorizationService.findById(id);
    }

    @Operation(
            summary = "Get resolved fields for a secured endpoint",
            description = "Get resolved fields for a secured endpoint"
    )
    @APIResponse(
            responseCode = "200",
            description = "List of resolved fields",
            content = @Content(schema = @Schema(
                    type = SchemaType.ARRAY,
                    implementation = ResourceAuthorization.class)))
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
            responseCode = "409",
            description = "Resolved field already exists.",
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
    @Path("/{secured-endpoint-id}/resolved")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @SecuredEndpoint
    public List<EndpointResolver> getSecuredEndpointResolvedList(
            @PathParam("secured-endpoint-id") String id) {
        return endpointResolverService.findAllEndpointResolver();
    }

    @Operation(
            summary = "Update resolved field for or a secured endpoint",
            description = "Update resolved field for or a secured endpoint"
    )
    @APIResponse(
            responseCode = "200",
            description = "Successfully updated rules",
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
            responseCode = "409",
            description = "Rule already exists.",
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
    @Path("/endpoint-resolver/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @SecuredEndpoint
    public EndpointResolver updateEndpointResolver(
            @PathParam("id") Long id,
            EndpointResolverRequest request) {

        var existing = endpointResolverService.findById(id);
        if (existing == null) {
            throw new NotFoundException("ResourceAuthorization with id " + id + " not found");
        }

        existing.setResource(request.resource);
        existing.setOriginalField(request.original_field);
        existing.setMappedField(request.mapped_field);
        existing.setCreatedAt(LocalDateTime.now());

        endpointResolverService.update(existing);

        return existing;
    }

    @Operation(
            summary = "Delete resolved fields for secured endpoint",
            description = "Delete resolved field"
    )
    @APIResponse(
            responseCode = "200",
            description = "Successfully deleted resolver",
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
            responseCode = "409",
            description = "Resolved field already exists.",
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
    @Path("/endpoint-resolver/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    @SecuredEndpoint
    public Response deleteEndpointResolver(@PathParam("id") Long id) {

        EndpointResolver existing = endpointResolverService.findById(id);
        if (existing == null) {
            throw new NotFoundException("ResourceAuthorization with id " + id + " not found");
        }

        endpointResolverService.delete(id);
        return Response.ok(Map.of("message", "Successfully deleted")).build();
    }

    @Operation(
            summary = "Get a specific resolved field  by id",
            description = "Get a specific resolved field"
    )
    @APIResponse(
            responseCode = "200",
            description = "Resolved field rule",
            content = @Content(schema = @Schema(
                    type = SchemaType.OBJECT,
                    implementation = ResourceAuthorization.class)))
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
            responseCode = "409",
            description = "Rule already exists.",
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
    @Path("/endpoint-resolved/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @SecuredEndpoint
    public EndpointResolver getEndpointResolverById(
            @PathParam("id") Long id) {
        return endpointResolverService.findById(id);
    }

    public static class PageableSecuredEndpoints extends PageResource<EndpointMetadata> {

        private List<EndpointMetadata> content;

        @Override
        public List<EndpointMetadata> getContent() {
            return content;
        }

        @Override
        public void setContent(List<EndpointMetadata> content) {
            this.content = content;
        }
    }
}


