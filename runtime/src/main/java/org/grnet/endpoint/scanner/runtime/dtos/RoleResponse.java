package org.grnet.endpoint.scanner.runtime.dtos;

import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Schema(name="RoleResponse", description="Represents a role entity returned from the role management system.")
public class RoleResponse {

    @Schema(
            type = SchemaType.STRING,
            implementation = String.class,
            description = "The unique identifier of the role.",
            example = "759e745e-bc94-4488-a452-c08e1ebe6fe8"
    )
    public String id;

    @Schema(
            type = SchemaType.STRING,
            implementation = String.class,
            description = "The name of the role.",
            example = "admin"
    )
    public String name;

    @Schema(
            type = SchemaType.OBJECT,
            implementation = Map.class,
            description = "Optional role attributes.",
            example = "{\"preferred_name\":[\"Administrator\"],\"description\":[\"Administrative role\"]}"
    )
    public Map<String, List<String>> attributes = new HashMap<>();

    public RoleResponse() {
    }

    public RoleResponse(String id, String name) {
        this.id = id;
        this.name = name;
    }

    public RoleResponse(String id, String name, Map<String, List<String>> attributes) {
        this.id = id;
        this.name = name;
        this.attributes = attributes;
    }
}
