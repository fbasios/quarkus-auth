package org.grnet.endpoint.scanner.runtime.repositories.mongo.codec;

import org.bson.BsonInt64;
import org.bson.BsonReader;
import org.bson.BsonType;
import org.bson.BsonValue;
import org.bson.BsonWriter;
import org.bson.codecs.CollectibleCodec;
import org.bson.codecs.DecoderContext;
import org.bson.codecs.EncoderContext;
import org.grnet.endpoint.scanner.runtime.entities.RoleEndpoint;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

public class RoleEndpointCodec implements CollectibleCodec<RoleEndpoint> {

    public RoleEndpointCodec() {
    }

    @Override
    public RoleEndpoint generateIdIfAbsentFromDocument(RoleEndpoint roleEndpoint) {
        if (!documentHasId(roleEndpoint)) {
            roleEndpoint.setId(generateNewId());
        }
        return roleEndpoint;
    }

    @Override
    public boolean documentHasId(RoleEndpoint roleEndpoint) {
        return roleEndpoint.getId() != null;
    }

    @Override
    public BsonValue getDocumentId(RoleEndpoint roleEndpoint) {
        return new BsonInt64(roleEndpoint.getId());
    }

    @Override
    public RoleEndpoint decode(BsonReader reader, DecoderContext decoderContext) {
        var entity = new RoleEndpoint();
        reader.readStartDocument();

        while (reader.readBsonType() != BsonType.END_OF_DOCUMENT) {
            String fieldName = reader.readName();

            switch (fieldName) {
                case "_id":
                    entity.setId(reader.readInt64());
                    break;
                case "secured_endpoint_id":
                    entity.setSecuredEndpointId(reader.readString());
                    break;
                case "role_id":
                    entity.setRoleId(reader.readString());
                    break;
                case "role_name":
                    entity.setRoleName(reader.readString());
                    break;
                case "scope":
                    if (reader.getCurrentBsonType() == BsonType.NULL) {
                        reader.readNull();
                        entity.setScope(null);
                    } else {
                        entity.setScope(reader.readString());
                    }
                    break;
                case "created_at":
                    long millis = reader.readDateTime();
                    entity.setCreatedAt(LocalDateTime.ofInstant(
                            Instant.ofEpochMilli(millis),
                            ZoneId.systemDefault()
                    ));
                    break;
                default:
                    reader.skipValue();
                    break;
            }
        }

        reader.readEndDocument();
        return entity;
    }

    @Override
    public void encode(BsonWriter bsonWriter, RoleEndpoint roleEndpoint, EncoderContext encoderContext) {

        bsonWriter.writeStartDocument();
        bsonWriter.writeInt64("_id", roleEndpoint.getId());
        bsonWriter.writeString("role_name", roleEndpoint.getRoleName());
        if (roleEndpoint.getScope() != null) {
            bsonWriter.writeString("scope", roleEndpoint.getScope().toUpperCase());
        } else {
            bsonWriter.writeNull("scope");
        }
        bsonWriter.writeString("role_id", roleEndpoint.getRoleId());
        bsonWriter.writeString("secured_endpoint_id", roleEndpoint.getSecuredEndpointId());
        if (roleEndpoint.getCreatedAt() != null) {
            bsonWriter.writeDateTime("created_at",
                    roleEndpoint.getCreatedAt().atZone(ZoneId.systemDefault()).toInstant().toEpochMilli());
        } else {
            bsonWriter.writeDateTime("created_at", LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant().toEpochMilli());
        }
        bsonWriter.writeEndDocument();
    }

    @Override
    public Class<RoleEndpoint> getEncoderClass() {
        return RoleEndpoint.class;
    }

    private long generateNewId() {
        return System.currentTimeMillis();
    }
}
