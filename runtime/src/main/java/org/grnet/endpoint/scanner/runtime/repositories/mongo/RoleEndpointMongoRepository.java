package org.grnet.endpoint.scanner.runtime.repositories.mongo;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import jakarta.inject.Inject;
import org.bson.Document;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.grnet.endpoint.scanner.runtime.entities.EndpointResolver;
import org.grnet.endpoint.scanner.runtime.entities.ResourceAuthorization;
import org.grnet.endpoint.scanner.runtime.entities.RoleEndpoint;
import org.grnet.endpoint.scanner.runtime.repositories.RoleEndpointRepository;

import java.util.ArrayList;
import java.util.List;

import static com.mongodb.client.model.Filters.and;
import static com.mongodb.client.model.Filters.eq;

public class RoleEndpointMongoRepository implements RoleEndpointRepository {

    @Inject
    MongoClient mongoClient;

    @ConfigProperty(name = "quarkus.mongodb.database")
    String database;


    @Override
    public List<RoleEndpoint> list(String column, String id) {
        return getCollectionByClass(RoleEndpoint.class)
                .find(and(
                        eq(column, id)
                )).into(new ArrayList<>());
    }

    @Override
    public void create(RoleEndpoint entity) {
        getCollectionByClass(RoleEndpoint.class).insertOne(entity);
    }

    @Override
    public RoleEndpoint findById(Long id) {
        return getCollectionByClass(RoleEndpoint.class)
                .find(and(
                        eq("_id", id)
                )).first();
    }

    @Override
    public void update(RoleEndpoint entity) {
        getCollectionByClass(RoleEndpoint.class).replaceOne(
                Filters.eq("_id", entity.getId()),
                entity
        );
    }

    @Override
    public void delete(Long id) {
        getCollectionByClass(RoleEndpoint.class).deleteOne(Filters.eq("_id", id));
    }

    @Override
    public void deleteByRoleIdAndEndpointId(String roleId, String securedEndpointId) {
        getCollectionByClass(RoleEndpoint.class).deleteMany(
                Filters.and(
                        Filters.eq("role_id", roleId),
                        Filters.eq("secured_endpoint_id", securedEndpointId)
                )
        );
    }

    @Override
    public void deleteByRoleIdAndEndpointIds(String roleId, List<String> securedEndpointId) {

        if (securedEndpointId == null || securedEndpointId.isEmpty()) {
            return;
        }

        getCollectionByClass(RoleEndpoint.class).deleteMany(
                Filters.and(
                        Filters.eq("role_id", roleId),
                        Filters.in("secured_endpoint_id", securedEndpointId)
                )
        );
    }

    @Override
    public void deleteByRoleId(String roleId) {
        getCollectionByClass(RoleEndpoint.class).deleteMany(
                Filters.eq("role_id", roleId)
        );
    }

    @Override
    public List<RoleEndpoint> findAll() {
        return getCollectionByClass(RoleEndpoint.class).find().into(new ArrayList<>());
    }

    private <T> MongoCollection<T> getCollectionByClass(Class<T> clazz){
        return mongoClient.getDatabase(database).getCollection(clazz.getSimpleName(), clazz);
    }

    private MongoCollection<Document> getCollection(Class<?> clazz) {
        return mongoClient.getDatabase(database).getCollection(clazz.getSimpleName());
    }

}

