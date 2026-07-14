package org.grnet.endpoint.scanner.runtime.repositories.mongo;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Aggregates;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Projections;
import com.mongodb.client.model.ReplaceOptions;
import jakarta.inject.Inject;
import org.bson.Document;
import org.bson.types.ObjectId;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.grnet.endpoint.scanner.runtime.repositories.PersistenceEntitlementRepository;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.APISetting;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Actor;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.ActorEntitlements;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Entitlement;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Setting;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.mongodb.client.model.Filters.and;
import static com.mongodb.client.model.Filters.eq;
import static com.mongodb.client.model.Updates.combine;
import static com.mongodb.client.model.Updates.set;

public class PersistenceEntitlementMongoRepository implements PersistenceEntitlementRepository {

    @Inject
    MongoClient mongoClient;

    @ConfigProperty(name = "quarkus.mongodb.database")
    String database;

    @Override
    public <T> void add(T document, Class<T> clazz){
        getCollectionByClass(clazz).insertOne(document);
    }

    @Override
    public Optional<Actor> findActorByOidcIdAndIssuer(String oidcId, String issuer) {

        var actor = getCollectionByClass(Actor.class)
                .find(and(
                        eq("oidc_id", oidcId),
                        eq("issuer", issuer)
                )).first();

        if(Objects.isNull(actor)){
            return Optional.empty();
        } else {
            return Optional.of(actor);
        }
    }

    @Override
    public Long count(Class<?> clazz){

        var count = getCollection(clazz)
                .aggregate(List.of(Aggregates.count()))
                .first();

        return count == null ? 0L : Long.parseLong(count.get("count").toString());
    }

    @Override
    public <T> List<T> fetchAll(int page, int size, Class<T> clazz) {

        return getCollectionByClass(clazz)
                .aggregate(List.of(Aggregates.skip(size * (page)), Aggregates.limit(size)))
                .into(new ArrayList<>());
    }

    @Override
    public <T> List<T> fetchAll(Class<T> clazz) {

        return getCollectionByClass(clazz)
                .find()
                .into(new ArrayList<>());
    }

    @Override
    public long countDocuments(Date start, Date end, Class<?> clazz) {

        return getCollection(clazz).countDocuments(Filters.and(Filters.gte("registered_on", start), Filters.lte("registered_on", adjustEndDate(end))));
    }

    @Override
    public Optional<Entitlement> findPersistenceEntitlementByName(String name){

        var entitlement = getCollectionByClass(Entitlement.class)
                .find(and(
                        eq("name", name)
                )).first();

        if(Objects.isNull(entitlement)){
            return Optional.empty();
        } else {
            return Optional.of(entitlement);
        }
    }

    @Override
    public <T> Optional<T> findByIdOptional(String id, Class<T> clazz) {

        var document = getCollectionByClass(clazz)
                .find(and(
                        eq("_id", id)
                )).first();

        if(Objects.isNull(document)){
            return Optional.empty();
        } else {
            return Optional.of(document);
        }
    }

    @Override
    public <T> T findById(String id, Class<T> clazz) {

        return getCollectionByClass(clazz)
                .find(and(
                        eq("_id", id)
                )).first();
    }

    @Override
    public void updatePersistenceEntitlementName(String id, String name) {

        getCollectionByClass(Entitlement.class)
                .updateOne(
                eq("_id", id),
                combine(
                        set("name", name),
                        set("registeredOn", LocalDateTime.now())
                )
        );
    }

    @Override
    public void updateEntitlementAttributes(String id, Map<String, List<String>> attributes) {

        getCollectionByClass(Entitlement.class)
                .updateOne(
                        eq("_id", id),
                        combine(
                                set("attributes", attributes),
                                set("registeredOn", LocalDateTime.now())
                        )
                );
    }

    @Override
    public void deleteById(String id, Class<?> clazz) {
        getCollectionByClass(clazz).deleteOne(eq("_id", id));
    }

    @Override
    public boolean findAnyEntitlementUsedByActor(String entitlementId){

        var entitlement = getCollectionByClass(ActorEntitlements.class)
                .find(and(
                        eq("entitlement_id", entitlementId)
                )).first();

        if(Objects.isNull(entitlement)){
            return false;
        } else {
            return true;
        }
    }

    @Override
    public List<String> findActorEntitlements(String actorId){

        var eq = Aggregates
                .match(Filters.eq("actor_id", actorId));

        var lookup = Aggregates.lookup("Entitlement", "entitlement_id", "_id", "details");

        var unwindDetails = Aggregates
                .unwind("$details");

        var projection = Aggregates.project(Projections.fields(
                Projections.excludeId(),
                Projections.computed("name", "$details.name")));

        var names = getCollection(ActorEntitlements.class)
                .aggregate(List.of(eq, lookup, unwindDetails, projection))
                .into(new ArrayList<>());

        return names.stream().map(doc->doc.getString("name")).collect(Collectors.toList());
    }

    @Override
    public List<Entitlement> findActorEntitlements(String actorId, int page, int size){

        var eq = Aggregates
                .match(Filters.eq("actor_id", actorId));

        var lookup = Aggregates.lookup("Entitlement", "entitlement_id", "_id", "entitlements");

        var unwindDetails = Aggregates
                .unwind("$entitlements");

        var projection = Aggregates.project(Projections.fields(
                Projections.computed("id", "$entitlements._id"),
                Projections.computed("registeredOn", "$entitlements.registered_on"),
                Projections.computed("name", "$entitlements.name")));

        return getCollectionByClass(ActorEntitlements.class)
                .aggregate(List.of(eq, lookup, unwindDetails, projection, Aggregates.skip(size * (page)), Aggregates.limit(size)), Entitlement.class)
                .into(new ArrayList<>());
    }

    @Override
    public long countActorEntitlements(String actorId) {

        var eq = Aggregates
                .match(Filters.eq("actor_id", actorId));

        var count = getCollection(ActorEntitlements.class)
                .aggregate(List.of(eq, Aggregates.count()))
                .first();

        return count == null ? 0L : Long.parseLong(count.get("count").toString());
    }

    @Override
    public Optional<ActorEntitlements> findActorEntitlementByEntitlementAndActor(String entitlementId, String actorId){

        var actorEntitlements = getCollectionByClass(ActorEntitlements.class)
                .find(and(
                        eq("actor_id", actorId),
                        eq("entitlement_id", entitlementId)
                )).first();

        if(Objects.isNull(actorEntitlements)){
            return Optional.empty();
        } else {
            return Optional.of(actorEntitlements);
        }
    }

    @Override
    public void deleteActorEntitlementByEntitlementAndActor(String entitlementId, String actorId) {

        getCollectionByClass(ActorEntitlements.class)
                .deleteOne(and(eq("entitlement_id", entitlementId), eq("actor_id", actorId)));
    }

    @Override
    public List<Actor> findAllActorsByEntitlementId(String entitlementId, int page, int size) {


        var eq = Aggregates
                .match(Filters.eq("entitlement_id", entitlementId));

        var lookup = Aggregates.lookup("Actor", "actor_id", "_id", "actors");

        var unwindDetails = Aggregates
                .unwind("$actors");

        var projection = Aggregates.project(Projections.fields(
                Projections.computed("_id", "$actors._id"),
                Projections.computed("registeredOn", "$actors.registered_on"),
                Projections.computed("name", "$actors.name"),
                Projections.computed("email", "$actors.email"),
                Projections.computed("issuer", "$actors.issuer"),
                Projections.computed("oidcId", "$actors.oidc_id")));

        List<Document> raw = getCollectionByClass(ActorEntitlements.class)
                .aggregate(List.of(eq, lookup, unwindDetails, projection), Document.class)
                .into(new ArrayList<>());

        raw.forEach(System.out::println);

        return getCollectionByClass(ActorEntitlements.class)
                .aggregate(List.of(eq, lookup, unwindDetails, projection, Aggregates.skip(size * (page)), Aggregates.limit(size)), Actor.class)
                .into(new ArrayList<>());
    }

    @Override
    public long countAllActorByEntitlementId(String entitlementId) {

        var eq = Aggregates
                .match(Filters.eq("entitlement_id", entitlementId));

        var count = getCollection(ActorEntitlements.class)
                .aggregate(List.of(eq, Aggregates.count()))
                .first();

        return count == null ? 0L : Long.parseLong(count.get("count").toString());
    }

    @Override
    public Optional<Setting> findSettingByKey(APISetting key) {
        var setting = getCollectionByClass(Setting.class)
                .find(and(
                        eq("key", key)
                )).first();

        if(Objects.isNull(setting)){
            return Optional.empty();
        } else {
            return Optional.of(setting);
        }
    }

    @Override
    public void saveOrUpdateSetting(APISetting key, String value) {

        var setting = findSettingByKey(key).orElseGet(() -> {
            var s = new Setting();
            s.setKey(key);
            s.setId(new ObjectId().toString());
            return s;
        });
        setting.setValue(value);

        getCollectionByClass(Setting.class)
                .replaceOne(
                eq("_id", setting.getId()),
                setting,
                new ReplaceOptions().upsert(true)
        );
    }

    private <T> MongoCollection<T> getCollectionByClass(Class<T> clazz){
        return mongoClient.getDatabase(database).getCollection(clazz.getSimpleName(), clazz);
    }

    private MongoCollection<Document> getCollection(Class<?> clazz){
        return mongoClient.getDatabase(database).getCollection(clazz.getSimpleName());
    }

    /**
     * Adjusts the given date to the end of the day (23:59:59.999).
     * @param date The original end date.
     * @return A new Date set to 23:59:59.999 of the given day.
     */
    private Date adjustEndDate(Date date) {

        var calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.set(Calendar.HOUR_OF_DAY, 23);
        calendar.set(Calendar.MINUTE, 59);
        calendar.set(Calendar.SECOND, 59);
        calendar.set(Calendar.MILLISECOND, 999);
        return calendar.getTime();
    }
}
