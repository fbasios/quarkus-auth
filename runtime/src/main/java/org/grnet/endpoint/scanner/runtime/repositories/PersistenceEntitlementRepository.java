package org.grnet.endpoint.scanner.runtime.repositories;

import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.APISetting;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Actor;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.ActorEntitlements;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Entitlement;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Setting;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface PersistenceEntitlementRepository {

    <T> void add(T entity, Class<T> clazz);

    Optional<Actor> findActorByOidcIdAndIssuer(String oidcId, String issuer);

    Long count(Class<?> clazz);

    <T> List<T> fetchAll(int page, int size, Class<T> clazz);

    <T> List<T> fetchAll(Class<T> clazz);


    long countDocuments(Date start, Date end, Class<?> clazz);

    Optional<Entitlement> findPersistenceEntitlementByName(String name);

    <T> Optional<T> findByIdOptional(String id, Class<T> clazz);

    <T> T findById(String id, Class<T> clazz);

    void updatePersistenceEntitlementName(String id, String name);

    void deleteById(String id, Class<?> clazz);

    boolean findAnyEntitlementUsedByActor(String entitlementId);

    List<String> findActorEntitlements(String actorId);

    List<Entitlement> findActorEntitlements(String actorId, int page, int size);

    long countActorEntitlements(String actorId);

    Optional<ActorEntitlements> findActorEntitlementByEntitlementAndActor(String entitlementId, String actorId);

    void deleteActorEntitlementByEntitlementAndActor(String entitlementId, String actorId);

    List<Actor> findAllActorsByEntitlementId(String entitlementId, int page, int size);

    long countAllActorByEntitlementId(String entitlementId);

    Optional<Setting> findSettingByKey(APISetting key);

    void saveOrUpdateSetting(APISetting key, String value);

    void updateEntitlementAttributes(String id, Map<String, List<String>> attributes);
}
