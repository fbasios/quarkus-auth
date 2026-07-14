package org.grnet.endpoint.scanner.runtime.repositories.jdbc;

import org.grnet.endpoint.scanner.runtime.repositories.PersistenceEntitlementRepository;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.APISetting;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Actor;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.ActorEntitlements;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Entitlement;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Setting;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class PersistenceEntitlementJDBCRepository implements PersistenceEntitlementRepository {
    @Override
    public <T> void add(T entity, Class<T> clazz) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public Optional<Actor> findActorByOidcIdAndIssuer(String oidcId, String issuer) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public Long count(Class<?> clazz) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public <T> List<T> fetchAll(int page, int size, Class<T> clazz) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public <T> List<T> fetchAll(Class<T> clazz) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public long countDocuments(Date start, Date end, Class<?> clazz) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public Optional<Entitlement> findPersistenceEntitlementByName(String name) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public <T> Optional<T> findByIdOptional(String id, Class<T> clazz) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public <T> T findById(String id, Class<T> clazz) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public void updatePersistenceEntitlementName(String id, String name) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public void deleteById(String id, Class<?> clazz) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public boolean findAnyEntitlementUsedByActor(String entitlementId) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public List<String> findActorEntitlements(String actorId) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public List<Entitlement> findActorEntitlements(String actorId, int page, int size) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public long countActorEntitlements(String actorId) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public Optional<ActorEntitlements> findActorEntitlementByEntitlementAndActor(String entitlementId, String actorId) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public void deleteActorEntitlementByEntitlementAndActor(String entitlementId, String actorId) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public List<Actor> findAllActorsByEntitlementId(String entitlementId, int page, int size) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public long countAllActorByEntitlementId(String entitlementId) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public Optional<Setting> findSettingByKey(APISetting key) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public void saveOrUpdateSetting(APISetting key, String value) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }

    @Override
    public void updateEntitlementAttributes(String id, Map<String, List<String>> attributes) {
        throw new RuntimeException("Entitlement persistence is not supported for relational databases.");
    }
}
