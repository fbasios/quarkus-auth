package org.grnet.endpoint.scanner.runtime.repositories.mongo.codec;

import org.bson.codecs.Codec;
import org.bson.codecs.configuration.CodecProvider;
import org.bson.codecs.configuration.CodecRegistry;
import org.grnet.endpoint.scanner.runtime.entities.EndpointResolver;
import org.grnet.endpoint.scanner.runtime.entities.ResourceAuthorization;
import org.grnet.endpoint.scanner.runtime.entities.RoleEndpoint;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Actor;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.ActorEntitlements;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Entitlement;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Setting;

public class PersistenceEntitlementCodecProvider implements CodecProvider {
    @Override
    public <T> Codec<T> get(Class<T> clazz, CodecRegistry registry) {
        if (clazz.equals(Actor.class)) {
            return (Codec<T>) new ActorCodec();
        } else if (clazz.equals(Entitlement.class)) {
            return (Codec<T>) new EntitlementCodec();
        } else if (clazz.equals(ActorEntitlements.class)) {
            return (Codec<T>) new ActorEntitlementsCodec();
        } else if(clazz.equals(EndpointResolver.class)){
            return (Codec<T>) new EndpointResolverCodec();
        } else if(clazz.equals(ResourceAuthorization.class)){
            return (Codec<T>) new ResourceAuthorizationCodec();
        } else if(clazz.equals(Setting.class)){
            return (Codec<T>) new SettingCodec();
        } else if(clazz.equals(RoleEndpoint.class)){
            return (Codec<T>) new RoleEndpointCodec();
        }
        return null;
    }
}
