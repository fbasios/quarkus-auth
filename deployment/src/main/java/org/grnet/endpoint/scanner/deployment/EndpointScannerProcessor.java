package org.grnet.endpoint.scanner.deployment;

import io.quarkus.agroal.spi.JdbcDataSourceBuildItem;
import io.quarkus.arc.deployment.*;
import io.quarkus.arc.processor.DotNames;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.Consume;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Produce;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.AdditionalIndexedClassesBuildItem;
import io.quarkus.deployment.builditem.CombinedIndexBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.oidc.TokenIntrospection;
import jakarta.enterprise.context.ApplicationScoped;
import org.grnet.endpoint.scanner.runtime.*;
import org.grnet.endpoint.scanner.runtime.clients.KeycloakClientCredentialsTokenProvider;
import org.grnet.endpoint.scanner.runtime.clients.groupmanagement.*;
import org.grnet.endpoint.scanner.runtime.clients.groupmanagement.response.GroupUserResponse;
import org.grnet.endpoint.scanner.runtime.clients.groupmanagement.response.PartialGroup;
import org.grnet.endpoint.scanner.runtime.clients.groupmanagement.response.UserGroupInfoDto;
import org.grnet.endpoint.scanner.runtime.context.RoleEndpointCleanupFilter;
import org.grnet.endpoint.scanner.runtime.context.RoleEndpointContext;
import org.grnet.endpoint.scanner.runtime.context.RoleEndpointHolder;
import org.grnet.endpoint.scanner.runtime.endpoints.*;
import org.grnet.endpoint.scanner.runtime.dtos.AssignRoleRequest;
import org.grnet.endpoint.scanner.runtime.dtos.CreateRoleRequest;
import org.grnet.endpoint.scanner.runtime.dtos.RoleResponse;
import org.grnet.endpoint.scanner.runtime.dtos.UserProfileDto;
import org.grnet.endpoint.scanner.runtime.endpoints.RoleEndpoint;
import org.grnet.endpoint.scanner.runtime.internal.AuthGroupInitializer;
import org.grnet.endpoint.scanner.runtime.internal.AgmGroupCache;
import org.grnet.endpoint.scanner.runtime.repositories.EndpointResolverRepository;
import org.grnet.endpoint.scanner.runtime.repositories.PersistenceEntitlementRepository;
import org.grnet.endpoint.scanner.runtime.repositories.ResourceAuthorizationRepository;
import org.grnet.endpoint.scanner.runtime.repositories.RoleEndpointRepository;
import org.grnet.endpoint.scanner.runtime.repositories.jdbc.EndpointResolverJdbcRepository;
import org.grnet.endpoint.scanner.runtime.repositories.jdbc.PersistenceEntitlementJDBCRepository;
import org.grnet.endpoint.scanner.runtime.repositories.jdbc.ResourceAuthorizationJdbcRepository;
import org.grnet.endpoint.scanner.runtime.repositories.jdbc.RoleEndpointJdbcRepository;
import org.grnet.endpoint.scanner.runtime.repositories.mongo.EndpointResolverMongoRepository;
import org.grnet.endpoint.scanner.runtime.repositories.mongo.ResourceAuthorizationMongoRepository;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Actor;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.ActorEntitlements;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Entitlement;
import org.grnet.endpoint.scanner.runtime.entities.entitlements.persistence.Setting;
import org.grnet.endpoint.scanner.runtime.repositories.mongo.PersistenceEntitlementMongoRepository;
import org.grnet.endpoint.scanner.runtime.repositories.mongo.RoleEndpointMongoRepository;
import org.grnet.endpoint.scanner.runtime.repositories.mongo.codec.ActorCodec;
import org.grnet.endpoint.scanner.runtime.repositories.mongo.codec.ActorEntitlementsCodec;
import org.grnet.endpoint.scanner.runtime.repositories.mongo.codec.EntitlementCodec;
import org.grnet.endpoint.scanner.runtime.repositories.mongo.codec.PersistenceEntitlementCodecProvider;
import org.grnet.endpoint.scanner.runtime.repositories.mongo.codec.ResourceAuthorizationCodec;
import org.grnet.endpoint.scanner.runtime.repositories.mongo.codec.RoleEndpointCodec;
import org.grnet.endpoint.scanner.runtime.repositories.mongo.codec.SettingCodec;
import org.grnet.endpoint.scanner.runtime.entities.pagination.Page;
import org.grnet.endpoint.scanner.runtime.entities.pagination.PageQuery;
import org.grnet.endpoint.scanner.runtime.entitlements.EntitlementProviderWithPersistence;
import org.grnet.endpoint.scanner.runtime.entitlements.EntitlementProviderWithoutPersistence;
import org.grnet.endpoint.scanner.runtime.entitlements.EntitlementService;
import org.grnet.endpoint.scanner.runtime.entitlements.UserContextInterface;
import org.grnet.endpoint.scanner.runtime.entitlements.qualifiers.OidcEntitlement;
import org.grnet.endpoint.scanner.runtime.entitlements.qualifiers.PersistenceEntitlement;

import org.grnet.endpoint.scanner.runtime.entities.*;
import org.grnet.endpoint.scanner.runtime.process.AfterProcessing;
import org.grnet.endpoint.scanner.runtime.process.BeforeProcessing;
import org.grnet.endpoint.scanner.runtime.process.Event;
import org.grnet.endpoint.scanner.runtime.resolvers.GroupIdResolver;
import org.grnet.endpoint.scanner.runtime.services.*;
import org.grnet.endpoint.scanner.runtime.database.SchemaInitializer;
import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.AnnotationTarget;
import org.jboss.jandex.AnnotationValue;
import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.ClassType;
import org.jboss.jandex.DotName;
import org.jboss.jandex.IndexView;
import org.jboss.jandex.MethodInfo;
import org.jboss.logging.Logger;

import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BooleanSupplier;

class EndpointScannerProcessor {

    private static final Logger LOG = Logger.getLogger(EndpointScannerProcessor.class);

    private static final String FEATURE = "endpoint-scanner";

    private static final Map<DotName, String> HTTP_METHOD_NAMES = Map.of(
            DotName.createSimple("jakarta.ws.rs.GET"), "GET",
            DotName.createSimple("jakarta.ws.rs.POST"), "POST",
            DotName.createSimple("jakarta.ws.rs.PUT"), "PUT",
            DotName.createSimple("jakarta.ws.rs.DELETE"), "DELETE",
            DotName.createSimple("jakarta.ws.rs.PATCH"), "PATCH"
    );

    private static final DotName PATH = DotName.createSimple("jakarta.ws.rs.Path");

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    @BuildStep
    EndpointMetadataBuildItem scan(CombinedIndexBuildItem indexBuildItem) {

        // Quarkus provides the index automatically
        var index = indexBuildItem.getIndex();

        var endpoints = new ArrayList<EndpointMetadata>();

        var securedAnnotation = DotName.createSimple(
                "org.grnet.endpoint.scanner.runtime.SecuredEndpoint"
        );


        for (AnnotationInstance annotation : index.getAnnotations(securedAnnotation)) {

            if (annotation.target().kind() != AnnotationTarget.Kind.METHOD) {
                continue; // ignore class-level and interceptor usage
            }

            var method = annotation.target().asMethod();

            String httpMethod = method.annotations().stream()
                    .filter(a -> HTTP_METHOD_NAMES.containsKey(a.name()))
                    .map(a -> HTTP_METHOD_NAMES.get(a.name()))
                    .findFirst()
                    .orElse(null);

            if (httpMethod == null) {
                continue; // not a REST endpoint
            }


            // Read @Path from the method (e.g. "/items/{id}")
            String methodPath = "";
            var methodPathAnnotation = method.annotation(PATH);
            if (methodPathAnnotation != null) {
                methodPath = methodPathAnnotation.value().asString();
            }

            // Read @Path from the declaring class (e.g. "/api/v1")
            String classPath = "";
            var declaringClass = method.declaringClass();
            var classPathAnnotation = declaringClass.annotationsMap()
                    .getOrDefault(PATH, List.of())
                    .stream()
                    .filter(a -> a.target().kind() == AnnotationTarget.Kind.CLASS)
                    .findFirst()
                    .orElse(null);

            if (classPathAnnotation != null) {
                classPath = classPathAnnotation.value().asString();
            }

            // Combine them, normalizing slashes
            var fullPath = normalizePath(classPath, methodPath);

            String description = "There is no description for this endpoint!";

            var operationAnnotation = method.annotation(DotName.createSimple("org.eclipse.microprofile.openapi.annotations.Operation"));

            if (operationAnnotation != null) {
                var descriptionValue = operationAnnotation.value("description");

                if (descriptionValue != null) {
                    description = descriptionValue.asString();
                }
            }

            Set<Scope> scopes = new HashSet<>();

            AnnotationValue scopeValue = annotation.value("scope");

            if (scopeValue != null && scopeValue.asEnumArray() != null) {
                for (var enumVal : scopeValue.asEnumArray()) {
                    scopes.add(Scope.valueOf(enumVal));
                }
            }
            addEndpoint(endpoints, new EndpointMetadata(generateSecuredEndpointId(httpMethod, fullPath), httpMethod, fullPath, description, scopes));
        }

        return new EndpointMetadataBuildItem(endpoints);
    }

    private String normalizePath(String classPath, String methodPath) {
        // Ensure class path starts with /
        if (!classPath.startsWith("/")) classPath = "/" + classPath;
        // Remove trailing slash from class path
        if (classPath.endsWith("/")) classPath = classPath.substring(0, classPath.length() - 1);
        // Ensure method path starts with /
        if (!methodPath.isEmpty() && !methodPath.startsWith("/")) methodPath = "/" + methodPath;

        return classPath + methodPath;
    }

    private void addEndpoint(List<EndpointMetadata> endpoints, EndpointMetadata endpoint) {

        if (endpoints.contains(endpoint)) {
            throw new IllegalArgumentException(
                    "Duplicate endpoint detected: action=%s, path=%s"
                            .formatted(endpoint.getAction(), endpoint.getPath()));
        }

        endpoints
                .stream()
                .map(EndpointMetadata::getSecuredEndpointId)
                .filter(hashed -> hashed.equals(endpoint.getSecuredEndpointId()))
                .findAny()
                .ifPresent(val -> {
                    throw new IllegalArgumentException("Duplicate hashed secured endpoint id detected: " + val);
                });

        endpoints.add(endpoint);
    }

    private String generateSecuredEndpointId(String httpMethod, String path) {

        var raw = httpMethod + path;
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate securedEndpointId hash", e);
        }
    }

    @BuildStep
    void registerResource(BuildProducer<AdditionalIndexedClassesBuildItem> additionalIndexedClasses, BuildProducer<AdditionalBeanBuildItem> additionalBeans) {

        additionalBeans.produce(new AdditionalBeanBuildItem(SecuredEndpointResource.class));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(SecuredEndpointResource.class.getName()));
        additionalBeans.produce(new AdditionalBeanBuildItem(ApiResourceEndpoint.class));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(ApiResourceEndpoint.class.getName()));
        additionalBeans.produce(new AdditionalBeanBuildItem(RoleEndpoint.class));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(UserEndpoint.class.getName()));
        additionalBeans.produce(new AdditionalBeanBuildItem(UserEndpoint.class));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(GroupManagementEndpoint.class.getName()));
        additionalBeans.produce(new AdditionalBeanBuildItem(GroupManagementEndpoint.class));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(RoleEndpoint.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(ResourceAuthorization.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(EndpointResolver.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(RoleEndpoint.class.getName()));

        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(Actor.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(Entitlement.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(ActorEntitlements.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(Setting.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(PageLink.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(PageResource.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(GroupUserResponse.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(PartialGroup.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(UserGroupInfoDto.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(Page.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(PageQuery.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(SecuredEndpointResource.PageableSecuredEndpoints.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(ApiResourceEndpoint.PageableApiResources.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(EndpointMetadata.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(ApiResourceMetadata.class.getName()));
        additionalBeans.produce(new AdditionalBeanBuildItem(KeycloakGroupManagementClient.class));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(KeycloakGroupManagementClient.class.getName()));
        additionalBeans.produce(new AdditionalBeanBuildItem(KeycloakTokenClient.class));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(KeycloakTokenClient.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(Event.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(InformativeResponse.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(AssignRoleRequest.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(CreateRoleRequest.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(UserProfileDto.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(RoleResponse.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(RoleEndpoint.PageableRoleResponse.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(Scope.class.getName()));
        additionalBeans.produce(new AdditionalBeanBuildItem(RoleEndpointCleanupFilter.class));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(AgmGroupCache.class.getName()));
        additionalBeans.produce(AdditionalBeanBuildItem.unremovableOf(AgmGroupCache.class));
    }

    @BuildStep
    void registerSecurityInterceptors(BuildProducer<InterceptorBindingRegistrarBuildItem> registrars, BuildProducer<AdditionalBeanBuildItem> beans) {

        registrars.produce(new InterceptorBindingRegistrarBuildItem(new AuthorizationAnnotationsRegistrar()));

        Class<?>[] interceptors = {SecuredEndpointInterceptor.class};
        beans.produce(new AdditionalBeanBuildItem(interceptors));
    }

    @BuildStep
    List<AdditionalBeanBuildItem> registerBeans() {

        return List.of(
                AdditionalBeanBuildItem.unremovableOf(EndpointMetadataHolder.class),
                AdditionalBeanBuildItem.unremovableOf(ApiResourceHolder.class),
                AdditionalBeanBuildItem.unremovableOf(PersistenceEntitlementRepository.class),
                AdditionalBeanBuildItem.unremovableOf(OidcResourceAuthorizationService.class),
                AdditionalBeanBuildItem.unremovableOf(EndpointResolverService.class),
                AdditionalBeanBuildItem.unremovableOf(GroupIdResolver.class),
                AdditionalBeanBuildItem.unremovableOf(ResourceAuthorizationRepository.class),
                AdditionalBeanBuildItem.unremovableOf(EndpointResolverRepository.class),
                AdditionalBeanBuildItem.unremovableOf(RoleEndpointRepository.class),
                AdditionalBeanBuildItem.unremovableOf(RoleEndpointContext.class),
                AdditionalBeanBuildItem.unremovableOf(RoleEndpointService.class),
                AdditionalBeanBuildItem.unremovableOf(AuthGroupInitializer.class),
                AdditionalBeanBuildItem.unremovableOf(RoleEndpointHolder.class),
                AdditionalBeanBuildItem.unremovableOf(AgmGroupCache.class));

    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    @Produce(SyntheticBeansRuntimeInitBuildItem.class)
    void syntheticBean(EndpointRecorder recorder, BuildProducer<SyntheticBeanBuildItem> syntheticBeanBuildItemBuildProducer,
                       List<JdbcDataSourceBuildItem> jdbcDataSourceBuildItems) {

        var names = getDataSourceNames(jdbcDataSourceBuildItems);

        var initializer = SyntheticBeanBuildItem
                .configure(SchemaInitializer.class)
                .scope(ApplicationScoped.class)
                .setRuntimeInit()
                .unremovable()
                .createWith(recorder.createSchemaInitializer())
                .checkActive(recorder.databaseCheckIsActive(names));

        var oidcEntitlementService = SyntheticBeanBuildItem
                .configure(EntitlementService.class)
                .scope(ApplicationScoped.class)
                .setRuntimeInit()
                .unremovable()
                .addQualifier()
                .annotation(DotName.createSimple(OidcEntitlement.class))
                .done()
                .addInjectionPoint(ClassType.create(DotName.createSimple(TokenIntrospection.class.getName())))
                .createWith(recorder.createOidcEntitlementService());

        var utilityService = SyntheticBeanBuildItem
                .configure(Utility.class)
                .scope(ApplicationScoped.class)
                .setRuntimeInit()
                .unremovable()
                .addInjectionPoint(ClassType.create(DotName.createSimple(TokenIntrospection.class.getName())))
                .createWith(recorder.createUtilityService());

        if (jdbcDataSourceBuildItems.isEmpty()) {

            var persistenceEntitlementService = SyntheticBeanBuildItem
                    .configure(EntitlementService.class)
                    .scope(ApplicationScoped.class)
                    .setRuntimeInit()
                    .unremovable()
                    .addQualifier()
                    .annotation(DotName.createSimple(PersistenceEntitlement.class))
                    .done()
                    .addInjectionPoint(ClassType.create(DotName.createSimple(PersistenceEntitlementRepository.class.getName())))
                    .addInjectionPoint(ClassType.create(DotName.createSimple(UserContextInterface.class.getName())))
                    .createWith(recorder.createPersistenceEntitlementService());

            syntheticBeanBuildItemBuildProducer.produce(persistenceEntitlementService.done());
        }

        syntheticBeanBuildItemBuildProducer.produce(initializer.done());
        syntheticBeanBuildItemBuildProducer.produce(oidcEntitlementService.done());
        syntheticBeanBuildItemBuildProducer.produce(utilityService.done());
    }

    @BuildStep
    List<AdditionalBeanBuildItem> selectBeans(List<JdbcDataSourceBuildItem> jdbcDataSourceBuildItems) {

        Class<?> resourceAuthorizationImplementation;
        Class<?> persistenceEntitlementImplementation;
        Class<?> entitlementProviderImplementation;
        Class<?> endpointResolverImplementation;
        Class<?> roleEndpointImplementation;


        if (!jdbcDataSourceBuildItems.isEmpty()) {
            resourceAuthorizationImplementation = ResourceAuthorizationJdbcRepository.class;
            persistenceEntitlementImplementation = PersistenceEntitlementJDBCRepository.class;
            entitlementProviderImplementation = EntitlementProviderWithoutPersistence.class;
            endpointResolverImplementation = EndpointResolverJdbcRepository.class;
            roleEndpointImplementation = RoleEndpointJdbcRepository.class;

        } else {

            resourceAuthorizationImplementation = ResourceAuthorizationMongoRepository.class;
            persistenceEntitlementImplementation = PersistenceEntitlementMongoRepository.class;
            entitlementProviderImplementation = EntitlementProviderWithPersistence.class;
            endpointResolverImplementation = EndpointResolverMongoRepository.class;
            roleEndpointImplementation = RoleEndpointMongoRepository.class;

        }

        return List.of(AdditionalBeanBuildItem
                .builder()
                .addBeanClass(resourceAuthorizationImplementation)
                .setUnremovable()
                .build(), AdditionalBeanBuildItem
                .builder()
                .addBeanClass(endpointResolverImplementation)
                .setUnremovable()
                .build(), AdditionalBeanBuildItem
                .builder()
                .addBeanClass(persistenceEntitlementImplementation)
                .setUnremovable()
                .build(), AdditionalBeanBuildItem
                .builder()
                .addBeanClass(entitlementProviderImplementation)
                .setUnremovable()
                .build(), AdditionalBeanBuildItem
                .builder()
                .addBeanClass(roleEndpointImplementation)
                .setUnremovable()
                .build()
        );
    }

    @BuildStep(onlyIf = IsMongoPresent.class)
    void registerCodecProvider(BuildProducer<AdditionalIndexedClassesBuildItem> additionalIndexedClasses) {
        LOG.info("Registering mongo related classes...");
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(ActorCodec.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(EntitlementCodec.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(ActorEntitlementsCodec.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(SettingCodec.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(ResourceAuthorizationCodec.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(RoleEndpointCodec.class.getName()));
        additionalIndexedClasses.produce(new AdditionalIndexedClassesBuildItem(PersistenceEntitlementCodecProvider.class.getName()));
    }

    public static class IsMongoPresent implements BooleanSupplier {
        @Override
        public boolean getAsBoolean() {
            try {
                Class.forName("io.quarkus.mongodb.deployment.CodecProviderBuildItem");
                LOG.info("Mongo CodecProviderBuildItem found in class path...");
                return true;
            } catch (ClassNotFoundException e) {
                return false;
            }
        }
    }

    public static class IsMongoAbsent implements BooleanSupplier {
        @Override
        public boolean getAsBoolean() {
            return !new IsMongoPresent().getAsBoolean();
        }
    }


    @BuildStep
    AdditionalBeanBuildItem registerExternalSystemAuthService() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClass(OidcResourceAuthorizationService.class)
                .setUnremovable()
                .build();
    }

    @BuildStep(onlyIf = IsMongoPresent.class)
    AdditionalBeanBuildItem registerPersistenceAuthService() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClass(PersistenceResourceAuthorizationService.class)
                .setUnremovable()
                .build();
    }

    @BuildStep(onlyIf = IsMongoPresent.class)
    AdditionalBeanBuildItem registerAuthServiceWithPersistence() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClass(ResourceAuthorizationServiceWithPersistence.class)
                .setUnremovable()
                .setDefaultScope(DotNames.APPLICATION_SCOPED)
                .build();
    }

    @BuildStep(onlyIf = IsMongoAbsent.class)
    AdditionalBeanBuildItem registerAuthServiceWithoutPersistence() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClass(ResourceAuthorizationServiceWithoutPersistence.class)
                .setUnremovable()
                .setDefaultScope(DotNames.APPLICATION_SCOPED)
                .build();
    }


    @BuildStep
    @Consume(BeanContainerBuildItem.class)
    @Record(ExecutionTime.RUNTIME_INIT)
    public void startActions(EndpointRecorder recorder) {

        recorder.initSchema();
    }

    @BuildStep
    @Record(ExecutionTime.STATIC_INIT)
        // or RUNTIME_INIT
    SecuredEndpointMetadataBuildItem processAndRecord(EndpointRecorder recorder, CombinedIndexBuildItem indexBuildItem) {

        var builder = scan(indexBuildItem);

        // Pass build-time data to the recorder → produces a RuntimeValue
        var metadata = recorder.storeSecuredEndpointMetadata(builder.getEndpoints());

        // Wire it into the CDI bean
        return new SecuredEndpointMetadataBuildItem(metadata);
    }

    @BuildStep
    @Record(ExecutionTime.STATIC_INIT)
    ApiResourcesBuildItem collectApiResources(
            EndpointRecorder recorder,
            CombinedIndexBuildItem combinedIndex
    ) {

        var validResources = new ArrayList<ApiResourceMetadata>();

        var apiResourceDotName =
                DotName.createSimple(ApiResource.class.getName());

        combinedIndex.getIndex()
                .getAllKnownImplementations(apiResourceDotName)
                .forEach(classInfo -> {

                    if (!classInfo.isEnum()) {
                        throw new IllegalStateException(
                                "Class [" + classInfo.name()
                                        + "] implements ApiResource but is not an enum!"
                        );
                    }

                    try {

                        String fqcn = classInfo.name().toString();

                        Class<?> clazz = Thread.currentThread()
                                .getContextClassLoader()
                                .loadClass(fqcn);

                        ApiResource apiResource =
                                (ApiResource) clazz.getEnumConstants()[0];

                        validResources.add(
                                new ApiResourceMetadata(
                                        apiResource.resourceName(),
                                        fqcn
                                )
                        );


                    } catch (Exception e) {

                        throw new RuntimeException(
                                "Failed to load ApiResource: "
                                        + classInfo.name(),
                                e
                        );
                    }
                });

        var metadata = recorder.storeApiResources(validResources);

        return new ApiResourcesBuildItem(metadata);
    }

    @BuildStep
    @Record(ExecutionTime.STATIC_INIT)
    void configureBeans(EndpointRecorder recorder, SecuredEndpointMetadataBuildItem configItem, ApiResourcesBuildItem resources, BuildProducer<BeanContainerListenerBuildItem> listeners) {

        listeners.produce(new BeanContainerListenerBuildItem(recorder.configureBeanContainer(configItem.getEndpoints())));

        listeners.produce(new BeanContainerListenerBuildItem(recorder.configureApiResourceBeanContainer(resources.getApiResources())));
    }

    private boolean isCdiBean(ClassInfo classInfo) {

        // CDI Scope annotations
        var cdiScopes = List.of(
                DotName.createSimple("jakarta.enterprise.context.ApplicationScoped"),
                DotName.createSimple("jakarta.enterprise.context.RequestScoped"),
                DotName.createSimple("jakarta.enterprise.context.SessionScoped"),
                DotName.createSimple("jakarta.enterprise.context.Dependent"),
                DotName.createSimple("jakarta.inject.Singleton"),
                DotName.createSimple("io.quarkus.arc.DefaultBean")
        );

        return classInfo
                .declaredAnnotations()
                .stream()
                .map(AnnotationInstance::name)
                .anyMatch(cdiScopes::contains);
    }


    private MethodInfo findMethodInHierarchy(IndexView index, ClassInfo classInfo, String methodName) {

        var current = classInfo;

        while (current != null) {

            // Check declared methods of current class
            var method = current.methods()
                    .stream()
                    .filter(m -> m.name().equals(methodName))
                    .findFirst();

            if (method.isPresent()) {
                return method.get();
            }

            // Check all implemented interfaces (default and static methods)
            for (var interfaceName : current.interfaceNames()) {
                var interfaceInfo = index.getClassByName(interfaceName);
                if (interfaceInfo != null) {

                    var interfaceMethod = interfaceInfo.methods()
                            .stream()
                            .filter(m -> m.name().equals(methodName))
                            .filter(m -> !Modifier.isAbstract(m.flags()))  // default + static
                            .findFirst();

                    if (interfaceMethod.isPresent()) {
                        return interfaceMethod.get();
                    }

                    // Recursively check parent interfaces
                    var parentInterfaceMethod = findMethodInHierarchy(index, interfaceInfo, methodName);
                    if (parentInterfaceMethod != null) {
                        return parentInterfaceMethod;
                    }
                }
            }

            // Walk up to superclass
            var superName = current.superName();
            if (superName == null || superName.toString().equals("java.lang.Object")) {
                break;
            }

            current = index.getClassByName(superName);
        }

        return null;
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    public void createGroupManagementServices(EndpointRecorder recorder, BuildProducer<SyntheticBeanBuildItem> syntheticBeanBuildItemBuildProducer) {

        var tokenProvider = recorder.createAuthTokenClient();

        var filter = recorder.createBearerTokenRequestFilter(tokenProvider);

        syntheticBeanBuildItemBuildProducer.produce(SyntheticBeanBuildItem.configure(KeycloakClientCredentialsTokenProvider.class)
                .unremovable()
                .setRuntimeInit()
                .runtimeValue(tokenProvider)
                .done());

        syntheticBeanBuildItemBuildProducer.produce(
                SyntheticBeanBuildItem.configure(BearerTokenRequestFilter.class)
                        .unremovable()
                        .setRuntimeInit()
                        .runtimeValue(filter)
                        .done());

        var service = recorder.createAuthGroupManagement(filter);

        syntheticBeanBuildItemBuildProducer.produce(
                SyntheticBeanBuildItem.configure(AuthGroupManagement.class)
                        .scope(ApplicationScoped.class)
                        .unremovable()
                        .setRuntimeInit()
                        .runtimeValue(service)
                        .done());
    }

    @BuildStep
    QualifierRegistrarBuildItem registerQualifiers() {
        return new QualifierRegistrarBuildItem(() -> {
            Map<DotName, Set<String>> qualifiers = new HashMap<>();
            qualifiers.put(
                    DotName.createSimple(BeforeProcessing.class.getName()),
                    Set.of("endpoint")
            );
            qualifiers.put(
                    DotName.createSimple(AfterProcessing.class.getName()),
                    Set.of("endpoint")
            );
            return qualifiers;
        });
    }

    private Set<String> getDataSourceNames(List<JdbcDataSourceBuildItem> jdbcDataSourceBuildItems) {
        Set<String> result = new HashSet<>(jdbcDataSourceBuildItems.size());
        for (JdbcDataSourceBuildItem item : jdbcDataSourceBuildItems) {
            result.add(item.getName());
        }
        return result;
    }

    private Set<Scope> extractScopes(AnnotationInstance annotation) {

        Set<Scope> scopes = new HashSet<>();

        AnnotationValue scopeValue = annotation.value("scope");

        if (scopeValue == null || scopeValue.asEnumArray() == null) {
            return scopes;
        }

        for (var enumVal : scopeValue.asEnumArray()) {
            scopes.add(Scope.valueOf(enumVal));
        }

        return scopes;
    }
}