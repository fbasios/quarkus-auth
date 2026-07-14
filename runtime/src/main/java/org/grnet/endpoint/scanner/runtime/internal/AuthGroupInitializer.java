package org.grnet.endpoint.scanner.runtime.internal;

import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.grnet.endpoint.scanner.runtime.clients.groupmanagement.AuthGroupManagement;
import org.grnet.endpoint.scanner.runtime.services.ResourceAuthorizationService;

@ApplicationScoped
public class AuthGroupInitializer {

    @Inject
    ResourceAuthorizationService resourceAuthorizationService;

    void onStart(@Observes StartupEvent event) {
        resourceAuthorizationService.init();
    }
}