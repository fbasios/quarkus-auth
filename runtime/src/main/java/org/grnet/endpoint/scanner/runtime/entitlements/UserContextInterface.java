package org.grnet.endpoint.scanner.runtime.entitlements;

import java.util.Optional;

public interface UserContextInterface {

    String getId();

    String getIssuer();

    String getNamespace();

    String entitlementManagement();

    String getParent();

    Optional<String> getName();

    Optional<String> getEmail();
}
