package org.grnet.endpoint.scanner.runtime.validators;

import io.quarkus.arc.Arc;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import io.quarkus.runtime.annotations.RegisterForReflection;
import org.grnet.endpoint.scanner.runtime.services.OidcResourceAuthorizationService;
import org.grnet.endpoint.scanner.runtime.services.ResourceAuthorizationService;
import org.grnet.endpoint.scanner.runtime.validators.constraints.ValidRole;

@RegisterForReflection
public class RoleValidator implements ConstraintValidator<ValidRole, String> {

    private ResourceAuthorizationService resourceAuthorizationService;

    @Override
    public void initialize(ValidRole constraintAnnotation) {
        this.resourceAuthorizationService =
                Arc.container().instance(ResourceAuthorizationService.class).get();
    }
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {

        if (value == null) {
            return true;
        }

        return resourceAuthorizationService.getAllRoles()
                .stream()
                .anyMatch(r -> value.equals(r.id));
    }
}