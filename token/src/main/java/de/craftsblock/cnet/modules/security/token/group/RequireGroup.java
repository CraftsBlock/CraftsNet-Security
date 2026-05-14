package de.craftsblock.cnet.modules.security.token.group;

import de.craftsblock.craftsnet.api.requirements.meta.RequirementMeta;
import de.craftsblock.craftsnet.api.requirements.meta.RequirementStore;
import de.craftsblock.craftsnet.api.requirements.meta.RequirementType;

import java.lang.annotation.*;

/**
 * Requirement annotation used to declare group-based access restrictions
 * for routes, controller methods, or WebSocket endpoints.
 * <p>
 * When applied, this annotation is processed by the CraftsNet requirement
 * system and results in a {@link GroupRequest} being injected into the
 * request context. The {@link GroupResolveMiddleware} then validates
 * whether the authenticated token contains all required groups.
 * <p>
 * If the requirement is not satisfied, the request or connection will be
 * rejected during the authentication/authorization pipeline.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@RequirementMeta(type = RequirementType.STORING)
public @interface RequireGroup {

    /**
     * Defines the group names required to access the annotated endpoint.
     *
     * @return an array of required group identifiers
     */
    @RequirementStore
    String[] value();

}
