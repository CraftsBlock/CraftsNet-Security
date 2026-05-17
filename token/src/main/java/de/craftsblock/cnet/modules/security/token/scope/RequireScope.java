package de.craftsblock.cnet.modules.security.token.scope;

import de.craftsblock.craftsnet.api.requirements.meta.RequirementMeta;
import de.craftsblock.craftsnet.api.requirements.meta.RequirementStore;
import de.craftsblock.craftsnet.api.requirements.meta.RequirementType;

import java.lang.annotation.*;

/**
 * Annotation used to declare required authentication scopes on routes
 * or endpoint handlers.
 * <p>
 * The declared scope values are injected into the request or WebSocket
 * context as a {@link ScopeRequest} and later validated by {@link ScopeResolveMiddleware}.
 * <p>
 * If a request does not provide a token containing all required scopes,
 * access to the endpoint will be denied during the authentication pipeline.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @since 1.0.0
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@RequirementMeta(type = RequirementType.STORING)
public @interface RequireScope {

    /**
     * Defines the list of required scopes that must be present
     * in the authenticated token in order to access the annotated route.
     *
     * @return an array of required scope identifiers
     */
    @RequirementStore
    String[] value();

}
