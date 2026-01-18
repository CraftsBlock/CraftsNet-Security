package de.craftsblock.cnet.modules.security.token.scope;

import de.craftsblock.craftsnet.api.requirements.meta.RequirementMeta;
import de.craftsblock.craftsnet.api.requirements.meta.RequirementStore;
import de.craftsblock.craftsnet.api.requirements.meta.RequirementType;

import java.lang.annotation.*;

@Documented
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@RequirementMeta(type = RequirementType.STORING)
public @interface RequireScope {

    @RequirementStore
    String[] value();

}
