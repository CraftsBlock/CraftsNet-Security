package de.craftsblock.cnet.modules.security.auth.exclusion;

import de.craftsblock.craftsnet.api.utils.Scheme;

import java.util.regex.Pattern;

public sealed interface Exclusion permits HttpExclusion, WebSocketExclusion {

    Scheme scheme();

    Pattern path();

}
