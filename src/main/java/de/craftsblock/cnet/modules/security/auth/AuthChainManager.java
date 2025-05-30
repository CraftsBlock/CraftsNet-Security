package de.craftsblock.cnet.modules.security.auth;

import de.craftsblock.cnet.modules.security.auth.chains.AuthChain;
import de.craftsblock.cnet.modules.security.utils.Manager;

import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * The {@code AuthChainManager} class is a manager for handling multiple {@link AuthChain} instances.
 * It extends {@link ConcurrentLinkedQueue} to provide a thread-safe way to manage and manipulate
 * authentication chains. Each {@link AuthChain} represents a chain of authentication adapters.
 *
 * @author Philipp Maywald
 * @author CraftsBlock
 * @version 1.0.0
 * @since 1.0.0-SNAPSHOT
 */
public final class AuthChainManager extends ConcurrentLinkedQueue<AuthChain> implements Manager {

}
