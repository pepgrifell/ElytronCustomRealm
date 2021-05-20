package com.grifell.pep.security.realm;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;

public class CustomSecurityRealm implements SecurityRealm {


    private final static java.util.logging.Logger LOGGER = java.util.logging.Logger.getLogger(CustomSecurityRealm.class.getName());

    private final String ejbPathName = "ejbPath";
    private String ejbPath = null;

    private final Map<String, Attributes> cache = new ConcurrentHashMap<>();

    public CustomSecurityRealm() {

    }

    // receiving configuration from subsystem
    public void initialize(Map<String, String> configuration) {
	LOGGER.log(Level.FINE, () -> "initialize(" + configuration + ")");
	this.ejbPath = configuration.get(this.ejbPathName);
	LOGGER.log(Level.FINE, () -> "ejbPath: [" + this.ejbPath + "]");
    }

    /**
     * Allows to detect, whether the security realm allows to acquire given type of credential.
     * Our testing security realm will not allow to obtain hash of the password, so we will return UNSUPPORTED for any type.
     *
     * @param credentialType
     * @param algorithmName
     * @param algorithmParameterSpec
     * @return
     * @throws RealmUnavailableException
     */
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName,
	    AlgorithmParameterSpec algorithmParameterSpec)
	    throws RealmUnavailableException {
	LOGGER.log(Level.FINE, () -> "getCredentialAcquireSupport(" + credentialType + ", " + algorithmName + ", " + algorithmParameterSpec + ")");
	return SupportLevel.UNSUPPORTED;  // this realm does not allow acquiring credentials
    }
    
    /*
      // this realm does not allow acquiring credentials
      public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName,
            AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        return SupportLevel.UNSUPPORTED;
      }
     */

    // this realm will be able to verify password evidences only
    /*
     Our security realm will support password verification - when clear password will be given, the realm will be able to say
     whether it is correct or not.
     But only for identities it knows - and we are asked for status for any identity - because of that,
     we will not return SUPPORTED, but POSSIBLY_SUPPORTED only
     */
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName)
	    throws RealmUnavailableException {
	LOGGER.log(Level.FINE, () -> "getEvidenceVerifySupport(" + evidenceType + ", " + algorithmName + ")");
	return PasswordGuessEvidence.class.isAssignableFrom(evidenceType) ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    protected Map<String, Object> authenticate(final String name, final String password) {

	LOGGER.log(Level.FINE, () -> "\tusing ejbPath: [" + this.ejbPath + "]");

	try {
	    final javax.naming.Context context = new javax.naming.InitialContext();

	    final Object bean = context.lookup(this.ejbPath);

	    LOGGER.log(Level.FINE, () -> "name: [" + name + "]");

	    final java.lang.reflect.Method method = bean.getClass()
		    .getMethod("authenticate", String.class, String.class);

	    LOGGER.log(Level.FINE, () -> "found method: [" + method + "]");

	    @SuppressWarnings("unchecked") final Map<String, Object> result = (Map<String, Object>) method.invoke(bean, name, password);

	    LOGGER.log(Level.FINE, () -> "result: [" + result + "]");

	    return result;

	} catch (java.lang.Exception exception) {
	    LOGGER.log(Level.SEVERE, "error authenticating", exception);
	    return null;
	}
    }

    @Override
    public RealmIdentity getRealmIdentity(final Evidence evidence)
	    throws RealmUnavailableException {
	LOGGER.log(Level.FINE, () -> "getRealmIdentity(" + evidence + ")");
	return SecurityRealm.super.getRealmIdentity(evidence);
    }

    @Override
    public RealmIdentity getRealmIdentity(final Principal principal)
	    throws RealmUnavailableException {

	LOGGER.log(Level.FINE, () -> "getRealmIdentity: [" + principal + ", " + principal.getName() + "]");

	return new RealmIdentity() {

	    @Override
	    public Principal getRealmIdentityPrincipal() {
		LOGGER.log(Level.FINE, () -> "getRealmIdentityPrincipal()");
		return principal;
	    }

	    @Override
	    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName,
		    final AlgorithmParameterSpec parameterSpec)
		    throws RealmUnavailableException {
		LOGGER.log(Level.FINE, () -> "getCredentialAcquireSupport(" + credentialType + ", " + algorithmName + ", " + parameterSpec + ")");
		return SupportLevel.UNSUPPORTED;
	    }

	    @Override
	    public <C extends Credential> C getCredential(final Class<C> credentialType)
		    throws RealmUnavailableException {
		LOGGER.log(Level.FINE, () -> "getCredential(" + credentialType + ")");
		return null;
	    }

	    @Override
	    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName)
		    throws RealmUnavailableException {

		LOGGER.log(Level.FINE, () -> "getEvidenceVerifySupport(" + evidenceType + ", " + algorithmName + ")");

		return (PasswordGuessEvidence.class.isAssignableFrom(evidenceType) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED);
	    }

	    @Override
	    public boolean verifyEvidence(final Evidence evidence)
		    throws RealmUnavailableException {

		LOGGER.log(Level.FINE, () -> "verifyEvidence(" + evidence + ")");

		if (evidence instanceof PasswordGuessEvidence) {

		    final PasswordGuessEvidence guess = (PasswordGuessEvidence) evidence;

		    LOGGER.log(Level.FINE, () -> "guess: [" + guess.getGuess() + "]");

		    try {
			final String principal = getRealmIdentityPrincipal().getName();

			final Map<String, Object> result = authenticate(principal, new String(guess.getGuess()));

			if (result != null) {

			    final MapAttributes attributes = new MapAttributes();

			    for (final Map.Entry<String, Object> entry : result.entrySet()) {

				if (entry.getValue() == null) {
				    continue;
				}

				if (entry.getValue() instanceof String[]) {
				    final String[] values = (String[]) entry.getValue();
				    for (int i = 0; i < values.length; i++) {
					final String value = values[i];
					attributes.add(entry.getKey(), i, value);
					LOGGER.log(Level.FINE, () -> "\tsetting [" + entry.getKey() + "]: [" + value + "]");
				    }
				} else {
				    attributes.add(entry.getKey(), 0, entry.getValue()
					    .toString());
				    LOGGER.log(Level.FINE, () -> "\tsetting [" + entry.getKey() + "] (0): [" + entry.getValue()
					    .toString() + "]");
				}
			    }
			    CustomSecurityRealm.this.cache.put(principal, attributes);
			    return true;
			}
		    } finally {
			guess.destroy();
		    }
		}

		return false;
	    }

	    @Override
	    public boolean exists()
		    throws RealmUnavailableException {
		LOGGER.log(Level.FINE, () -> "exists()");
		return true;
	    }

	    @Override
	    public AuthorizationIdentity getAuthorizationIdentity()
		    throws RealmUnavailableException {
		LOGGER.log(Level.FINE, () -> "getAuthorizationIdentity()");
		final Attributes attributes = getAttributes();
		return new AuthorizationIdentity() {
		    @Override
		    public Attributes getAttributes() {
			LOGGER.log(Level.FINE, () -> "getAttributes(): " + attributes);
			return attributes;
		    }
		};
	    }

	    @Override
	    public Attributes getAttributes()
		    throws RealmUnavailableException {
		LOGGER.log(Level.FINE, () -> "getAttributes()");
		final String principal = getRealmIdentityPrincipal().getName();
		LOGGER.log(Level.FINE, () -> "\tusing principal [" + principal + "]");
		Attributes attributes = CustomSecurityRealm.this.cache.get(principal);
		if (attributes==null && principal!=null && principal.equals("SYSTEM")) {
		    attributes = new MapAttributes();
		    attributes.add("SYSTEM", 0, "SYSTEM");
		    CustomSecurityRealm.this.cache.put(principal, attributes);
		}
		return CustomSecurityRealm.this.cache.get(principal);
	    }
	};
    }

}


