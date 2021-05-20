Custom Realm in Elytron
=======================

Example of CustomRealm that uses EJB to authenticate and authorize.  Tested with Wildfly23.

Based on these two posts:
- https://hkalina.github.io/2018/06/06/custom-realm/  (custom security realm for WildFly Elytron)
- https://github.com/AntonYudin/wildfly-securityrealm-ejb   ( an implementation of wildfly/elytron security realm that uses an EJB bean as a way to authenticate and authorize a user)


To create custom Elytron component you need to create WildFly module containing JAR with class extending interface SecurityRealm available from Maven in package org.wildfly.security.wildfly-elytron. This JAR will have to be placed in modules directory of your application server together with module descriptor module.xml.


With PicketBox (previous Wildfly security system) I had a class that extended from *org.jboss.security.auth.spi.UsernamePasswordLoginModule*. In this class I do some validations and access database to do authorization and authentication.

The only way I found to implement these validations in Elytron is to create a custom SecurityRealm that can be configured with the address of an EJB that's deployed in our application (EAR).
	

The EJB has to be Stateless and must implement the method Map<String, Object> authenticate(String, String) which is called with a username and a password.

We to return a map that contains all roles the user belongs to or null if the credentials are invalid.

The project CustomSecurityRealm generates a JAR  (mvn clean install) that will be placed as a module:

- Copy folder 'modules' into <Wildfly> root. Inside 'modules/com/grifell/pep/security/realm/main' copy the generated JAR.

Inside the Jar there is a class called CustomSecurityRealm. In the *initialize(Map<String, String> configuration)* method, we receive ass parameter the ejbPathName that we will call to do the authentication and validation.

The EJB called is found in LoginEJB project. In my case, this JAR is placed inside an EAR deployed in Wildfly. The

Modifications in standalone-full.xml in order to use Elytron security system and custom security realm:

Create a custom realm (PepCustomRealm) that references a class (CustomSecurityRealm) in the module:

```xml
     <custom-realm name="PepCustomRealm" module="com.grifell.pep.security.realm" class-name="com.grifell.pep.security.realm.CustomSecurityRealm">
         <configuration>
            <property name="ejbPath" value="java:app/LoginEJB-1.0.0-SNAPSHOT/LoginManager"/>
         </configuration>
     </custom-realm>
```

We use a property with name= “ejbPath” and value = “java:app/LoginEJB-1.0.0-SNAPSHOT/LoginManager”. This info will be received in method initialize of class CustomSecurityRealm.

The LoginManagerBean contains the code that we had in JAAS class (PicketBox) and the method called:

```java
public Map<String, Object> authenticate(String name, String pwd)
```
returns a Map of <String,Object>. In this case, we return as String the text “roles” and as Object, a role list (list of privileges).

This Map is received in custom realm (CustomSecurityRealm class) in method:
```java
public boolean verifyEvidence(final Evidence evidence)
```

And principal and privileges are assigned to the realm:
```java
CustomSecurityRealm.this.cache.put(principal, attributes);
```

The key that we set in the Map is “roles”. It’s important to keep this name as we use it in the standalone-full.xml:
```xml
 <security-domain name="PepDomain" default-realm="PepCustomRealm" permission-mapper="default-permission-mapper">
     <realm name="PepCustomRealm" role-decoder="rolesAttributeToRoles"/>
 </security-domain>
```

The role decoder is called "rolesAttributeToRoles”. This is a name of role-decoder defined as:
```xml
<simple-role-decoder name="rolesAttributeToRoles" attribute="roles"/>
```
In the role-decoder, we indicate that the name of the key in the Map<String,Object> will be “roles”.

# Problems with Singleton EJB with @RunAs

I have a @Singleton EJB, that executes batch jobs and it is started when Wildfly starts (@Startup).
The EJB is executed under the role SYSTEM  (@RunAs("SYSTEM")).

When deploying the EAR in Wildfly, I got a NullPointerException.

I had to add this code in CustomSecurityRealm in order to work, but I think this is not the way to do it properly:

In method *getRealmIdentity(final Principal principal)*, we create a RealmIdentity, and in the method *getAttributes()* of this class I added this code:

```java
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
```

Previous code that gives nullPointerException when deploying:

```java
	    @Override
	    public Attributes getAttributes()
		    throws RealmUnavailableException {
		LOGGER.log(Level.FINE, () -> "getAttributes()");
		final String principal = getRealmIdentityPrincipal().getName();
		return CustomSecurityRealm.this.cache.get(principal);
	    }
```








