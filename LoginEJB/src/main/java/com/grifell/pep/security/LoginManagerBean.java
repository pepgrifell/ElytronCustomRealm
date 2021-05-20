package com.grifell.pep.security;

import javax.ejb.Remote;
import javax.ejb.Stateless;
import java.util.HashMap;
import java.util.Map;

@Stateless(name = "LoginManager")
@Remote(LoginManager.class)
public class LoginManagerBean implements LoginManager {

    public LoginManagerBean() {
    }

    public Map<String, Object> authenticate(String username, String pwd) {
	Map<String, Object> mapUserRoles = null;
	boolean authenticated = true;
	/**
	 * validate user and password: against database, ldap,...
	 */
	if (authenticated) {
	    mapUserRoles = null;
	    String[] roleArray = new String[0];
	    mapUserRoles = new HashMap<>();
	    roleArray = getRolesForUser(username);
	    /*
	      In standalone-full.xml we define a RoleDecoder and we indicate that the key of the map
	      that will contain the role list is 'roles'
	      <simple-role-decoder name="rolesAttributeToRoles" attribute="roles"/>
	     */
	    mapUserRoles.put("roles", roleArray);
	}
	return mapUserRoles;
    }

    private String[] getRolesForUser(String username) {
	String[] roles = { "ADD_USER", "DELETE_USER" };
	return roles; //load roles/privileges from database
    }
}