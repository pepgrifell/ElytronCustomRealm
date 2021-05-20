package com.grifell.pep.security;

import javax.ejb.Remote;
import java.util.Map;

@Remote
public interface LoginManager {

    Map<String, Object> authenticate(final String name, final String password);
}
