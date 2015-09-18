package org.keedio.jaas.impl;


import java.io.IOException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;

import org.eclipse.jetty.jaas.callback.ObjectCallback;
import org.eclipse.jetty.jaas.spi.AbstractLoginModule;
import org.eclipse.jetty.jaas.spi.UserInfo;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;
import org.eclipse.jetty.util.security.Credential;

/**
 * This is an alternative implementation of LDAP login module,
 * which is like tomcat JAASRealm.
 * 
 * @author malong
 *
 */
public class SimpleLdapLoginModule extends AbstractLoginModule
{
        private static final Logger LOG = Log.getLogger(SimpleLdapLoginModule.class);
        
        private String _ldapURL;
        private String _authenticationMethod = "simple";
        private String _contextFactory = "com.sun.jndi.ldap.LdapCtxFactory";

        private String _bindDn;
        private String _bindPassword;
        
        private String _userObjectClass = "inetOrgPerson";
        private String _userId = "uid";
        private String _userPassword = "userPassword";
        private String _userBaseDn;
        private String _userRoleName;
        
        private String _roleBaseDn;
        private String _roleUserId = "uid";
        private String _roleObjectClass = "groupOfUniqueNames";
        private String _roleMember = "uniqueMember";
        private String _roleName = "roleName";
        
        private DirContext _rootContext;
        
        @Override
        public void initialize(Subject subject, 
                        CallbackHandler callbackHandler, 
                        Map<String,?> sharedState, 
                        Map<String,?> options)
        {
                super.initialize(subject, callbackHandler, sharedState, options);
                
                _ldapURL = getOption(options, "ldapURL", null);
                _authenticationMethod = getOption(options, "authenticationMethod", "simple");
                _contextFactory = getOption(options, "contextFactory", "com.sun.jndi.ldap.LdapCtxFactory");
                
                _bindDn = getOption(options, "bindDn", null);
                _bindPassword = getOption(options, "bindPassword", null);
                
                _userObjectClass = getOption(options, "userObjectClass", "inetOrgPerson");
                _userId = getOption(options, "userId", "uid");
                _userPassword = getOption(options, "userPassword", "userPassword");
                _userBaseDn = getOption(options, "userBaseDn", null);
                _userRoleName = getOption(options, "userRoleName", null);
                
                
                _roleBaseDn = getOption(options, "roleBaseDn", null);
                _roleObjectClass = getOption(options, "roleObjectClass", "groupOfUniqueNames");
                _roleMember = getOption(options, "roleMember", "uniqueMember");
                _roleUserId = getOption(options, "roleUserId", "uid");
                _roleName = getOption(options, "roleName", null);
                
                try
        {
            _rootContext = new InitialDirContext(getEnvironment());
        }
        catch (NamingException ex)
        {
            throw new IllegalStateException("Unable to establish root context", ex);
        }
        }
        
        private String getOption(Map<String,?> options, String key, String defaultValue)
        {
                Object value = options.get(key);
                return value==null ? defaultValue : value.toString().trim();
    }
        
        public Hashtable<Object, Object> getEnvironment()
    {
        Properties env = new Properties();

        env.put(Context.INITIAL_CONTEXT_FACTORY, _contextFactory);
        
        if(_ldapURL != null)
        {
                env.put(Context.PROVIDER_URL, _ldapURL + (_ldapURL.endsWith("/") ? "" : "/"));
        }

        if (_authenticationMethod != null)
        {
            env.put(Context.SECURITY_AUTHENTICATION, _authenticationMethod);
        }

        if (_bindDn != null)
        {
            env.put(Context.SECURITY_PRINCIPAL, _bindDn);
        }

        if (_bindPassword != null)
        {
            env.put(Context.SECURITY_CREDENTIALS, _bindPassword);
        }

        return env;
    }
        
        private void close() throws LoginException
        {
                try 
        {
            _rootContext.close();
        } 
        catch (NamingException e) 
        {
            throw new LoginException( "error closing root context: " + e.getMessage() );
        }
        }
        
        @Override
        public boolean commit() throws LoginException 
        {
                close();
                return super.commit();
        }
        
        @Override
        public boolean abort() throws LoginException 
        {
                close();
                return super.abort();
        }
        
        @Override
        public boolean logout() throws LoginException 
        {
                close();
                return super.logout();
        }
        
        @Override
        public boolean login() throws LoginException
        {
                if (getCallbackHandler() == null)
        {
            throw new LoginException("No callback handler");
        }
                
                try
                {
                        Callback[] callbacks = configureCallbacks();
                        getCallbackHandler().handle(callbacks);
                        
                        String webUsername = ((NameCallback) callbacks[0]).getName();
            String webPassword = (String)((ObjectCallback) callbacks[1]).getObject();
            
            if (webUsername == null || webPassword == null)
            {
                setAuthenticated(false);
                return isAuthenticated();
            }
            
            String userDn = String.format("%s=%s%s %s", _userId, webUsername,
                        (_userBaseDn.startsWith(",")? "" : ","), _userBaseDn);
            
            LOG.info("Attempting authentication: " + userDn);
            if(!checkLogin(userDn, webPassword))
            {
                setAuthenticated(false);
                return isAuthenticated();
            }
            
            UserInfo userInfo = getUserInfo(webUsername);

            if (userInfo == null)
            {
                setAuthenticated(false);
                return false;
            }

            setCurrentUser(new JAASUserInfo(userInfo));
            setAuthenticated(true);
            return isAuthenticated();
                }
                catch(NamingException e)
                {
                        LOG.info(e);
                        throw new LoginException("LDAP Error performing login.");
                }
                catch(IOException e)
                {
                        LOG.info(e);
                        throw new LoginException("IO Error performing login.");
                }
                catch(UnsupportedCallbackException e)
                {
                        LOG.info(e);
                        throw new LoginException("Error obtaining callback information.");
                }
        }
        
        private boolean checkLogin(String userDn, String passwd)
        {
                Hashtable<Object,Object> env = getEnvironment();
                env.put(Context.SECURITY_PRINCIPAL, userDn);
                env.put(Context.SECURITY_CREDENTIALS, passwd);
                
                boolean b;
                try 
                {
                        DirContext dirContext = new InitialDirContext(env);
                        b = (dirContext!=null);
                } 
                catch (NamingException e) 
                {
                        LOG.debug(e);
                        b = false;
                }
                
                return b;
        }
        
        @Override
        public UserInfo getUserInfo(String username) throws LoginException, NamingException
        {
                SearchResult user = findUser(username);
                Attributes userAttrs = user.getAttributes();
                
                Credential credential = Credential.getCredential(getUserAttributesCredentials(userAttrs));
                List<String> roles = null;
                if(_userRoleName!=null)
                {
                        roles = getUserAttributesRoles(userAttrs);
                }
                else
                {
                        roles = findRoles(username);
                }
                
                return new UserInfo(username, credential, roles);
        }

        private String getUserAttributesCredentials(Attributes userAttrs)
        {
                String ldapCredential = null;
                //Attributes attributes = user.getAttributes();
                Attribute attribute = userAttrs.get(_userPassword);
                if (attribute != null)
        {
            try
            {
                byte[] value = (byte[]) attribute.get();
                ldapCredential = new String(value);
            }
            catch (NamingException e)
            {
                LOG.debug("no password available under attribute: " + _userPassword);
            }
        }
                
                LOG.debug("user credential is: " + ldapCredential);
        return ldapCredential;
        }
        
        private List<String> getUserAttributesRoles(Attributes userAttrs)
        {
                List<String> roleList = new ArrayList<String>();
                Attribute attribute = userAttrs.get(_userRoleName);
        if (attribute != null)
        {
            try
            {
                for (NamingEnumeration<?> ne = attribute.getAll(); ne.hasMoreElements();)
                {
                    Object v = ne.next();
                    roleList.add(v.toString());
                }
            }
            catch (NamingException e)
            {
                LOG.debug("no roles available under user attribute: " + _userRoleName);
            }
        }
        
        LOG.info("user roles is: " + roleList);
        return roleList;
        }
        
        private SearchResult findUser(String username) throws LoginException, NamingException
        {
                SearchControls ctls = new SearchControls();
                ctls.setCountLimit(1);
                ctls.setDerefLinkFlag(true);
                ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);

                String filter = "(&(objectClass={0})({1}={2}))";
                LOG.info("Searching for users with filter: \'" + filter + "\'" + " from base dn: " + _userBaseDn);

                Object[] filterArguments = new Object[]{_userObjectClass, _userId, username};
                NamingEnumeration<SearchResult> results = _rootContext.search(_userBaseDn, 
                                filter, filterArguments, ctls);
                
                LOG.info("Found user?: " + results.hasMoreElements());
                if (!results.hasMoreElements())
        {
            throw new LoginException("User not found.");
        }

        return (SearchResult) results.nextElement();
        }
        
    private List<String> findRoles(String username) throws LoginException, NamingException
    {
        List<String> roleList = new ArrayList<String>();

        if (_roleBaseDn == null || _roleMember == null || _roleObjectClass == null)
        {
            return roleList;
        }

        SearchControls ctls = new SearchControls();
        ctls.setDerefLinkFlag(true);
        ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        String filter = "(&(objectClass={0})({1}={2}))";
        
        String userDn = String.format("%s=%s%s %s", _userId, username,
            (_userBaseDn.startsWith(",")? "" : ","), _userBaseDn);
        
        Object[] filterArguments = {_roleObjectClass, _roleMember, userDn};
        NamingEnumeration<SearchResult> results = _rootContext.search(_roleBaseDn, filter, filterArguments, ctls);

        LOG.debug("Found user roles?: " + results.hasMoreElements());

        while (results.hasMoreElements())
        {
            SearchResult result = (SearchResult) results.nextElement();

            Attributes attributes = result.getAttributes();

            if (attributes == null)
            {
                continue;
            }

            Attribute roleAttribute = attributes.get(_roleName);

            if (roleAttribute == null)
            {
                continue;
            }

            NamingEnumeration<?> roles = roleAttribute.getAll();
            while (roles.hasMore())
            {
                roleList.add(roles.next().toString());
            }
        }

        return roleList;
    }
}