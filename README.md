# Jaas Login Module
## Descripción
Módulo para la autorización y autenticación de usuarios mediante el framwork JAAS contra un repositorio de datos LDAP.

## Instaltación
1. Compilar el proyecto:

```
mvn clean package
```

2. Copiar el fichero jar generado en el classpath del proyecto

3. Crear el fichero de configuración (FICH_CONF) con los parametros necesarios en el directorio de configuración (CONF_DIR)

```
ldaploginmodule {
   org.keedio.jaas.impl.SimpleLdapLoginModule required
   debug="true"
   contextFactory="com.sun.jndi.ldap.LdapCtxFactory"
   ldapURL="ldap://ambari6:389"
   bindDn="cn=Manager,dc=keedio,dc=com"
   bindPassword="hola"
   authenticationMethod="simple"
   forceBindingLogin="true"
   userBaseDn="ou=People,dc=keedio,dc=com"
   userRdnAttribute="uid"
   userIdAttribute="uid"
   userPasswordAttribute="userPassword"
   userObjectClass="inetOrgPerson"
   roleBaseDn="ou=Groups,dc=keedio,dc=com"
   roleNameAttribute="cn"
   roleMemberAttribute="member"
   roleObjectClass="groupOfNames"
   roleName="cn"
   roleMember="member";
   };	
```

4. Arrancar el sevicio java con el parametro

```
java ... -Djava.security.auth.login.config=CONF_DIR/FICH_CONF ...
```



