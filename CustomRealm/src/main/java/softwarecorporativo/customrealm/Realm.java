/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package softwarecorporativo.customrealm;

import com.sun.appserv.security.AppservRealm;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import java.util.Enumeration;
import java.util.Properties;

/**
 *
 * @author MASC
 */
public class Realm extends AppservRealm {
    public static final String PASSWORD_SQL_QUERY = "password-sql-query";
    public static final String GROUPS_SQL_QUERY = "groups-sql-query";
    public static final String JTA_DATA_SOURCE = "jta-data-source";

    @Override
    public synchronized void init(Properties properties) throws BadRealmException, NoSuchRealmException {
        setProperty(JAAS_CONTEXT_PARAM, properties.getProperty(JAAS_CONTEXT_PARAM));
        setProperty(PASSWORD_SQL_QUERY, properties.getProperty(PASSWORD_SQL_QUERY));
        setProperty(GROUPS_SQL_QUERY, properties.getProperty(GROUPS_SQL_QUERY));
        setProperty(JTA_DATA_SOURCE, properties.getProperty(JTA_DATA_SOURCE));
    }

    public String getJtaDataSource() {
        return super.getProperty(JTA_DATA_SOURCE);
    }
    
    public String getPasswordQuery() {
        return super.getProperty(PASSWORD_SQL_QUERY);
    }
    
    public String getGroupsQuery() {
        return super.getProperty(GROUPS_SQL_QUERY);
    }
    
    @Override
    public String getAuthType() {
        return "jdbc";
    }

    @Override
    public String getJAASContext() {
        return "customRealm";
    }

    @Override
    public Enumeration getGroupNames(String string) 
            throws InvalidOperationException, NoSuchUserException {
        return null;
    }
}
