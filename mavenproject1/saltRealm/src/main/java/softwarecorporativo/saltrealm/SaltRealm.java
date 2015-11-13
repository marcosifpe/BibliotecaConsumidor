package softwarecorporativo.saltrealm;

import com.sun.appserv.security.AppservRealm;
import static com.sun.enterprise.security.BaseRealm.JAAS_CONTEXT_PARAM;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import java.util.Enumeration;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.Vector;

/**
 *
 * @author MASC
 */
public class SaltRealm extends AppservRealm {

    public static final String PASSWORD_SQL_QUERY = "password-sql-query";
    public static final String GROUPS_SQL_QUERY = "groups-sql-query";
    public static final String JTA_DATA_SOURCE = "jta-data-source";
    public static final String HASH_ALGORITHM = "hash-algorithm";
    public static final String CHARSET = "charset";
    public static final String GROUPS_SQL = "groups-sql";

    @Override
    public synchronized void init(Properties properties) throws BadRealmException, NoSuchRealmException {
        setProperty(JAAS_CONTEXT_PARAM, properties.getProperty(JAAS_CONTEXT_PARAM));
        setProperty(PASSWORD_SQL_QUERY, properties.getProperty(PASSWORD_SQL_QUERY));
        setProperty(GROUPS_SQL_QUERY, properties.getProperty(GROUPS_SQL_QUERY));
        setProperty(JTA_DATA_SOURCE, properties.getProperty(JTA_DATA_SOURCE));
        setProperty(HASH_ALGORITHM, properties.getProperty(HASH_ALGORITHM));
        setProperty(CHARSET, properties.getProperty(CHARSET));
        setProperty(GROUPS_SQL, properties.getProperty(GROUPS_SQL));
    }

    public String getGroupsSql() {
        return super.getProperty(GROUPS_SQL);
    }

    public String getCharset() {
        return super.getProperty(CHARSET);
    }

    public String getHashAlgorithm() {
        return super.getProperty(HASH_ALGORITHM);
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
        return "saltRealm";
    }

    @Override
    @SuppressWarnings("UseOfObsoleteCollectionType")
    public Enumeration getGroupNames(String username) throws InvalidOperationException, NoSuchUserException {
        Vector<String> vector = new Vector<String>();
        StringTokenizer tokenizer = new StringTokenizer(getGroupsSql());

        while (tokenizer.hasMoreTokens()) {
            String str = (String) tokenizer.nextElement();
            vector.add(str);
        }
        
        return vector.elements();
    }
}
