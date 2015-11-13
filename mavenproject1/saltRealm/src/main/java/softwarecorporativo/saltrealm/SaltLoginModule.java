/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package softwarecorporativo.saltrealm;

import com.sun.appserv.connectors.internal.api.ConnectorRuntime;
import com.sun.appserv.security.AppservPasswordLoginModule;
import com.sun.enterprise.security.common.Util;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.naming.NamingException;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;
import org.glassfish.hk2.api.ActiveDescriptor;
import org.glassfish.hk2.utilities.BuilderHelper;

/**
 *
 * @author MASC
 */
public class SaltLoginModule extends AppservPasswordLoginModule {
    private static DataSource dataSource;

    private synchronized Connection getConnection() throws NamingException, SQLException {
        if (dataSource == null) {
            SaltRealm realm = (SaltRealm) _currentRealm;
            ActiveDescriptor<ConnectorRuntime> cr = (ActiveDescriptor<ConnectorRuntime>) Util.getDefaultHabitat().getBestDescriptor(BuilderHelper.createContractFilter(ConnectorRuntime.class.getName()));
            ConnectorRuntime connectorRuntime = Util.getDefaultHabitat().getServiceHandle(cr).getService();
            dataSource = (DataSource) connectorRuntime.lookupNonTxResource(realm.getJtaDataSource(), false);
        }
        
        return dataSource.getConnection();
    }

    public String getHash(String salt) {
        try {
            SaltRealm realm = (SaltRealm) _currentRealm;
            String pwd = salt + _password;
            MessageDigest digest = MessageDigest.getInstance(realm.getHashAlgorithm());
            digest.update(pwd.getBytes(Charset.forName(realm.getCharset())));
            return Base64.getEncoder().encodeToString(digest.digest());
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }
    
    
    @Override
    protected void authenticateUser() throws LoginException {
        Connection conn = null;
        SaltRealm realm = (SaltRealm) _currentRealm;
        try {
            conn = getConnection();
            PreparedStatement stmt = conn.prepareStatement(realm.getPasswordQuery());
            stmt.setString(1, _username);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                String password = rs.getString(1);      
                String salt = rs.getString(2);

                if (password == null || !password.equals(getHash(salt))) {
                    throw new LoginException("Invalid login. Please try again");
                }
            }

            rs.close();
            stmt.close();

            stmt = conn.prepareStatement(realm.getGroupsQuery());
            stmt.setString(1, _username);
            rs = stmt.executeQuery();
            
            List<String> groups = new ArrayList<>();
            while (rs.next()) {
                String group = rs.getString(1);
                groups.add(group);
            }
            
            String[] groupsArray = new String[groups.size()];
            int i = 0;
            for (String group : groups) {
                groupsArray[i++] = group;
            }

            rs.close();
            stmt.close();
            commitUserAuthentication(groupsArray);            
        } catch (SQLException | NamingException ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        } finally {
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException ex) {
                throw new RuntimeException(ex.getMessage(), ex);
            }
        }
        
    }
    
}
