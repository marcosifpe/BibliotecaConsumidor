/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package softwarecorporativo.customrealm;

import com.sun.appserv.connectors.internal.api.ConnectorRuntime;
import com.sun.appserv.security.AppservPasswordLoginModule;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.security.auth.login.LoginException;
import com.sun.enterprise.security.common.Util;
import javax.naming.NamingException;
import javax.sql.DataSource;
import org.glassfish.hk2.api.ActiveDescriptor;
import org.glassfish.hk2.utilities.BuilderHelper;

/**
 *
 * @author MASC
 */
public class LoginModule extends AppservPasswordLoginModule {
    private DataSource dataSource;

    private Connection getConnection() throws NamingException, SQLException {
        if (this.dataSource == null) {
            Realm realm = (Realm) _currentRealm;
            ActiveDescriptor<ConnectorRuntime> cr = (ActiveDescriptor<ConnectorRuntime>) Util.getDefaultHabitat().getBestDescriptor(BuilderHelper.createContractFilter(ConnectorRuntime.class.getName()));
            ConnectorRuntime connectorRuntime = Util.getDefaultHabitat().getServiceHandle(cr).getService();
            dataSource = (DataSource) connectorRuntime.lookupNonTxResource(realm.getJtaDataSource(), false);
        }
        return dataSource.getConnection();
    }

    @Override
    protected void authenticateUser() throws LoginException {
        Connection conn = null;
        Realm realm = (Realm) _currentRealm;
        try {
            conn = getConnection();
            PreparedStatement stmt = conn.prepareStatement(realm.getPasswordQuery());
            stmt.setString(1, _username);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                String pass = rs.getString(1);

                if (pass == null || !_password.equals(pass)) {
                    throw new LoginException("Autorização inválida");
                }
            }

            rs.close();
            stmt.close();

            stmt = conn.prepareStatement(realm.getGroupsQuery());
            stmt.setString(1, _username);
            rs = stmt.executeQuery();

            if (rs.next()) {
                String group = rs.getString(1);
                commitUserAuthentication(new String[]{group});
            }

            rs.close();
            stmt.close();
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
