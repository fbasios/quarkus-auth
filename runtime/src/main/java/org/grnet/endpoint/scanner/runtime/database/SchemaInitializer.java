package org.grnet.endpoint.scanner.runtime.database;

import io.agroal.api.AgroalDataSource;
import io.quarkus.arc.Arc;
import io.quarkus.datasource.common.runtime.DatabaseKind;
import org.apache.ibatis.jdbc.ScriptRunner;
import org.eclipse.microprofile.config.ConfigProvider;
import org.grnet.endpoint.scanner.runtime.EndpointMetadata;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import org.jboss.logging.Logger;

import static io.quarkus.arc.ComponentsProvider.LOG;


public class SchemaInitializer {

    private static final Logger LOG = Logger.getLogger(SchemaInitializer.class);

    public void createTables() {

        var ds = Arc.container().select(AgroalDataSource.class);

        if (!ds.isUnsatisfied() && ds.getHandle().getBean().isActive()){

            var dbKind = ConfigProvider.getConfig().getValue("quarkus.datasource.db-kind", String.class);

            if(DatabaseKind.isPostgreSQL(dbKind)){
                LOG.info("Secured Endpoints extension: Creating tables for PostgreSQL...");

                try (Connection conn = ds.get().getConnection(); var reader = new InputStreamReader(Objects.requireNonNull(getClass().getResourceAsStream("/db/postgresql/init.sql")))) {

                    var runner = new ScriptRunner(conn);
                    runner.setAutoCommit(false);
                    runner.setStopOnError(true);
                    runner.setSendFullScript(true);
                    runner.setLogWriter(null);
                    runner.setErrorLogWriter(null);
                    runner.runScript(reader);
                    conn.commit();

                } catch (Exception e) {
                    throw new RuntimeException("Failed to run extension SQL script for Postgresql", e);
                }
            } else if (DatabaseKind.isMySQL(dbKind)) {
                LOG.info("Secured Endpoints extension: Creating tables for MySql...");

                try (Connection conn = ds.get().getConnection(); var reader = new InputStreamReader(Objects.requireNonNull(getClass().getResourceAsStream("/db/mysql/init.sql")))) {

                    var runner = new ScriptRunner(conn);
                    runner.setAutoCommit(false);
                    runner.setStopOnError(true);
                    runner.setSendFullScript(false);
                    runner.setLogWriter(null);
                    runner.setErrorLogWriter(null);
                    runner.runScript(reader);
                    conn.commit();

                } catch (Exception e) {
                    throw new RuntimeException("Failed to run extension SQL script for MySql", e);
                }

            }else {
                throw new RuntimeException("Unsupported database kind: " + dbKind);
            }
        } else {
            LOG.info("No JDBC data source found...");
            throw new RuntimeException("No JDBC data source found...");
        }

        LOG.info("Secured Endpoints extension: Database tables have been successfully created!");
    }

    private String generateSecuredEndpointId(EndpointMetadata endpoint) {
        String raw = endpoint.getAction() + endpoint.getPath();
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate securedEndpointId hash", e);
        }
    }
}
