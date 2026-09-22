//go:build linux

package database

import (
	"encoding/hex"
	"strings"
)

type transferFenceScope struct {
	Database Database
	Accounts []transferFenceAccount
}

func buildTransferFenceStatement(statement mariaDBStatement, values ...any) (string, error) {
	if statement == sqlTransferFenceReplication {
		if len(values) != 0 {
			return "", ErrInvalidCommand
		}
		return "SHOW ALL SLAVES STATUS;\n", nil
	}
	if statement == sqlTransferFenceIdentity {
		if len(values) != 0 {
			return "", ErrInvalidCommand
		}
		return "SELECT SHA2(CONCAT(@@hostname,CHAR(0),@@socket,CHAR(0),@@datadir,CHAR(0),@@server_id),256);\n", nil
	}
	if statement == sqlTransferFenceAudit {
		scope, ok := oneValue[transferFenceScope](values)
		if !ok || scope.Database.Validate() != nil || len(scope.Accounts) == 0 || len(scope.Accounts) > 64 {
			return "", ErrInvalidResource
		}
		var users []string
		for _, account := range scope.Accounts {
			if account.Principal.Validate() != nil || account.Principal.HostScope != HostScopeLoopback {
				return "", ErrInvalidResource
			}
			users = append(users, "'"+account.Principal.Name.String()+"'")
		}
		names := "(" + strings.Join(users, ",") + ")"
		db := "'" + scope.Database.Name.String() + "'"
		pattern := hex.EncodeToString([]byte(strings.ReplaceAll(scope.Database.Name.String(), "_", "\\_")))
		// Host root and the native mysql service UID are outside application
		// isolation. Exempt only their exact local, socket-only native identities,
		// never a password-authenticated administrator with the same name.
		admins := `SELECT CONCAT(QUOTE(u.User),'@',QUOTE(u.Host)) FROM mysql.user u JOIN mysql.global_priv g USING(User,Host) WHERE u.User IN ('root','mysql') AND u.Host='localhost' AND (u.plugin='unix_socket' AND u.authentication_string IN ('',u.User) OR u.plugin='mysql_native_password' AND u.authentication_string='invalid' AND JSON_LENGTH(JSON_EXTRACT(g.Priv,'$.auth_or'))=2 AND JSON_LENGTH(JSON_EXTRACT(g.Priv,'$.auth_or[0]'))=0 AND JSON_VALUE(g.Priv,'$.auth_or[1].plugin')='unix_socket' AND COALESCE(JSON_VALUE(g.Priv,'$.auth_or[1].authentication_string'),'') IN ('',u.User))`
		return "SELECT IF(@@wsrep_on,1,0)+" +
			"(SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE PRIVILEGE_TYPE<>'USAGE' AND GRANTEE NOT IN (" + admins + "))+" +
			"(SELECT COUNT(*) FROM mysql.user WHERE User IN " + names + " AND (Host<>'localhost' OR is_role<>'N' OR plugin<>'mysql_native_password'))+" +
			"(SELECT COUNT(*) FROM mysql.db WHERE (User IN " + names + " AND (Host<>'localhost' OR HEX(Db)<>'" + strings.ToUpper(pattern) + "')) OR (" + db + " LIKE Db AND User NOT IN " + names + "))+" +
			"(SELECT COUNT(*) FROM mysql.tables_priv WHERE Db=" + db + " OR User IN " + names + ")+" +
			"(SELECT COUNT(*) FROM mysql.columns_priv WHERE Db=" + db + " OR User IN " + names + ")+" +
			"(SELECT COUNT(*) FROM mysql.procs_priv WHERE Db=" + db + " OR User IN " + names + ")+" +
			"(SELECT COUNT(*) FROM mysql.roles_mapping)+" +
			"(SELECT COUNT(*) FROM mysql.proxies_priv WHERE CONCAT(QUOTE(User),'@',QUOTE(Host)) NOT IN (" + admins + "))+" +
			// A definer routine/trigger or scheduled event in another schema can
			// write here without logging in as the fenced account. Dependency
			// analysis is deliberately unsupported: refuse these server features.
			"(SELECT COUNT(*) FROM information_schema.TRIGGERS)+" +
			"(SELECT COUNT(*) FROM information_schema.VIEWS WHERE SECURITY_TYPE='DEFINER' AND (TABLE_SCHEMA NOT IN ('sys','mysql') OR DEFINER<>'mariadb.sys@localhost'))+" +
			"(SELECT COUNT(*) FROM information_schema.ROUTINES WHERE SECURITY_TYPE='DEFINER' AND (ROUTINE_SCHEMA NOT IN ('sys','mysql') OR DEFINER<>'mariadb.sys@localhost'))+" +
			"(SELECT COUNT(*) FROM information_schema.EVENTS WHERE STATUS='ENABLED');\n", nil
	}
	p, ok := oneValue[DatabasePrincipal](values)
	if !ok || p.Validate() != nil || p.HostScope != HostScopeLoopback {
		return "", ErrInvalidResource
	}
	user := "'" + p.Name.String() + "'"
	switch statement {
	case sqlTransferFenceAccount:
		return "SELECT SHA2(CONCAT(u.User,CHAR(0),u.Host,CHAR(0),u.plugin,CHAR(0),u.authentication_string,CHAR(0),COALESCE(JSON_EXTRACT(g.Priv,'$.auth_or'),'')),256),COALESCE(JSON_VALUE(g.Priv,'$.account_locked'),0) FROM mysql.user u JOIN mysql.global_priv g USING(User,Host) WHERE u.User=" + user + " AND u.Host='localhost';\n", nil
	case sqlTransferFenceGrants:
		return "SELECT HEX(TABLE_SCHEMA),PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE=CONCAT(QUOTE(" + user + "),'@',QUOTE('localhost')) ORDER BY BINARY TABLE_SCHEMA,PRIVILEGE_TYPE,IS_GRANTABLE;\n", nil
	case sqlTransferFenceSessions:
		// An authentication already in flight when ACCOUNT LOCK commits must
		// become an identified session (or exit) before drainage can be claimed.
		return "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER IN (" + user + ",'unauthenticated user','') OR USER IS NULL;\n", nil
	case sqlTransferFenceLock:
		return "ALTER USER " + quotedAccount(p) + " ACCOUNT LOCK;\n", nil
	case sqlTransferFenceUnlock:
		return "ALTER USER " + quotedAccount(p) + " ACCOUNT UNLOCK;\n", nil
	}
	return "", ErrInvalidCommand
}
