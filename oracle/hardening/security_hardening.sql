-- =============================================
-- Database:    Oracle 19c/21c
-- Author:      Suleman
-- Description: Oracle Database Hardening Script
--              Security best practices
-- =============================================

-- -----------------------------------------------
-- 1. Remove PUBLIC Privileges
--    PUBLIC means ALL users have access
-- -----------------------------------------------

-- Revoke execute on dangerous packages from PUBLIC
REVOKE EXECUTE ON UTL_FILE       FROM PUBLIC;
REVOKE EXECUTE ON UTL_TCP        FROM PUBLIC;
REVOKE EXECUTE ON UTL_HTTP       FROM PUBLIC;
REVOKE EXECUTE ON UTL_SMTP       FROM PUBLIC;
REVOKE EXECUTE ON DBMS_ADVISOR   FROM PUBLIC;
REVOKE EXECUTE ON DBMS_BACKUP_RESTORE FROM PUBLIC;

-- Check what PUBLIC has
SELECT
    GRANTEE,
    OWNER,
    TABLE_NAME,
    PRIVILEGE
FROM DBA_TAB_PRIVS
WHERE GRANTEE = 'PUBLIC'
  AND PRIVILEGE = 'EXECUTE'
  AND TABLE_NAME IN (
    'UTL_FILE','UTL_TCP','UTL_HTTP',
    'UTL_SMTP','DBMS_BACKUP_RESTORE'
  )
ORDER BY TABLE_NAME;

-- -----------------------------------------------
-- 2. Secure Listener Configuration
-- -----------------------------------------------
-- Add to listener.ora:
/*
SECURE_CONTROL_COMPANYDB_LISTENER = TCPS
SECURE_PROTOCOL_LISTENER          = TCPS
ADMIN_RESTRICTIONS_LISTENER       = ON
*/

-- -----------------------------------------------
-- 3. Set Secure Database Parameters
-- -----------------------------------------------

-- Require OS authentication only for local
ALTER SYSTEM SET REMOTE_OS_AUTHENT = FALSE SCOPE=SPFILE;

-- Disable remote OS roles
ALTER SYSTEM SET REMOTE_OS_ROLES = FALSE SCOPE=SPFILE;

-- Set maximum failed logins
ALTER SYSTEM SET SEC_MAX_FAILED_LOGIN_ATTEMPTS = 3 SCOPE=BOTH;

-- Case sensitive passwords (Oracle 12c+)
ALTER SYSTEM SET SEC_CASE_SENSITIVE_LOGON = TRUE SCOPE=BOTH;

-- -----------------------------------------------
-- 4. Security Health Check Report
-- -----------------------------------------------
SELECT '=== ORACLE SECURITY HEALTH CHECK ===' AS REPORT FROM DUAL;

-- Check for users with default passwords
SELECT
    'DEFAULT PASSWORD' AS RISK,
    USERNAME,
    ACCOUNT_STATUS
FROM DBA_USERS_WITH_DEFPWD
WHERE ACCOUNT_STATUS = 'OPEN';

-- Check for DBA role grants
SELECT
    'DBA ROLE GRANTED' AS RISK,
    GRANTEE AS USERNAME,
    GRANTED_ROLE
FROM DBA_ROLE_PRIVS
WHERE GRANTED_ROLE = 'DBA'
  AND GRANTEE NOT IN ('SYS','SYSTEM');

-- Check password policies
SELECT
    'NO EXPIRY'    AS RISK,
    u.USERNAME,
    p.LIMIT        AS PASSWORD_LIFE_TIME
FROM DBA_USERS u
JOIN DBA_PROFILES p
    ON u.PROFILE = p.PROFILE
WHERE p.RESOURCE_NAME = 'PASSWORD_LIFE_TIME'
  AND p.LIMIT = 'UNLIMITED'
  AND u.ACCOUNT_STATUS = 'OPEN'
  AND u.USERNAME NOT IN ('SYS','SYSTEM');

-- Check open accounts with no activity
SELECT
    'INACTIVE ACCOUNT' AS RISK,
    USERNAME,
    LAST_LOGIN,
    ACCOUNT_STATUS
FROM DBA_USERS
WHERE ACCOUNT_STATUS = 'OPEN'
  AND (LAST_LOGIN < SYSDATE - 90
       OR LAST_LOGIN IS NULL)
  AND USERNAME NOT IN ('SYS','SYSTEM','DBSNMP')
ORDER BY LAST_LOGIN NULLS FIRST;
