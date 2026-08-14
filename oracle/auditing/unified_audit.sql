-- =============================================
-- Database:    Oracle 19c/21c
-- Author:      Suleman
-- Description: Oracle Unified Auditing Setup
--              Oracle 12c+ recommended method
-- =============================================

-- -----------------------------------------------
-- Check if Unified Auditing is Enabled
-- -----------------------------------------------
SELECT
    VALUE
FROM V$OPTION
WHERE PARAMETER = 'Unified Auditing';

-- -----------------------------------------------
-- POLICY 1: Audit All Failed Login Attempts
-- -----------------------------------------------
CREATE AUDIT POLICY audit_failed_logins
    ACTIONS
        LOGON
    WHEN 'SYS_CONTEXT(''USERENV'',''AUTHENTICATED_IDENTITY'')
          IS NOT NULL'
    EVALUATE PER SESSION;

-- Enable the policy for failures only
AUDIT POLICY audit_failed_logins
    WHENEVER NOT SUCCESSFUL;

-- -----------------------------------------------
-- POLICY 2: Audit Privileged User Activity
--           DBA actions must be tracked
-- -----------------------------------------------
CREATE AUDIT POLICY audit_dba_activity
    PRIVILEGES
        CREATE ANY TABLE,
        DROP ANY TABLE,
        ALTER ANY TABLE,
        CREATE ANY USER,
        DROP ANY USER,
        ALTER USER,
        GRANT ANY PRIVILEGE,
        GRANT ANY ROLE,
        CREATE ANY PROCEDURE,
        DROP ANY PROCEDURE,
        ALTER DATABASE,
        ALTER SYSTEM
    ACTIONS
        CREATE TABLE,
        DROP TABLE,
        ALTER TABLE,
        CREATE USER,
        DROP USER,
        GRANT,
        REVOKE,
        CREATE PROCEDURE,
        DROP PROCEDURE;

AUDIT POLICY audit_dba_activity;

-- -----------------------------------------------
-- POLICY 3: Audit Sensitive Table Access
--           Track who reads salary data
-- -----------------------------------------------
CREATE AUDIT POLICY audit_sensitive_data
    ACTIONS
        SELECT,
        INSERT,
        UPDATE,
        DELETE
    ON CompanyDB.Employees
    WHEN 'SYS_CONTEXT(''USERENV'',''SESSION_USER'')
          NOT IN (''SYS'',''SYSTEM'')'
    EVALUATE PER SESSION;

AUDIT POLICY audit_sensitive_data;

-- -----------------------------------------------
-- POLICY 4: Audit All DDL Changes
-- -----------------------------------------------
CREATE AUDIT POLICY audit_ddl_changes
    ACTIONS
        CREATE TABLE,
        ALTER TABLE,
        DROP TABLE,
        TRUNCATE TABLE,
        CREATE INDEX,
        DROP INDEX,
        CREATE VIEW,
        DROP VIEW,
        CREATE PROCEDURE,
        ALTER PROCEDURE,
        DROP PROCEDURE,
        CREATE TRIGGER,
        DROP TRIGGER,
        CREATE SEQUENCE,
        DROP SEQUENCE;

AUDIT POLICY audit_ddl_changes;

-- -----------------------------------------------
-- POLICY 5: Audit User Management
-- -----------------------------------------------
CREATE AUDIT POLICY audit_user_mgmt
    ACTIONS
        CREATE USER,
        ALTER USER,
        DROP USER,
        GRANT,
        REVOKE;

AUDIT POLICY audit_user_mgmt;

-- -----------------------------------------------
-- View Audit Policies
-- -----------------------------------------------
SELECT
    POLICY_NAME,
    ENABLED_OPTION,
    ENTITY_NAME,
    SUCCESS,
    FAILURE
FROM AUDIT_UNIFIED_ENABLED_POLICIES
ORDER BY POLICY_NAME;

-- -----------------------------------------------
-- Query Unified Audit Trail
-- -----------------------------------------------

-- Recent audit records
SELECT
    EVENT_TIMESTAMP,
    DBUSERNAME,
    OS_USERNAME,
    USERHOST,
    ACTION_NAME,
    OBJECT_SCHEMA,
    OBJECT_NAME,
    UNIFIED_AUDIT_POLICIES,
    RETURN_CODE,
    SQL_TEXT
FROM UNIFIED_AUDIT_TRAIL
WHERE EVENT_TIMESTAMP > SYSDATE - 1
ORDER BY EVENT_TIMESTAMP DESC
FETCH FIRST 50 ROWS ONLY;

-- Failed login attempts today
SELECT
    EVENT_TIMESTAMP,
    DBUSERNAME,
    OS_USERNAME,
    USERHOST,
    ACTION_NAME,
    RETURN_CODE
FROM UNIFIED_AUDIT_TRAIL
WHERE ACTION_NAME   = 'LOGON'
  AND RETURN_CODE  != 0
  AND EVENT_TIMESTAMP > TRUNC(SYSDATE)
ORDER BY EVENT_TIMESTAMP DESC;

-- Users with most privilege escalation attempts
SELECT
    DBUSERNAME,
    COUNT(*)    AS VIOLATION_COUNT,
    MAX(EVENT_TIMESTAMP) AS LAST_ATTEMPT
FROM UNIFIED_AUDIT_TRAIL
WHERE RETURN_CODE != 0
  AND ACTION_NAME IN ('GRANT','ALTER USER','CREATE USER')
GROUP BY DBUSERNAME
ORDER BY VIOLATION_COUNT DESC;
