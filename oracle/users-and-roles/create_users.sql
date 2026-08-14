-- =============================================
-- Database:    Oracle 19c/21c
-- Author:      Suleman
-- Description: Create Database Users
--              with proper security settings
-- =============================================

-- -----------------------------------------------
-- USER 1: Application Service Account
--         Used by the application to connect
--         NEVER used by humans directly
-- -----------------------------------------------
CREATE USER app_service
    IDENTIFIED BY "AppService#2024!"
    DEFAULT TABLESPACE USERS
    TEMPORARY TABLESPACE TEMP
    PROFILE app_profile          -- Password policy
    ACCOUNT UNLOCK;

-- Grant application role
GRANT app_read_write TO app_service;

-- Grant CREATE SESSION only
GRANT CREATE SESSION TO app_service;

-- Restrict to connect only from app server
-- (using Oracle Connection Manager or VPD)

COMMENT ON COLUMN ALL_USERS.USERNAME IS
    'app_service: Application service account - no direct human login';

-- -----------------------------------------------
-- USER 2: Report User
--         For business intelligence and reports
-- -----------------------------------------------
CREATE USER report_svc
    IDENTIFIED BY "ReportSvc#2024!"
    DEFAULT TABLESPACE USERS
    TEMPORARY TABLESPACE TEMP
    PROFILE app_profile
    ACCOUNT UNLOCK;

GRANT CREATE SESSION TO report_svc;
GRANT report_user    TO report_svc;

-- -----------------------------------------------
-- USER 3: DBA User (Named Account)
--         Individual DBA - never use shared DBA
-- -----------------------------------------------
CREATE USER dba_john
    IDENTIFIED BY "DbaJohn#2024!"
    DEFAULT TABLESPACE USERS
    TEMPORARY TABLESPACE TEMP
    PROFILE dba_profile
    ACCOUNT UNLOCK;

GRANT CREATE SESSION TO dba_john;
GRANT app_dba        TO dba_john;

-- -----------------------------------------------
-- USER 4: Read Only User
--         For data analysts
-- -----------------------------------------------
CREATE USER analyst_sarah
    IDENTIFIED BY "Analyst#2024!"
    DEFAULT TABLESPACE USERS
    TEMPORARY TABLESPACE TEMP
    PROFILE app_profile
    ACCOUNT UNLOCK;

GRANT CREATE SESSION TO analyst_sarah;
GRANT app_read_only  TO analyst_sarah;

-- -----------------------------------------------
-- USER 5: Developer (Non-Production Only)
-- -----------------------------------------------
CREATE USER dev_mike
    IDENTIFIED BY "DevMike#2024!"
    DEFAULT TABLESPACE USERS
    TEMPORARY TABLESPACE TEMP
    PROFILE dev_profile
    ACCOUNT UNLOCK;

GRANT CREATE SESSION TO dev_mike;
GRANT app_developer  TO dev_mike;

-- -----------------------------------------------
-- Verify Users Created
-- -----------------------------------------------
SELECT
    USERNAME,
    ACCOUNT_STATUS,
    LOCK_DATE,
    EXPIRY_DATE,
    DEFAULT_TABLESPACE,
    PROFILE,
    CREATED
FROM DBA_USERS
WHERE USERNAME IN (
    'APP_SERVICE',
    'REPORT_SVC',
    'DBA_JOHN',
    'ANALYST_SARAH',
    'DEV_MIKE'
)
ORDER BY USERNAME;
