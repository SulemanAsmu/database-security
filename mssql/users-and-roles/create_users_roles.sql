-- =============================================
-- Database:    SQL Server 2019
-- Author:      Suleman
-- Description: SQL Server Security Setup
--              Users, Roles and Permissions
-- =============================================

USE CompanyDB;
GO

-- -----------------------------------------------
-- STEP 1: Create Database Roles
-- -----------------------------------------------

-- Read Only Role
CREATE ROLE app_read_only;
GO

-- Grant SELECT to role
GRANT SELECT ON SCHEMA::dbo TO app_read_only;
GO

-- Read Write Role
CREATE ROLE app_read_write;
GO

GRANT SELECT, INSERT, UPDATE, DELETE
    ON SCHEMA::dbo TO app_read_write;
GO

-- Developer Role
CREATE ROLE app_developer;
GO

GRANT SELECT, INSERT, UPDATE, DELETE,
      EXECUTE, ALTER ON SCHEMA::dbo
    TO app_developer;
GO

-- -----------------------------------------------
-- STEP 2: Create Logins and Users
-- -----------------------------------------------

-- Application Service Account
USE master;
GO

CREATE LOGIN app_service
    WITH PASSWORD = 'AppService#2024!',
    CHECK_POLICY = ON,
    CHECK_EXPIRATION = ON,
    DEFAULT_DATABASE = CompanyDB;
GO

USE CompanyDB;
GO

CREATE USER app_service
    FOR LOGIN app_service
    WITH DEFAULT_SCHEMA = dbo;
GO

ALTER ROLE app_read_write
    ADD MEMBER app_service;
GO

-- DBA User
USE master;
GO

CREATE LOGIN dba_john
    WITH PASSWORD = 'DbaJohn#2024!',
    CHECK_POLICY = ON,
    CHECK_EXPIRATION = ON;
GO

USE CompanyDB;
GO

CREATE USER dba_john FOR LOGIN dba_john;
GO

ALTER ROLE db_owner ADD MEMBER dba_john;
GO

-- -----------------------------------------------
-- STEP 3: Row Level Security
-- -----------------------------------------------
USE CompanyDB;
GO

-- Create security predicate function
CREATE OR ALTER FUNCTION dbo.fn_dept_security (
    @DepartmentID INT
)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN (
    SELECT 1 AS security_result
    WHERE
        -- User is in the department
        @DepartmentID = (
            SELECT DepartmentID
            FROM dbo.Employees
            WHERE Email = USER_NAME() + '@company.com'
        )
        OR
        -- User is DBA or manager
        IS_MEMBER('db_owner') = 1
        OR
        IS_MEMBER('app_developer') = 1
);
GO

-- Create security policy
CREATE SECURITY POLICY DeptSecurityPolicy
    ADD FILTER PREDICATE
        dbo.fn_dept_security(DepartmentID)
    ON dbo.Employees,
    ADD BLOCK PREDICATE
        dbo.fn_dept_security(DepartmentID)
    ON dbo.Employees AFTER INSERT
WITH (STATE = ON);
GO

-- -----------------------------------------------
-- STEP 4: Transparent Data Encryption (TDE)
-- -----------------------------------------------
USE master;
GO

-- Create Master Key
CREATE MASTER KEY
    ENCRYPTION BY PASSWORD = 'MasterKey#2024!';
GO

-- Create Certificate
CREATE CERTIFICATE TDE_Certificate
    WITH SUBJECT = 'CompanyDB TDE Certificate',
    EXPIRY_DATE = '2026-12-31';
GO

-- Create Database Encryption Key
USE CompanyDB;
GO

CREATE DATABASE ENCRYPTION KEY
    WITH ALGORITHM = AES_256
    ENCRYPTION BY SERVER CERTIFICATE TDE_Certificate;
GO

-- Enable TDE
ALTER DATABASE CompanyDB
    SET ENCRYPTION ON;
GO

-- Verify TDE Status
SELECT
    db_name(database_id)    AS DatabaseName,
    encryption_state,
    CASE encryption_state
        WHEN 0 THEN 'No Encryption'
        WHEN 1 THEN 'Unencrypted'
        WHEN 2 THEN 'Encryption in Progress'
        WHEN 3 THEN 'Encrypted'
        WHEN 4 THEN 'Key Change in Progress'
        WHEN 5 THEN 'Decryption in Progress'
    END                     AS EncryptionStatus,
    percent_complete,
    encryptor_type
FROM sys.dm_database_encryption_keys
WHERE db_name(database_id) = 'CompanyDB';
GO

-- -----------------------------------------------
-- STEP 5: SQL Server Audit
-- -----------------------------------------------
USE master;
GO

-- Create Server Audit
CREATE SERVER AUDIT CompanyDB_Audit
    TO FILE (
        FILEPATH = 'C:\AuditLogs\',
        MAXSIZE   = 100 MB,
        MAX_FILES = 10,
        RESERVE_DISK_SPACE = OFF
    )
    WITH (
        QUEUE_DELAY = 1000,
        ON_FAILURE  = CONTINUE
    );
GO

-- Enable Server Audit
ALTER SERVER AUDIT CompanyDB_Audit
    WITH (STATE = ON);
GO

-- Create Database Audit Specification
USE CompanyDB;
GO

CREATE DATABASE AUDIT SPECIFICATION
    CompanyDB_Audit_Spec
    FOR SERVER AUDIT CompanyDB_Audit
    ADD (SELECT, INSERT, UPDATE, DELETE
         ON dbo.Employees BY PUBLIC),
    ADD (SELECT, INSERT, UPDATE, DELETE
         ON dbo.Orders    BY PUBLIC),
    ADD (EXECUTE         ON SCHEMA::dbo BY PUBLIC),
    ADD (DATABASE_OBJECT_CHANGE_GROUP),
    ADD (DATABASE_PERMISSION_CHANGE_GROUP),
    ADD (DATABASE_PRINCIPAL_CHANGE_GROUP),
    ADD (FAILED_LOGIN_GROUP),
    ADD (LOGOUT_GROUP),
    ADD (USER_CHANGE_PASSWORD_GROUP)
    WITH (STATE = ON);
GO

-- -----------------------------------------------
-- Query Audit Logs
-- -----------------------------------------------
SELECT TOP 50
    event_time,
    action_id,
    succeeded,
    session_server_principal_name  AS username,
    database_name,
    object_name,
    statement,
    client_ip
FROM sys.fn_get_audit_file(
    'C:\AuditLogs\*.sqlaudit',
    DEFAULT, DEFAULT
)
ORDER BY event_time DESC;
GO

-- Failed Logins
SELECT
    event_time,
    session_server_principal_name  AS username,
    client_ip,
    statement
FROM sys.fn_get_audit_file(
    'C:\AuditLogs\*.sqlaudit',
    DEFAULT, DEFAULT
)
WHERE action_id = 'LGIF'    -- Login Failed
ORDER BY event_time DESC;
GO

-- -----------------------------------------------
-- STEP 6: Security Health Check
-- -----------------------------------------------
USE CompanyDB;
GO

-- Check users with sysadmin
SELECT
    'SYSADMIN ACCESS'           AS Risk,
    sp.name                     AS LoginName,
    sp.type_desc                AS LoginType
FROM sys.server_principals sp
INNER JOIN sys.server_role_members srm
    ON sp.principal_id = srm.member_principal_id
INNER JOIN sys.server_principals sr
    ON srm.role_principal_id = sr.principal_id
WHERE sr.name = 'sysadmin'
  AND sp.name NOT IN ('sa','NT AUTHORITY\SYSTEM')
ORDER BY sp.name;

-- Check for SA account enabled
SELECT
    'SA ACCOUNT STATUS'         AS Risk,
    name,
    is_disabled,
    LOGINPROPERTY(name,'IsLocked') AS IsLocked
FROM sys.sql_logins
WHERE name = 'sa';

-- Check orphaned users
SELECT
    'ORPHANED USER'             AS Risk,
    dp.name                     AS DatabaseUser,
    dp.type_desc
FROM sys.database_principals dp
LEFT JOIN sys.server_principals sp
    ON dp.sid = sp.sid
WHERE dp.type NOT IN ('A','G','R','X')
  AND dp.sid IS NOT NULL
  AND sp.sid IS NULL
  AND dp.name NOT IN ('dbo','guest','INFORMATION_SCHEMA','sys');
GO
