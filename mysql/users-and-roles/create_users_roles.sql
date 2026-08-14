-- =============================================
-- Database:    MySQL 8.0
-- Author:      Suleman
-- Description: MySQL Users, Roles and Security
-- =============================================

USE mysql;

-- -----------------------------------------------
-- STEP 1: Configure Password Policy
-- -----------------------------------------------
-- Set global password policy
SET GLOBAL validate_password.policy         = STRONG;
SET GLOBAL validate_password.length         = 12;
SET GLOBAL validate_password.mixed_case_count = 1;
SET GLOBAL validate_password.number_count   = 1;
SET GLOBAL validate_password.special_char_count = 1;

-- -----------------------------------------------
-- STEP 2: Create Roles (MySQL 8.0+)
-- -----------------------------------------------

-- Read Only Role
CREATE ROLE IF NOT EXISTS 'app_read_only';
GRANT SELECT ON CompanyDB.* TO 'app_read_only';

-- Read Write Role
CREATE ROLE IF NOT EXISTS 'app_read_write';
GRANT SELECT, INSERT, UPDATE, DELETE
    ON CompanyDB.* TO 'app_read_write';

-- Developer Role
CREATE ROLE IF NOT EXISTS 'app_developer';
GRANT SELECT, INSERT, UPDATE, DELETE,
      CREATE, ALTER, DROP, INDEX,
      CREATE VIEW, SHOW VIEW,
      CREATE ROUTINE, ALTER ROUTINE,
      EXECUTE, TRIGGER
    ON CompanyDB.* TO 'app_developer';

-- Report Role
CREATE ROLE IF NOT EXISTS 'report_user';
GRANT SELECT ON CompanyDB.vw_SalesDashboard  TO 'report_user';
GRANT SELECT ON CompanyDB.vw_EmployeeDetails TO 'report_user';

-- -----------------------------------------------
-- STEP 3: Create Users
-- -----------------------------------------------

-- Application Service Account
CREATE USER IF NOT EXISTS
    'app_service'@'192.168.1.%'    -- Only from app server subnet
    IDENTIFIED BY 'AppService#2024!'
    PASSWORD EXPIRE INTERVAL 365 DAY
    FAILED_LOGIN_ATTEMPTS 5
    PASSWORD_LOCK_TIME 1;

GRANT 'app_read_write' TO 'app_service'@'192.168.1.%';
SET DEFAULT ROLE 'app_read_write'
    FOR 'app_service'@'192.168.1.%';

-- Report User
CREATE USER IF NOT EXISTS
    'report_svc'@'192.168.1.%'
    IDENTIFIED BY 'ReportSvc#2024!'
    PASSWORD EXPIRE INTERVAL 180 DAY
    FAILED_LOGIN_ATTEMPTS 5
    PASSWORD_LOCK_TIME 1;

GRANT 'report_user' TO 'report_svc'@'192.168.1.%';
SET DEFAULT ROLE 'report_user'
    FOR 'report_svc'@'192.168.1.%';

-- DBA User (only from DBA server)
CREATE USER IF NOT EXISTS
    'dba_john'@'192.168.1.50'
    IDENTIFIED BY 'DbaJohn#2024!'
    PASSWORD EXPIRE INTERVAL 90 DAY
    FAILED_LOGIN_ATTEMPTS 3
    PASSWORD_LOCK_TIME 2;

GRANT ALL PRIVILEGES ON CompanyDB.*
    TO 'dba_john'@'192.168.1.50'
    WITH GRANT OPTION;

-- -----------------------------------------------
-- STEP 4: Remove Anonymous and Root Remote Access
-- -----------------------------------------------

-- Remove anonymous users
DELETE FROM mysql.user
WHERE User = '';

-- Remove root remote access
DELETE FROM mysql.user
WHERE User = 'root'
  AND Host != 'localhost';

-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db = 'test';

FLUSH PRIVILEGES;

-- -----------------------------------------------
-- STEP 5: Verify Security Settings
-- -----------------------------------------------

-- Show all users
SELECT
    User,
    Host,
    account_locked,
    password_expired,
    password_lifetime
FROM mysql.user
ORDER BY User, Host;

-- Show role grants
SELECT
    FROM_USER,
    FROM_HOST,
    TO_USER,
    TO_HOST
FROM mysql.role_edges
ORDER BY FROM_USER;
