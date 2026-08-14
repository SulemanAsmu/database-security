-- =============================================
-- Database:    Oracle 19c/21c
-- Author:      Suleman
-- Description: Create Database Roles
--              Following Least Privilege Principle
-- =============================================

-- -----------------------------------------------
-- DROP existing roles if recreating
-- -----------------------------------------------
BEGIN
    FOR r IN (
        SELECT ROLE FROM DBA_ROLES
        WHERE ROLE IN (
            'APP_READ_ONLY',
            'APP_READ_WRITE',
            'APP_DEVELOPER',
            'APP_MANAGER',
            'APP_DBA',
            'REPORT_USER'
        )
    )
    LOOP
        EXECUTE IMMEDIATE 'DROP ROLE ' || r.ROLE;
    END LOOP;
END;
/

-- -----------------------------------------------
-- ROLE 1: APP_READ_ONLY
--         For users who only need to read data
--         Example: Report users, analysts
-- -----------------------------------------------
CREATE ROLE app_read_only;

-- Grant SELECT on specific tables only
GRANT SELECT ON CompanyDB.Employees    TO app_read_only;
GRANT SELECT ON CompanyDB.Departments  TO app_read_only;
GRANT SELECT ON CompanyDB.Customers    TO app_read_only;
GRANT SELECT ON CompanyDB.Products     TO app_read_only;
GRANT SELECT ON CompanyDB.Orders       TO app_read_only;
GRANT SELECT ON CompanyDB.OrderDetails TO app_read_only;

-- Grant SELECT on views only (not base tables)
GRANT SELECT ON CompanyDB.vw_EmployeeDetails  TO app_read_only;
GRANT SELECT ON CompanyDB.vw_SalesDashboard   TO app_read_only;

COMMENT ON ROLE app_read_only IS
    'Read-only access to application tables and views';

-- -----------------------------------------------
-- ROLE 2: APP_READ_WRITE
--         For application users
--         Can read and modify data but not DDL
-- -----------------------------------------------
CREATE ROLE app_read_write;

-- Inherit read only
GRANT app_read_only TO app_read_write;

-- Add DML permissions
GRANT INSERT, UPDATE, DELETE ON CompanyDB.Employees    TO app_read_write;
GRANT INSERT, UPDATE, DELETE ON CompanyDB.Customers    TO app_read_write;
GRANT INSERT, UPDATE, DELETE ON CompanyDB.Orders       TO app_read_write;
GRANT INSERT, UPDATE, DELETE ON CompanyDB.OrderDetails TO app_read_write;
GRANT INSERT, UPDATE, DELETE ON CompanyDB.Products     TO app_read_write;

-- Allow use of sequences
GRANT SELECT ON CompanyDB.seq_employee_id TO app_read_write;
GRANT SELECT ON CompanyDB.seq_customer_id TO app_read_write;
GRANT SELECT ON CompanyDB.seq_order_id    TO app_read_write;

COMMENT ON ROLE app_read_write IS
    'Read and write access to application tables';

-- -----------------------------------------------
-- ROLE 3: APP_DEVELOPER
--         For developers in non-production
--         Can create and modify objects
-- -----------------------------------------------
CREATE ROLE app_developer;

-- Inherit read write
GRANT app_read_write TO app_developer;

-- DDL permissions
GRANT CREATE TABLE     TO app_developer;
GRANT CREATE VIEW      TO app_developer;
GRANT CREATE PROCEDURE TO app_developer;
GRANT CREATE SEQUENCE  TO app_developer;
GRANT CREATE TRIGGER   TO app_developer;
GRANT CREATE INDEX     TO app_developer;
GRANT CREATE TYPE      TO app_developer;

COMMENT ON ROLE app_developer IS
    'Developer access - DDL and DML in dev/test only';

-- -----------------------------------------------
-- ROLE 4: REPORT_USER
--         Very restricted - reporting only
--         Can only run specific reports
-- -----------------------------------------------
CREATE ROLE report_user;

-- Only access to reporting views
GRANT SELECT ON CompanyDB.vw_SalesDashboard  TO report_user;
GRANT SELECT ON CompanyDB.vw_EmployeeDetails TO report_user;

-- Execute stored procedures for reports
GRANT EXECUTE ON CompanyDB.sp_MonthlySalesReport TO report_user;

COMMENT ON ROLE report_user IS
    'Restricted access for report generation only';

-- -----------------------------------------------
-- ROLE 5: APP_DBA
--         Application DBA role
--         Full access to app schema
--         NOT a full DBA
-- -----------------------------------------------
CREATE ROLE app_dba;

GRANT app_developer TO app_dba;

-- Schema management
GRANT CREATE ANY TABLE      TO app_dba;
GRANT ALTER  ANY TABLE      TO app_dba;
GRANT DROP   ANY TABLE      TO app_dba;
GRANT CREATE ANY INDEX      TO app_dba;
GRANT ANALYZE ANY           TO app_dba;

COMMENT ON ROLE app_dba IS
    'Application DBA - schema management only';

-- -----------------------------------------------
-- Verify Roles Created
-- -----------------------------------------------
SELECT
    ROLE,
    PASSWORD_REQUIRED,
    AUTHENTICATION_TYPE
FROM DBA_ROLES
WHERE ROLE IN (
    'APP_READ_ONLY',
    'APP_READ_WRITE',
    'APP_DEVELOPER',
    'REPORT_USER',
    'APP_DBA'
)
ORDER BY ROLE;
