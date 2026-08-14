-- =============================================
-- Database:    Oracle 19c/21c
-- Author:      Suleman
-- Description: Permission Management Scripts
--              Grant, Revoke, Review
-- =============================================

-- -----------------------------------------------
-- 1. Check Current Privileges for a User
-- -----------------------------------------------
-- System Privileges
SELECT
    GRANTEE,
    PRIVILEGE,
    ADMIN_OPTION
FROM DBA_SYS_PRIVS
WHERE GRANTEE = 'APP_SERVICE'
ORDER BY PRIVILEGE;

-- Object Privileges
SELECT
    GRANTEE,
    OWNER,
    TABLE_NAME,
    PRIVILEGE,
    GRANTABLE
FROM DBA_TAB_PRIVS
WHERE GRANTEE = 'APP_SERVICE'
ORDER BY TABLE_NAME, PRIVILEGE;

-- Role Privileges
SELECT
    GRANTEE,
    GRANTED_ROLE,
    ADMIN_OPTION,
    DEFAULT_ROLE
FROM DBA_ROLE_PRIVS
WHERE GRANTEE = 'APP_SERVICE'
ORDER BY GRANTED_ROLE;

-- -----------------------------------------------
-- 2. Column Level Security
--    Restrict access to sensitive columns
-- -----------------------------------------------

-- Create a view that hides sensitive columns
-- instead of granting access to base table
CREATE OR REPLACE VIEW vw_Employees_Public AS
SELECT
    EmployeeID,
    FirstName,
    LastName,
    -- Email is masked for non-HR users
    CASE
        WHEN SYS_CONTEXT('USERENV','SESSION_USER')
             IN ('HR_MANAGER','DBA_JOHN')
        THEN Email
        ELSE REGEXP_REPLACE(Email,
             '(^[^@]+)(@.+$)',
             RPAD(SUBSTR('\1',1,2),
             LENGTH(REGEXP_SUBSTR(Email,'^[^@]+')),
             '*') || '\2')
    END                     AS Email,
    JobTitle,
    DepartmentID,
    -- Salary hidden from non-managers
    CASE
        WHEN SYS_CONTEXT('USERENV','SESSION_USER')
             IN ('DBA_JOHN','ANALYST_SARAH')
        THEN Salary
        ELSE NULL
    END                     AS Salary,
    HireDate,
    Status
FROM Employees;

-- Grant access to masked view only
GRANT SELECT ON vw_Employees_Public TO app_read_only;
REVOKE SELECT ON Employees FROM app_read_only;

-- -----------------------------------------------
-- 3. Row Level Security (VPD)
--    Users only see their department's data
-- -----------------------------------------------

-- Create security policy function
CREATE OR REPLACE FUNCTION fn_dept_security (
    p_schema IN VARCHAR2,
    p_object IN VARCHAR2
)
RETURN VARCHAR2
AS
    v_dept_id NUMBER;
    v_user    VARCHAR2(100);
BEGIN
    v_user := SYS_CONTEXT('USERENV','SESSION_USER');

    -- DBAs see everything
    IF v_user IN ('SYS','SYSTEM','DBA_JOHN') THEN
        RETURN NULL;  -- No restriction
    END IF;

    -- Get user's department
    BEGIN
        SELECT DepartmentID INTO v_dept_id
        FROM Employees
        WHERE UPPER(Email) = UPPER(v_user || '@company.com');
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RETURN '1=0';  -- No access if not found
    END;

    -- Return filter condition
    RETURN 'DepartmentID = ' || v_dept_id;
END fn_dept_security;
/

-- Apply VPD Policy to Employees table
BEGIN
    DBMS_RLS.ADD_POLICY (
        object_schema   => 'COMPANYDB',
        object_name     => 'EMPLOYEES',
        policy_name     => 'DEPT_SECURITY_POLICY',
        function_schema => 'COMPANYDB',
        policy_function => 'FN_DEPT_SECURITY',
        statement_types => 'SELECT, INSERT, UPDATE, DELETE',
        update_check    => TRUE,
        enable          => TRUE
    );
END;
/

-- -----------------------------------------------
-- 4. Review Users With Dangerous Privileges
-- -----------------------------------------------

-- Users with DBA role
SELECT
    GRANTEE,
    GRANTED_ROLE,
    ADMIN_OPTION,
    DEFAULT_ROLE
FROM DBA_ROLE_PRIVS
WHERE GRANTED_ROLE = 'DBA'
ORDER BY GRANTEE;

-- Users with ANY system privileges
SELECT
    GRANTEE,
    PRIVILEGE,
    ADMIN_OPTION
FROM DBA_SYS_PRIVS
WHERE PRIVILEGE LIKE '%ANY%'
  AND GRANTEE NOT IN ('SYS','SYSTEM','DBA','IMP_FULL_DATABASE')
ORDER BY GRANTEE, PRIVILEGE;

-- Users with SYSDBA/SYSOPER
SELECT
    USERNAME,
    SYSDBA,
    SYSOPER,
    SYSASM
FROM V$PWFILE_USERS
ORDER BY USERNAME;

-- -----------------------------------------------
-- 5. Revoke Excessive Privileges
-- -----------------------------------------------

-- Revoke dangerous ANY privileges from non-DBA users
REVOKE SELECT ANY TABLE  FROM dev_mike;
REVOKE CREATE ANY TABLE  FROM dev_mike;
REVOKE DROP   ANY TABLE  FROM dev_mike;
REVOKE EXECUTE ANY PROCEDURE FROM dev_mike;

-- -----------------------------------------------
-- 6. Privilege Analysis
--    Find which privileges are ACTUALLY used
--    (Oracle 12c+)
-- -----------------------------------------------

-- Create analysis
BEGIN
    DBMS_PRIVILEGE_CAPTURE.CREATE_CAPTURE(
        name        => 'ANALYZE_APP_SERVICE',
        description => 'Analyze privileges used by app_service',
        type        => DBMS_PRIVILEGE_CAPTURE.G_DATABASE,
        condition   => 'SYS_CONTEXT(''USERENV'',
                        ''SESSION_USER'') = ''APP_SERVICE'''
    );
END;
/

-- Enable analysis (run for several days)
BEGIN
    DBMS_PRIVILEGE_CAPTURE.ENABLE_CAPTURE(
        name => 'ANALYZE_APP_SERVICE'
    );
END;
/

-- After testing period, disable and report
BEGIN
    DBMS_PRIVILEGE_CAPTURE.DISABLE_CAPTURE(
        name => 'ANALYZE_APP_SERVICE'
    );
    DBMS_PRIVILEGE_CAPTURE.GENERATE_RESULT(
        name => 'ANALYZE_APP_SERVICE'
    );
END;
/

-- Check used privileges
SELECT
    USERNAME,
    SYS_PRIV,
    OBJECT_OWNER,
    OBJECT_NAME,
    OBJ_PRIV
FROM DBA_USED_PRIVS
WHERE CAPTURE   = 'ANALYZE_APP_SERVICE'
ORDER BY USERNAME;

-- Check UNUSED privileges (can be revoked!)
SELECT
    USERNAME,
    SYS_PRIV,
    OBJECT_OWNER,
    OBJECT_NAME,
    OBJ_PRIV
FROM DBA_UNUSED_PRIVS
WHERE CAPTURE = 'ANALYZE_APP_SERVICE'
ORDER BY USERNAME;
