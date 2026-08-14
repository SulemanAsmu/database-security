-- =============================================
-- Database:    MySQL 8.0
-- Author:      Suleman
-- Description: MySQL Auditing Configuration
--              Using MySQL Enterprise Audit
--              or General Query Log
-- =============================================

-- -----------------------------------------------
-- METHOD 1: General Query Log (Basic Auditing)
-- -----------------------------------------------

-- Enable general query log
SET GLOBAL general_log          = 'ON';
SET GLOBAL general_log_file     = '/var/log/mysql/general.log';

-- Enable slow query log for performance auditing
SET GLOBAL slow_query_log       = 'ON';
SET GLOBAL slow_query_log_file  = '/var/log/mysql/slow.log';
SET GLOBAL long_query_time      = 2;

-- -----------------------------------------------
-- METHOD 2: Using Performance Schema for Auditing
-- -----------------------------------------------

-- Enable statement auditing
UPDATE performance_schema.setup_consumers
SET ENABLED = 'YES'
WHERE NAME IN (
    'events_statements_history',
    'events_statements_history_long'
);

UPDATE performance_schema.setup_instruments
SET ENABLED = 'YES', TIMED = 'YES'
WHERE NAME LIKE 'statement/%';

-- View recent statements
SELECT
    EVENT_ID,
    EVENT_NAME,
    SQL_TEXT,
    CURRENT_USER(),
    TIMER_WAIT/1000000000    AS duration_ms,
    ROWS_AFFECTED,
    ERRORS
FROM performance_schema.events_statements_history_long
WHERE SQL_TEXT IS NOT NULL
ORDER BY EVENT_ID DESC
LIMIT 20;

-- -----------------------------------------------
-- METHOD 3: Create Audit Log Table
--           Custom solution when Enterprise
--           Audit is not available
-- -----------------------------------------------
USE CompanyDB;

CREATE TABLE IF NOT EXISTS SecurityAuditLog (
    AuditID         BIGINT          AUTO_INCREMENT PRIMARY KEY,
    EventTime       DATETIME        DEFAULT NOW(),
    DBUser          VARCHAR(100),
    ClientHost      VARCHAR(100),
    DatabaseName    VARCHAR(100),
    TableName       VARCHAR(100),
    Action          VARCHAR(20),
    RecordID        INT,
    OldValues       JSON,
    NewValues       JSON,
    SessionID       INT,
    INDEX idx_audit_time   (EventTime),
    INDEX idx_audit_user   (DBUser),
    INDEX idx_audit_action (Action)
) ENGINE=InnoDB;

-- Create audit trigger for Employees
DELIMITER $$

CREATE TRIGGER trg_employees_audit_insert
AFTER INSERT ON Employees
FOR EACH ROW
BEGIN
    INSERT INTO SecurityAuditLog (
        DBUser, ClientHost, DatabaseName,
        TableName, Action, RecordID, NewValues
    )
    VALUES (
        USER(),
        @@hostname,
        DATABASE(),
        'Employees',
        'INSERT',
        NEW.EmployeeID,
        JSON_OBJECT(
            'FirstName', NEW.FirstName,
            'LastName',  NEW.LastName,
            'Email',     NEW.Email,
            'Salary',    NEW.Salary,
            'JobTitle',  NEW.JobTitle
        )
    );
END$$

CREATE TRIGGER trg_employees_audit_update
AFTER UPDATE ON Employees
FOR EACH ROW
BEGIN
    INSERT INTO SecurityAuditLog (
        DBUser, ClientHost, DatabaseName,
        TableName, Action, RecordID,
        OldValues, NewValues
    )
    VALUES (
        USER(),
        @@hostname,
        DATABASE(),
        'Employees',
        'UPDATE',
        NEW.EmployeeID,
        JSON_OBJECT(
            'Salary',  OLD.Salary,
            'JobTitle',OLD.JobTitle,
            'Status',  OLD.Status
        ),
        JSON_OBJECT(
            'Salary',  NEW.Salary,
            'JobTitle',NEW.JobTitle,
            'Status',  NEW.Status
        )
    );
END$$

CREATE TRIGGER trg_employees_audit_delete
BEFORE DELETE ON Employees
FOR EACH ROW
BEGIN
    INSERT INTO SecurityAuditLog (
        DBUser, ClientHost, DatabaseName,
        TableName, Action, RecordID, OldValues
    )
    VALUES (
        USER(),
        @@hostname,
        DATABASE(),
        'Employees',
        'DELETE',
        OLD.EmployeeID,
        JSON_OBJECT(
            'FirstName', OLD.FirstName,
            'LastName',  OLD.LastName,
            'Email',     OLD.Email
        )
    );
END$$

DELIMITER ;

-- -----------------------------------------------
-- Query Audit Log
-- -----------------------------------------------

-- Recent activity
SELECT
    EventTime,
    DBUser,
    TableName,
    Action,
    RecordID
FROM SecurityAuditLog
ORDER BY EventTime DESC
LIMIT 20;

-- Suspicious activity - after hours
SELECT
    EventTime,
    DBUser,
    TableName,
    Action,
    RecordID
FROM SecurityAuditLog
WHERE HOUR(EventTime) NOT BETWEEN 7 AND 19
ORDER BY EventTime DESC;

-- Most active users
SELECT
    DBUser,
    Action,
    COUNT(*) AS ActionCount
FROM SecurityAuditLog
WHERE EventTime > DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY DBUser, Action
ORDER BY ActionCount DESC;
