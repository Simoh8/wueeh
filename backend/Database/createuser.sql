CREATE PROCEDURE Create_Table (@Id INT, @Name VARCHAR(50), @Email VARCHAR(100), @Password VARCHAR(50))
AS
BEGIN
    SET NOCOUNT ON;

    IF OBJECT_ID('UserInfo', 'U') IS NOT NULL
        DROP TABLE UserInfo;

    CREATE TABLE UserInfo
    (
        Id INT PRIMARY KEY,
        Name VARCHAR(50),
        Email VARCHAR(100),
        Password VARCHAR(50)
    );

    INSERT INTO UserInfo (Id, Name, Email, Password)
    VALUES (@Id, @Name, @Email, @Password);
END;
