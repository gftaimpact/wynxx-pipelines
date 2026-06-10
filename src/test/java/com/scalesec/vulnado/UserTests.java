package com.scalesec.vulnado;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

/**
 * Comprehensive unit tests for the User class.
 * Tests cover token generation, JWT authentication, and database fetch operations.
 * Mocking is used to isolate database dependencies via Mockito.
 */
class UserTest {

    @Mock
    private Connection mockConnection;
    @Mock
    private Statement mockStatement;
    @Mock
    private ResultSet mockResultSet;

    private User testUser;
    private static final String TEST_SECRET = "testSecretKeyForJWTTesting";
    private static final String TEST_USER_ID = "1";
    private static final String TEST_USERNAME = "testUser";
    private static final String TEST_PASSWORD = "hashedPassword";

    /**
     * Initializes mocks and creates a default test user before each test.
     */
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testUser = new User(TEST_USER_ID, TEST_USERNAME, TEST_PASSWORD);
    }

    // -------------------------------------------------------------------------
    // Helper / reusable methods
    // -------------------------------------------------------------------------

    /**
     * Configures the Postgres static mock and statement chain for a given ResultSet.
     */
    private void configureDatabaseMock(MockedStatic<Postgres> postgresMock) throws Exception {
        postgresMock.when(Postgres::connection).thenReturn(mockConnection);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockStatement.executeQuery(anyString())).thenReturn(mockResultSet);
    }

    /**
     * Populates the mock ResultSet to simulate a single matching user row.
     */
    private void configureResultSetWithUser(String userId, String username, String password) throws Exception {
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString("user_id")).thenReturn(userId);
        when(mockResultSet.getString("username")).thenReturn(username);
        when(mockResultSet.getString("password")).thenReturn(password);
    }

    /**
     * Builds a SecretKey from the test secret for token verification.
     */
    private SecretKey buildTestKey() {
        return Keys.hmacShaKeyFor(TEST_SECRET.getBytes());
    }

    /**
     * Generates a token for the testUser using the test secret.
     */
    private String generateTestToken() {
        return testUser.token(TEST_SECRET);
    }

    // -------------------------------------------------------------------------
    // Constructor tests
    // -------------------------------------------------------------------------

    /**
     * Verifies that User constructor correctly assigns all fields.
     */
    @Test
    @DisplayName("Constructor_WithValidArgs_ShouldAssignFields")
    void Constructor_WithValidArgs_ShouldAssignFields() {
        User user = new User("42", "alice", "pw123");
        assertEquals("42", user.id, "Constructor should correctly assign id");
        assertEquals("alice", user.username, "Constructor should correctly assign username");
        assertEquals("pw123", user.hashedPassword, "Constructor should correctly assign hashedPassword");
    }

    /**
     * Verifies that two User objects with different IDs have distinct identity.
     */
    @Test
    @DisplayName("Constructor_WithDifferentIds_ShouldCreateDistinctUsers")
    void Constructor_WithDifferentIds_ShouldCreateDistinctUsers() {
        User user1 = new User("1", "user1", "pw1");
        User user2 = new User("2", "user2", "pw2");
        assertNotEquals(user1.id, user2.id, "Users with different IDs should not share the same id");
    }

    // -------------------------------------------------------------------------
    // token() tests
    // -------------------------------------------------------------------------

    /**
     * Verifies that token() generates a non-null JWT string.
     */
    @Test
    @DisplayName("Token_Generate_ShouldReturnNonNull")
    void Token_Generate_ShouldReturnNonNull() {
        String token = generateTestToken();
        assertNotNull(token, "Generated token should not be null");
    }

    /**
     * Verifies that the returned token has the standard three-part JWT structure.
     */
    @Test
    @DisplayName("Token_Generate_ShouldHaveThreeJwtParts")
    void Token_Generate_ShouldHaveThreeJwtParts() {
        String token = generateTestToken();
        assertEquals(3, token.split("\\.").length, "Token should have three parts separated by dots (header.payload.signature)");
    }

    /**
     * Verifies that the JWT subject matches the username of the user who created it.
     */
    @Test
    @DisplayName("Token_Generate_ShouldContainCorrectUsernameAsSubject")
    void Token_Generate_ShouldContainCorrectUsernameAsSubject() {
        String token = generateTestToken();
        String subject = Jwts.parserBuilder()
                .setSigningKey(buildTestKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
        assertEquals(TEST_USERNAME, subject, "Token subject should match the username");
    }

    /**
     * Verifies that two different users produce distinct tokens.
     */
    @Test
    @DisplayName("Token_ForDifferentUsers_ShouldGenerateUniqueTokens")
    void Token_ForDifferentUsers_ShouldGenerateUniqueTokens() {
        User user1 = new User("1", "user1", "password1");
        User user2 = new User("2", "user2", "password2");

        String token1 = user1.token(TEST_SECRET);
        String token2 = user2.token(TEST_SECRET);

        assertNotEquals(token1, token2, "Tokens for different users should be unique");
    }

    /**
     * Verifies that the same user generates the same token when called twice
     * (deterministic because no nonce/time-based claims are added).
     */
    @Test
    @DisplayName("Token_SameUserCalledTwice_ShouldProduceSameToken")
    void Token_SameUserCalledTwice_ShouldProduceSameToken() {
        String token1 = testUser.token(TEST_SECRET);
        String token2 = testUser.token(TEST_SECRET);
        assertEquals(token1, token2, "Token for the same user and secret should be deterministic");
    }

    /**
     * Verifies that different secrets produce different tokens for the same user.
     */
    @Test
    @DisplayName("Token_WithDifferentSecrets_ShouldProduceDifferentTokens")
    void Token_WithDifferentSecrets_ShouldProduceDifferentTokens() {
        String token1 = testUser.token("secretOne_aaaaaaaaaaaaaaaa");
        String token2 = testUser.token("secretTwo_aaaaaaaaaaaaaaaa");
        assertNotEquals(token1, token2, "Tokens generated with different secrets should differ");
    }

    // -------------------------------------------------------------------------
    // assertAuth() tests
    // -------------------------------------------------------------------------

    /**
     * Verifies that assertAuth() does not throw when a valid token is provided.
     */
    @Test
    @DisplayName("AssertAuth_WithValidToken_ShouldNotThrowException")
    void AssertAuth_WithValidToken_ShouldNotThrowException() {
        String token = generateTestToken();
        assertDoesNotThrow(
                () -> User.assertAuth(TEST_SECRET, token),
                "assertAuth should not throw an exception for a valid token"
        );
    }

    /**
     * Verifies that assertAuth() throws Unauthorized for a completely invalid token string.
     */
    @Test
    @DisplayName("AssertAuth_WithInvalidToken_ShouldThrowUnauthorized")
    void AssertAuth_WithInvalidToken_ShouldThrowUnauthorized() {
        assertThrows(
                Unauthorized.class,
                () -> User.assertAuth(TEST_SECRET, "invalidToken"),
                "assertAuth should throw Unauthorized for invalid token"
        );
    }

    /**
     * Verifies that assertAuth() throws Unauthorized when the last character of the
     * token signature is tampered with.
     */
    @Test
    @DisplayName("AssertAuth_WithModifiedToken_ShouldThrowUnauthorized")
    void AssertAuth_WithModifiedToken_ShouldThrowUnauthorized() {
        String token = generateTestToken();
        String modifiedToken = token.substring(0, token.length() - 1) + "X";
        assertThrows(
                Unauthorized.class,
                () -> User.assertAuth(TEST_SECRET, modifiedToken),
                "assertAuth should throw Unauthorized for a tampered token"
        );
    }

    /**
     * Verifies that assertAuth() throws Unauthorized for an expired token.
     */
    @Test
    @DisplayName("AssertAuth_WithExpiredToken_ShouldThrowUnauthorized")
    void AssertAuth_WithExpiredToken_ShouldThrowUnauthorized() {
        String expiredToken = Jwts.builder()
                .setSubject(TEST_USERNAME)
                .setExpiration(new java.util.Date(System.currentTimeMillis() - 1000))
                .signWith(buildTestKey())
                .compact();

        assertThrows(
                Unauthorized.class,
                () -> User.assertAuth(TEST_SECRET, expiredToken),
                "assertAuth should throw Unauthorized for an expired token"
        );
    }

    /**
     * Verifies that assertAuth() throws Unauthorized when the signing secret is wrong.
     */
    @Test
    @DisplayName("AssertAuth_WithWrongSecret_ShouldThrowUnauthorized")
    void AssertAuth_WithWrongSecret_ShouldThrowUnauthorized() {
        String token = generateTestToken();
        assertThrows(
                Unauthorized.class,
                () -> User.assertAuth("completelydifferentsecretkey", token),
                "assertAuth should throw Unauthorized when validated with the wrong secret"
        );
    }

    /**
     * Verifies that assertAuth() prints a stack trace to stderr on exception.
     */
    @Test
    @DisplayName("AssertAuth_WithInvalidToken_ShouldPrintStackTrace")
    void AssertAuth_WithInvalidToken_ShouldPrintStackTrace() {
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream originalErr = System.err;
        System.setErr(new PrintStream(errContent));

        try {
            assertThrows(Unauthorized.class, () -> User.assertAuth(TEST_SECRET, "badToken"));
            assertTrue(errContent.toString().contains("Stack trace:"),
                    "assertAuth should print stack trace on exception");
        } finally {
            System.setErr(originalErr);
        }
    }

    /**
     * Verifies that assertAuth() throws Unauthorized for an empty string token.
     */
    @Test
    @DisplayName("AssertAuth_WithEmptyToken_ShouldThrowUnauthorized")
    void AssertAuth_WithEmptyToken_ShouldThrowUnauthorized() {
        assertThrows(
                Unauthorized.class,
                () -> User.assertAuth(TEST_SECRET, ""),
                "assertAuth should throw Unauthorized for an empty token string"
        );
    }

    // -------------------------------------------------------------------------
    // fetch() tests
    // -------------------------------------------------------------------------

    /**
     * Verifies that fetch() returns a properly populated User when a row exists.
     */
    @Test
    @DisplayName("Fetch_WithExistingUser_ShouldReturnUser")
    void Fetch_WithExistingUser_ShouldReturnUser() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            configureDatabaseMock(postgresMock);
            configureResultSetWithUser(TEST_USER_ID, TEST_USERNAME, TEST_PASSWORD);

            User result = User.fetch(TEST_USERNAME);

            assertNotNull(result, "Fetch should return a user for an existing username");
            assertEquals(TEST_USERNAME, result.username, "Fetched user should have the correct username");
            assertEquals(TEST_USER_ID, result.id, "Fetched user should have the correct id");
            assertEquals(TEST_PASSWORD, result.hashedPassword, "Fetched user should have the correct hashed password");
        }
    }

    /**
     * Verifies that fetch() returns null when no rows are found for the given username.
     */
    @Test
    @DisplayName("Fetch_WithNonExistingUser_ShouldReturnNull")
    void Fetch_WithNonExistingUser_ShouldReturnNull() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            configureDatabaseMock(postgresMock);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch("nonExistingUser");

            assertNull(result, "Fetch should return null when no user matches the username");
        }
    }

    /**
     * Verifies that fetch() returns null when the database throws an exception.
     */
    @Test
    @DisplayName("Fetch_WithDatabaseException_ShouldReturnNull")
    void Fetch_WithDatabaseException_ShouldReturnNull() {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenThrow(new RuntimeException("DB connection failed"));

            User result = User.fetch("exceptionUser");

            assertNull(result, "Fetch should return null when a database exception occurs");
        }
    }

    /**
     * Verifies that fetch() executes the expected SQL query including the username.
     */
    @Test
    @DisplayName("Fetch_WithValidUsername_ShouldExecuteCorrectSQLQuery")
    void Fetch_WithValidUsername_ShouldExecuteCorrectSQLQuery() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            configureDatabaseMock(postgresMock);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(TEST_USERNAME);

            String expectedQuery = "select * from users where username = '" + TEST_USERNAME + "' limit 1";
            verify(mockStatement).executeQuery(expectedQuery);
        }
    }

    /**
     * Verifies that fetch() closes the database connection after a successful query.
     */
    @Test
    @DisplayName("Fetch_AfterSuccessfulQuery_ShouldCloseConnection")
    void Fetch_AfterSuccessfulQuery_ShouldCloseConnection() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            configureDatabaseMock(postgresMock);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(TEST_USERNAME);

            verify(mockConnection).close();
        }
    }

    /**
     * Verifies that fetch() prints "Opened database successfully" to stdout.
     */
    @Test
    @DisplayName("Fetch_OnDatabaseOpen_ShouldPrintOpenedDatabaseMessage")
    void Fetch_OnDatabaseOpen_ShouldPrintOpenedDatabaseMessage() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            configureDatabaseMock(postgresMock);
            when(mockResultSet.next()).thenReturn(false);

            ByteArrayOutputStream outContent = new ByteArrayOutputStream();
            PrintStream originalOut = System.out;
            System.setOut(new PrintStream(outContent));

            try {
                User.fetch(TEST_USERNAME);
            } finally {
                System.setOut(originalOut);
            }

            assertTrue(outContent.toString().contains("Opened database successfully"),
                    "Fetch should print 'Opened database successfully' to stdout");
        }
    }

    /**
     * Verifies that fetch() prints the SQL query string to stdout before execution.
     */
    @Test
    @DisplayName("Fetch_BeforeQueryExecution_ShouldPrintQueryToStdout")
    void Fetch_BeforeQueryExecution_ShouldPrintQueryToStdout() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            configureDatabaseMock(postgresMock);
            when(mockResultSet.next()).thenReturn(false);

            ByteArrayOutputStream outContent = new ByteArrayOutputStream();
            PrintStream originalOut = System.out;
            System.setOut(new PrintStream(outContent));

            try {
                User.fetch(TEST_USERNAME);
            } finally {
                System.setOut(originalOut);
            }

            String expectedQuery = "select * from users where username = '" + TEST_USERNAME + "' limit 1";
            assertTrue(outContent.toString().contains(expectedQuery),
                    "Fetch should print the executed SQL query to stdout");
        }
    }

    /**
     * Verifies that fetch() prints the exception class and message to stderr on error.
     */
    @Test
    @DisplayName("Fetch_OnDatabaseException_ShouldPrintErrorToStderr")
    void Fetch_OnDatabaseException_ShouldPrintErrorToStderr() {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenThrow(new RuntimeException("Test database exception"));

            ByteArrayOutputStream errContent = new ByteArrayOutputStream();
            PrintStream originalErr = System.err;
            System.setErr(new PrintStream(errContent));

            try {
                User result = User.fetch("exceptionUser");
                assertNull(result, "Fetch should return null when an exception occurs");
                assertTrue(errContent.toString().contains("Test database exception"),
                        "Fetch should print the exception message to stderr");
            } finally {
                System.setErr(originalErr);
            }
        }
    }

    /**
     * Verifies that fetch() returns only the first matching user when multiple rows exist.
     * The SQL uses LIMIT 1, so the loop should stop at the first row.
     */
    @Test
    @DisplayName("Fetch_WithMultipleResults_ShouldReturnFirstUser")
    void Fetch_WithMultipleResults_ShouldReturnFirstUser() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            configureDatabaseMock(postgresMock);
            when(mockResultSet.next()).thenReturn(true, true, false);
            when(mockResultSet.getString("user_id")).thenReturn("1", "2");
            when(mockResultSet.getString("username")).thenReturn(TEST_USERNAME, TEST_USERNAME);
            when(mockResultSet.getString("password")).thenReturn("password1", "password2");

            User result = User.fetch(TEST_USERNAME);

            assertNotNull(result, "Fetch should return a user when multiple results exist");
            assertEquals("1", result.id, "Fetch should return the first user when multiple rows exist");
        }
    }

    /**
     * Verifies that fetch() includes a raw SQL injection payload in the query,
     * demonstrating the vulnerability (no parameterization). Result should be null
     * if no such user exists.
     */
    @Test
    @DisplayName("Fetch_WithSQLInjectionUsername_ShouldIncludeRawPayloadInQuery")
    void Fetch_WithSQLInjectionUsername_ShouldIncludeRawPayloadInQuery() throws Exception {
        String maliciousUsername = "user' OR '1'='1";
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            configureDatabaseMock(postgresMock);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(maliciousUsername);

            assertNull(result, "Fetch should return null for SQL injection attempt with no matching row");
            verify(mockStatement).executeQuery(
                    "select * from users where username = '" + maliciousUsername + "' limit 1"
            );
        }
    }

    /**
     * Verifies that the query contains the DELETE keyword present in the vulnerable
     * query string, illustrating the SQL injection vulnerability comment in the code.
     */
    @Test
    @DisplayName("Fetch_QueryString_ShouldContainDeleteKeywordFromVulnerableCode")
    void Fetch_QueryString_ShouldContainDeleteKeywordFromVulnerableCode() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            configureDatabaseMock(postgresMock);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(TEST_USERNAME);

            // The original query string appends "DELETE" after "limit 1"
            verify(mockStatement).executeQuery(contains("DELETE"));
        }
    }

    /**
     * Verifies that the statement is created from the connection during fetch().
     */
    @Test
    @DisplayName("Fetch_WithValidConnection_ShouldCreateStatement")
    void Fetch_WithValidConnection_ShouldCreateStatement() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            configureDatabaseMock(postgresMock);
            when(mockResultSet.next()).thenReturn(false);

            User.fetch(TEST_USERNAME);

            verify(mockConnection).createStatement();
        }
    }

    /**
     * Verifies that fetch() correctly maps all three column values from the ResultSet
     * into the returned User object fields.
     */
    @Test
    @DisplayName("Fetch_WithResultSet_ShouldMapAllColumnsToUserFields")
    void Fetch_WithResultSet_ShouldMapAllColumnsToUserFields() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            configureDatabaseMock(postgresMock);
            configureResultSetWithUser("99", "mappedUser", "mappedPass");

            User result = User.fetch("mappedUser");

            assertNotNull(result, "Fetch should return a non-null user");
            assertEquals("99", result.id, "User id should map from 'user_id' column");
            assertEquals("mappedUser", result.username, "User username should map from 'username' column");
            assertEquals("mappedPass", result.hashedPassword, "User hashedPassword should map from 'password' column");
        }
    }

    /**
     * Verifies that fetch() handles a null username argument gracefully
     * (no NPE; returns null because query executes with literal 'null').
     */
    @Test
    @DisplayName("Fetch_WithNullUsername_ShouldReturnNull")
    void Fetch_WithNullUsername_ShouldReturnNull() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            configureDatabaseMock(postgresMock);
            when(mockResultSet.next()).thenReturn(false);

            User result = User.fetch(null);

            assertNull(result, "Fetch should return null when username is null and no row is found");
        }
    }

    /**
     * Verifies that an exception thrown by executeQuery still results in null being returned.
     */
    @Test
    @DisplayName("Fetch_WhenExecuteQueryThrows_ShouldReturnNull")
    void Fetch_WhenExecuteQueryThrows_ShouldReturnNull() throws Exception {
        try (MockedStatic<Postgres> postgresMock = mockStatic(Postgres.class)) {
            postgresMock.when(Postgres::connection).thenReturn(mockConnection);
            when(mockConnection.createStatement()).thenReturn(mockStatement);
            when(mockStatement.executeQuery(anyString())).thenThrow(new RuntimeException("Query failed"));

            User result = User.fetch(TEST_USERNAME);

            assertNull(result, "Fetch should return null when executeQuery throws an exception");
        }
    }
}
