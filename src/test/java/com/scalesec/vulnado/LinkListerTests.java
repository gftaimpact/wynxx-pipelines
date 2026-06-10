import com.scalesec.vulnado.BadRequest;
import com.scalesec.vulnado.LinkLister;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.jsoup.Jsoup;
import org.jsoup.Connection;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the LinkLister class.
 * Tests cover both getLinks and getLinksV2 methods, including
 * edge cases such as private IP ranges, invalid URLs, and valid public URLs.
 * Tests are designed for independent and parallel execution.
 */
@Execution(ExecutionMode.CONCURRENT)
public class LinkListerTest {

    // Reusable constants for test data
    private static final String VALID_PUBLIC_URL = "http://example.com";
    private static final String PRIVATE_IP_172_URL = "http://172.16.0.1/page";
    private static final String PRIVATE_IP_192_URL = "http://192.168.1.1/page";
    private static final String PRIVATE_IP_10_URL = "http://10.0.0.1/page";
    private static final String MALFORMED_URL = "not_a_valid_url";
    private static final String EMPTY_URL = "";
    private static final String LINK_HREF_1 = "http://example.com/page1";
    private static final String LINK_HREF_2 = "http://example.com/page2";

    /**
     * Helper method to create a mocked Jsoup Document with anchor elements.
     * Builds a Document containing the given absolute href values.
     */
    private Document buildMockDocument(String... absUrls) {
        Document doc = new Document(VALID_PUBLIC_URL);
        for (String absUrl : absUrls) {
            Element anchor = doc.createElement("a");
            anchor.attr("href", absUrl);
            anchor.attr("abs:href", absUrl);
            doc.body().appendChild(anchor);
        }
        return doc;
    }

    /**
     * Helper method to mock the Jsoup static connection and return a pre-built Document.
     */
    private MockedStatic<Jsoup> mockJsoupWithDocument(String url, Document document) throws IOException {
        MockedStatic<Jsoup> jsoupMock = Mockito.mockStatic(Jsoup.class);
        Connection mockConnection = mock(Connection.class);
        when(mockConnection.get()).thenReturn(document);
        jsoupMock.when(() -> Jsoup.connect(url)).thenReturn(mockConnection);
        return jsoupMock;
    }

    // ==================== getLinks Tests ====================

    /**
     * Test: getLinks with a valid URL returns a non-null list.
     * Approach: Mock Jsoup to return a Document with known links.
     */
    @Test
    @DisplayName("GetLinks_ValidUrl_ShouldReturnNonNullList")
    public void GetLinks_ValidUrl_ShouldReturnNonNullList() throws IOException {
        Document doc = buildMockDocument(LINK_HREF_1, LINK_HREF_2);
        try (MockedStatic<Jsoup> jsoupMock = mockJsoupWithDocument(VALID_PUBLIC_URL, doc)) {
            List<String> result = LinkLister.getLinks(VALID_PUBLIC_URL);
            assertNotNull(result, "Result list should not be null for a valid URL");
        }
    }

    /**
     * Test: getLinks with a valid URL containing multiple links returns correct count.
     * Approach: Mock Jsoup with a Document containing two anchor elements.
     */
    @Test
    @DisplayName("GetLinks_ValidUrlWithMultipleLinks_ShouldReturnCorrectCount")
    public void GetLinks_ValidUrlWithMultipleLinks_ShouldReturnCorrectCount() throws IOException {
        Document doc = buildMockDocument(LINK_HREF_1, LINK_HREF_2);
        try (MockedStatic<Jsoup> jsoupMock = mockJsoupWithDocument(VALID_PUBLIC_URL, doc)) {
            List<String> result = LinkLister.getLinks(VALID_PUBLIC_URL);
            assertEquals(2, result.size(), "Result list should contain exactly 2 links");
        }
    }

    /**
     * Test: getLinks with a valid URL containing no links returns an empty list.
     * Approach: Mock Jsoup with a Document that has no anchor elements.
     */
    @Test
    @DisplayName("GetLinks_ValidUrlWithNoLinks_ShouldReturnEmptyList")
    public void GetLinks_ValidUrlWithNoLinks_ShouldReturnEmptyList() throws IOException {
        Document doc = buildMockDocument();
        try (MockedStatic<Jsoup> jsoupMock = mockJsoupWithDocument(VALID_PUBLIC_URL, doc)) {
            List<String> result = LinkLister.getLinks(VALID_PUBLIC_URL);
            assertTrue(result.isEmpty(), "Result list should be empty when document has no links");
        }
    }

    /**
     * Test: getLinks propagates IOException when Jsoup connection fails.
     * Approach: Mock Jsoup connection to throw IOException.
     */
    @Test
    @DisplayName("GetLinks_JsoupThrowsIOException_ShouldPropagateException")
    public void GetLinks_JsoupThrowsIOException_ShouldPropagateException() {
        try (MockedStatic<Jsoup> jsoupMock = Mockito.mockStatic(Jsoup.class)) {
            Connection mockConnection = mock(Connection.class);
            try {
                when(mockConnection.get()).thenThrow(new IOException("Connection refused"));
            } catch (IOException e) {
                fail("Unexpected exception during mock setup");
            }
            jsoupMock.when(() -> Jsoup.connect(VALID_PUBLIC_URL)).thenReturn(mockConnection);

            assertThrows(IOException.class,
                    () -> LinkLister.getLinks(VALID_PUBLIC_URL),
                    "getLinks should propagate IOException from Jsoup");
        }
    }

    /**
     * Test: getLinks returns links matching expected href values.
     * Approach: Mock Jsoup with specific hrefs and verify list contents.
     */
    @Test
    @DisplayName("GetLinks_ValidUrlWithKnownLinks_ShouldReturnMatchingHrefs")
    public void GetLinks_ValidUrlWithKnownLinks_ShouldReturnMatchingHrefs() throws IOException {
        Document doc = buildMockDocument(LINK_HREF_1, LINK_HREF_2);
        try (MockedStatic<Jsoup> jsoupMock = mockJsoupWithDocument(VALID_PUBLIC_URL, doc)) {
            List<String> result = LinkLister.getLinks(VALID_PUBLIC_URL);
            assertTrue(result.contains(LINK_HREF_1),
                    "Result should contain the first expected link href");
            assertTrue(result.contains(LINK_HREF_2),
                    "Result should contain the second expected link href");
        }
    }

    // ==================== getLinksV2 Tests ====================

    /**
     * Test: getLinksV2 with a public URL should return links without throwing.
     * Approach: Mock Jsoup to return a Document with known links; verify no exception.
     */
    @Test
    @DisplayName("GetLinksV2_ValidPublicUrl_ShouldReturnLinks")
    public void GetLinksV2_ValidPublicUrl_ShouldReturnLinks() throws IOException {
        Document doc = buildMockDocument(LINK_HREF_1);
        try (MockedStatic<Jsoup> jsoupMock = mockJsoupWithDocument(VALID_PUBLIC_URL, doc)) {
            assertDoesNotThrow(() -> {
                List<String> result = LinkLister.getLinksV2(VALID_PUBLIC_URL);
                assertNotNull(result, "Result should not be null for a valid public URL");
            }, "getLinksV2 should not throw for a valid public URL");
        }
    }

    /**
     * Test: getLinksV2 with a 172.x.x.x private IP URL should throw BadRequest.
     * Approach: Pass a URL with a 172.x host; verify BadRequest is thrown with correct message.
     */
    @Test
    @DisplayName("GetLinksV2_PrivateIp172Range_ShouldThrowBadRequest")
    public void GetLinksV2_PrivateIp172Range_ShouldThrowBadRequest() {
        BadRequest exception = assertThrows(BadRequest.class,
                () -> LinkLister.getLinksV2(PRIVATE_IP_172_URL),
                "getLinksV2 should throw BadRequest for 172.x.x.x IP range");
        assertNotNull(exception.getMessage(),
                "BadRequest exception message should not be null");
    }

    /**
     * Test: getLinksV2 with a 192.168.x.x private IP URL should throw BadRequest.
     * Approach: Pass a URL with a 192.168 host; verify BadRequest is thrown.
     */
    @Test
    @DisplayName("GetLinksV2_PrivateIp192Range_ShouldThrowBadRequest")
    public void GetLinksV2_PrivateIp192Range_ShouldThrowBadRequest() {
        BadRequest exception = assertThrows(BadRequest.class,
                () -> LinkLister.getLinksV2(PRIVATE_IP_192_URL),
                "getLinksV2 should throw BadRequest for 192.168.x.x IP range");
        assertNotNull(exception.getMessage(),
                "BadRequest exception message should not be null");
    }

    /**
     * Test: getLinksV2 with a 10.x.x.x private IP URL should throw BadRequest.
     * Approach: Pass a URL with a 10.x host; verify BadRequest is thrown.
     */
    @Test
    @DisplayName("GetLinksV2_PrivateIp10Range_ShouldThrowBadRequest")
    public void GetLinksV2_PrivateIp10Range_ShouldThrowBadRequest() {
        BadRequest exception = assertThrows(BadRequest.class,
                () -> LinkLister.getLinksV2(PRIVATE_IP_10_URL),
                "getLinksV2 should throw BadRequest for 10.x.x.x IP range");
        assertNotNull(exception.getMessage(),
                "BadRequest exception message should not be null");
    }

    /**
     * Test: getLinksV2 with a malformed/invalid URL should throw BadRequest.
     * Approach: Pass a non-URL string; verify BadRequest is thrown.
     */
    @Test
    @DisplayName("GetLinksV2_MalformedUrl_ShouldThrowBadRequest")
    public void GetLinksV2_MalformedUrl_ShouldThrowBadRequest() {
        assertThrows(BadRequest.class,
                () -> LinkLister.getLinksV2(MALFORMED_URL),
                "getLinksV2 should throw BadRequest for a malformed URL");
    }

    /**
     * Test: getLinksV2 with an empty string URL should throw BadRequest.
     * Approach: Pass an empty string; verify BadRequest is thrown.
     */
    @Test
    @DisplayName("GetLinksV2_EmptyUrl_ShouldThrowBadRequest")
    public void GetLinksV2_EmptyUrl_ShouldThrowBadRequest() {
        assertThrows(BadRequest.class,
                () -> LinkLister.getLinksV2(EMPTY_URL),
                "getLinksV2 should throw BadRequest for an empty URL string");
    }

    /**
     * Test: getLinksV2 with a 172.x URL should have BadRequest message indicating private IPs.
     * Approach: Pass private IP URL and inspect the exception message content.
     */
    @Test
    @DisplayName("GetLinksV2_PrivateIp172Range_ShouldHavePrivateIpMessage")
    public void GetLinksV2_PrivateIp172Range_ShouldHavePrivateIpMessage() {
        BadRequest exception = assertThrows(BadRequest.class,
                () -> LinkLister.getLinksV2(PRIVATE_IP_172_URL),
                "getLinksV2 should throw BadRequest with private IP message for 172.x range");
        assertTrue(exception.getMessage().contains("Private"),
                "BadRequest message should indicate the use of private IPs");
    }

    /**
     * Test: getLinksV2 with a 192.168.x.x URL should have BadRequest message indicating private IPs.
     * Approach: Pass private IP URL and inspect the exception message content.
     */
    @Test
    @DisplayName("GetLinksV2_PrivateIp192Range_ShouldHavePrivateIpMessage")
    public void GetLinksV2_PrivateIp192Range_ShouldHavePrivateIpMessage() {
        BadRequest exception = assertThrows(BadRequest.class,
                () -> LinkLister.getLinksV2(PRIVATE_IP_192_URL),
                "getLinksV2 should throw BadRequest with private IP message for 192.168 range");
        assertTrue(exception.getMessage().contains("Private"),
                "BadRequest message should indicate the use of private IPs");
    }

    /**
     * Test: getLinksV2 with a 10.x.x.x URL should have BadRequest message indicating private IPs.
     * Approach: Pass private IP URL and inspect the exception message content.
     */
    @Test
    @DisplayName("GetLinksV2_PrivateIp10Range_ShouldHavePrivateIpMessage")
    public void GetLinksV2_PrivateIp10Range_ShouldHavePrivateIpMessage() {
        BadRequest exception = assertThrows(BadRequest.class,
                () -> LinkLister.getLinksV2(PRIVATE_IP_10_URL),
                "getLinksV2 should throw BadRequest with private IP message for 10.x range");
        assertTrue(exception.getMessage().contains("Private"),
                "BadRequest message should indicate the use of private IPs");
    }

    /**
     * Test: getLinksV2 with a valid public URL returns a list with expected size.
     * Approach: Mock Jsoup with two links and verify the returned count.
     */
    @Test
    @DisplayName("GetLinksV2_ValidPublicUrlWithMultipleLinks_ShouldReturnCorrectCount")
    public void GetLinksV2_ValidPublicUrlWithMultipleLinks_ShouldReturnCorrectCount() throws IOException {
        Document doc = buildMockDocument(LINK_HREF_1, LINK_HREF_2);
        try (MockedStatic<Jsoup> jsoupMock = mockJsoupWithDocument(VALID_PUBLIC_URL, doc)) {
            assertDoesNotThrow(() -> {
                List<String> result = LinkLister.getLinksV2(VALID_PUBLIC_URL);
                assertEquals(2, result.size(),
                        "getLinksV2 should return list with correct link count for public URL");
            }, "getLinksV2 should not throw for a valid public URL");
        }
    }

    /**
     * Test: getLinksV2 with a valid public URL returns the correct link values.
     * Approach: Mock Jsoup with known hrefs and verify list contents.
     */
    @Test
    @DisplayName("GetLinksV2_ValidPublicUrlWithKnownLinks_ShouldReturnMatchingHrefs")
    public void GetLinksV2_ValidPublicUrlWithKnownLinks_ShouldReturnMatchingHrefs() throws IOException {
        Document doc = buildMockDocument(LINK_HREF_1, LINK_HREF_2);
        try (MockedStatic<Jsoup> jsoupMock = mockJsoupWithDocument(VALID_PUBLIC_URL, doc)) {
            assertDoesNotThrow(() -> {
                List<String> result = LinkLister.getLinksV2(VALID_PUBLIC_URL);
                assertTrue(result.contains(LINK_HREF_1),
                        "getLinksV2 result should contain the first expected link href");
                assertTrue(result.contains(LINK_HREF_2),
                        "getLinksV2 result should contain the second expected link href");
            }, "getLinksV2 should not throw for a valid public URL");
        }
    }
}
