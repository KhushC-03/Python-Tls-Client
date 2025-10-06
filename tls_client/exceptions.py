import re
from typing import Optional, Dict, Any


class TLSClientException(IOError):
    """Base exception class for all TLS client errors"""
    def __init__(self, message, response = None, request_payload = None):
        self.message = message
        self.response = response
        self.request_payload = request_payload
        super().__init__(message)


class RequestException(TLSClientException):
    """Base class for all request-related exceptions"""


class ConnectionError(RequestException):
    """Raised when a connection error occurs"""


class Timeout(RequestException):
    """Raised when the request times out"""


class ConnectTimeout(Timeout):
    """Raised when the connection attempt times out"""


class ReadTimeout(Timeout):
    """Raised when the server does not send data within the allotted time"""


class SSLError(ConnectionError):
    """Raised when SSL/TLS certificate verification fails"""


class ProxyError(ConnectionError):
    """Raised when proxy-related errors occur"""


class InvalidURL(RequestException):
    """Raised when the URL is invalid"""


class InvalidHeader(RequestException):
    """Raised when an invalid header is provided"""


class ChunkedEncodingError(RequestException):
    """Raised when the server declared chunked encoding but sent invalid chunks"""


class ContentDecodingError(RequestException):
    """Raised when the content encoding is invalid"""


class StreamConsumedError(RequestException):
    """Raised when attempting to access consumed stream content"""


class RetryError(RequestException):
    """Raised when max retries are exceeded"""


class TooManyRedirects(RequestException):
    """Raised when the maximum number of redirects is exceeded"""


class MissingSchema(RequestException):
    """Raised when the URL schema (http/https) is missing"""


class InvalidSchema(RequestException):
    """Raised when the URL schema is invalid"""


class InvalidProxyURL(ProxyError):
    """Raised when the proxy URL is invalid"""


class ProxyConnectionError(ProxyError):
    """Raised when unable to connect to the proxy"""


class ProxyAuthenticationRequired(ProxyError):
    """Raised when proxy requires authentication (407)"""
    
class ProxyFlagged(ProxyError):
    """Raised when an HTTP error status is returned (403), the proxy has been flagged"""

class ProxyDenied(ProxyError):
    """Raised when an HTTP error status is returned (502), the proxy has been denied"""
    
class HTTPError(RequestException):
    """Raised when an HTTP error status is returned (4xx, 5xx)"""
    



class ErrorClassifier:

    # all the differnt error types, so we can use regex to find them
    ERROR_PATTERNS = {
        # Timeout errors
        ConnectTimeout: [
            r"connect timeout",
            r"connection timeout", 
            r"dial tcp.*i/o timeout",
        ],
        Timeout: [
            r"context deadline exceeded",
            r"operation timed out", 
            r"i/o timeout",
            r"timeout",
        ],
        ReadTimeout: [
            r"read timeout",
            r"TLS handshake timeout",
        ],
        
        # SSL/Certificate errors
        SSLError: [
            r"certificate",
            r"x509",
            r"tls",
            r"ssl",
            r"handshake failure",
            r"certificate verify failed"
        ],
        
        # Proxy errors
        ProxyAuthenticationRequired: [
            r"407",
            r"proxy authentication required",
            r"proxy auth",
        ],
        ProxyConnectionError: [
            r"proxy connection failed",
            r"unable to connect to proxy",
            r"proxy refused connection",
            r"SOCKS5 proxy",
        ],
        InvalidProxyURL: [
            r"invalid proxy url",
            r"malformed proxy url",
        ],
        
        # Connection errors
        ConnectionError: [
            r"connection refused",
            r"connection reset",
            r"connection aborted",
            r"broken pipe",
            r"network is unreachable",
            r"no route to host",
            r"connection closed",
            r"EOF",
            r"dial tcp",
            r"no such host",
            r"cannot connect",
            r"connection failed",
        ],
        
        # URL errors
        InvalidURL: [
            r"invalid url",
            r"malformed url",
            r"no host",
            r"invalid host",
        ],
        MissingSchema: [
            r"no schema",
            r"missing schema",
            r"invalid scheme",
        ],
        
        # Encoding/Decoding errors
        ContentDecodingError: [
            r"decode error",
            r"decompression error",
            r"invalid encoding",
            r"gzip: invalid header",
        ],
        ChunkedEncodingError: [
            r"chunked encoding error",
            r"invalid chunk",
        ],
        
        # Other errors
        TooManyRedirects: [
            r"max redirects",
            r"too many redirects",
            r"redirect loop",
        ],
    }
    
    @classmethod
    def classify_error(cls, error_message, response, request_payload):
        """
        Here we can match the error message with the correct exception class

        """
        
        if not error_message:
            return TLSClientException("Unknown error", response, request_payload)
        
        error_lower = error_message.lower()
        
        for exception_class, patterns in cls.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, error_lower):
                    return exception_class(error_message, response, request_payload)
        
        # Check if it's a server returning 407, 403, 502 (as opposed to proxy) so then it helps us differntiate it for sites like RAH
        if response and hasattr(response, 'status_code'):
            if response.status_code == 407:
                # Server returned 407, not a proxy error
                return HTTPError(error_message, response, request_payload)
            
            if response.status_code == 403:
                # Server returned 403
                return ProxyFlagged(error_message, response, request_payload)

            if response.status_code == 502:
                # Server returned 502
                return ProxyDenied(error_message, response, request_payload)
        
        # Default to base exception if no pattern matches
        return TLSClientException(error_message, response, request_payload)
    
    @classmethod
    def raise_for_error(cls, error_message, response, request_payload):
        """
        classify and raise an appropriate exception
        """
        raise cls.classify_error(error_message, response, request_payload)

