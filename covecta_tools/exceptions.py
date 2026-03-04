"""
Custom exception classes for the Covecta Tools SDK

These exceptions map HTTP status codes and connection errors to appropriate
Python exceptions for better error handling in client applications.
"""


class CovectaToolsException(Exception):
    """Base exception for all Covecta Tools SDK errors"""
    
    def __init__(self, message: str, status_code: int = None, detail: dict = None):
        """
        Initialize a Covecta Tools exception.
        
        Args:
            message: Human-readable error message
            status_code: HTTP status code (if applicable)
            detail: Additional error details from the API response
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.detail = detail or {}


class CovectaToolsConnectionError(CovectaToolsException):
    """Raised when unable to connect to the Covecta Tools service"""
    pass


class CovectaToolsNotFoundError(CovectaToolsException):
    """Raised when a requested resource (tool, namespace) is not found (404)"""
    pass


class CovectaToolsValidationError(CovectaToolsException):
    """Raised when request validation fails (422)"""
    pass


class CovectaToolsServerError(CovectaToolsException):
    """Raised when the Covecta Tools service returns a server error (5xx)"""
    pass


class CovectaToolsTimeoutError(CovectaToolsException):
    """Raised when a request times out (504)"""
    pass


class CovectaToolsBadGatewayError(CovectaToolsException):
    """Raised when the Covecta Tools service returns a bad gateway error (502)"""
    pass
