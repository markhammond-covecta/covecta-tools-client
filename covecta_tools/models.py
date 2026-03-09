"""
Pydantic models for Covecta Tools SDK request and response types

These models provide type-safe data structures for interacting with the Covecta Tools API.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class ToolSummary(BaseModel):
    """Summary information about a tool"""
    
    tool_name: str = Field(..., description="The name of the tool")
    service_url: str = Field(..., description="URL of the tool service")
    port: Optional[int] = Field(None, description="Port number of the tool service")
    description: Optional[str] = Field(None, description="Description of the tool")


class ToolListResponse(BaseModel):
    """Response from listing tools in a namespace"""
    
    tools: List[ToolSummary] = Field(..., description="List of tools in the namespace")


class FunctionParameter(BaseModel):
    """Parameter definition for a tool function"""
    
    type: str = Field(..., description="Parameter type (e.g., 'string', 'integer')")
    required: bool = Field(True, description="Whether the parameter is required")
    description: Optional[str] = Field(None, description="Parameter description")
    example: Optional[Any] = Field(None, description="Example value for the parameter")
    enum: Optional[List[Any]] = Field(
        default=None,
        description="Allowed values for the parameter (if enumerated)"
    )


class ToolFunction(BaseModel):
    """Definition of a tool function"""
    
    name: str = Field(..., description="Name of the function")
    description: Optional[str] = Field(None, description="Description of the function")
    full_description: Optional[str] = Field(None, description="Full docstring description")
    parameters: List[str] = Field(default_factory=list, description="List of parameter names")
    parameters_schema: Dict[str, FunctionParameter] = Field(
        default_factory=dict, description="Schema for parameters"
    )
    return_type: Optional[str] = Field(None, description="Return type of the function")
    example: Optional[Any] = Field(None, description="Example return value")


class ToolDetails(BaseModel):
    """Detailed information about a tool"""
    
    tool_name: str = Field(..., description="The name of the tool")
    service_url: str = Field(..., description="URL of the tool service")
    port: Optional[int] = Field(None, description="Port number of the tool service")
    functions: Dict[str, ToolFunction] = Field(
        default_factory=dict, description="Available functions of the tool"
    )


class TemplateSummary(BaseModel):
    """Summary information about a saved template"""

    template_name: str = Field(..., description="The name of the template")
    description: str = Field("", description="Description of the template")
    docstring: str = Field("", description="Full docstring for the template")
    tool: str = Field("", description="The tool this template invokes")
    method: str = Field("", description="The tool method this template invokes")
    category: str = Field("Other", description="Template category for grouping")
    input_schema: dict = Field(default_factory=dict, description="JSON schema for template input data")


class NamespaceInfo(BaseModel):
    """Namespace metadata returned by the registry."""

    namespace: str = Field(..., description="Unique namespace identifier")
    description: str = Field('', description="Purpose or notes")
    created_at: str = Field('', description="ISO-8601 creation timestamp")
    updated_at: str = Field('', description="ISO-8601 last-update timestamp")
    tool_count: int = Field(0, description="Number of tools currently assigned")
    metadata: dict = Field(default_factory=dict, description="Arbitrary key-value metadata")


class InvokeToolRequest(BaseModel):
    """Request model for invoking a tool"""
    
    parameters: Dict[str, Any] = Field(
        ..., description="Parameters to pass to the tool"
    )


class InvokeToolResponse(BaseModel):
    """Response model for tool invocation"""
    
    # Tool responses are dynamic, so we use a generic dict
    # The actual structure depends on the tool being invoked
    data: Dict[str, Any] = Field(..., description="Tool execution result")
