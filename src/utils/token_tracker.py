"""
Token usage tracking utility for OpenAI API calls.
Tracks input and output tokens across the entire conversation.
"""

from typing import Dict, Any
import json


class TokenTracker:
    """Singleton class to track token usage across all API calls."""
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(TokenTracker, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self.reset()
            TokenTracker._initialized = True
    
    def reset(self):
        """Reset all token counters."""
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_tokens = 0
        self.call_count = 0
        self.call_history = []
    
    def add_tokens(self, input_tokens: int, output_tokens: int, model: str = "unknown"):
        """Add token usage from an API call."""
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_tokens += input_tokens + output_tokens
        self.call_count += 1
        
        call_info = {
            "call_number": self.call_count,
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens
        }
        self.call_history.append(call_info)
    
    def add_from_response(self, response: Any):
        """Extract and add token usage from an API response."""
        try:
            # Handle different response types
            if hasattr(response, 'response_metadata'):
                # LangChain response
                metadata = response.response_metadata
                usage = metadata.get('token_usage', {})
                model = metadata.get('model_name', 'unknown')
            elif hasattr(response, 'usage'):
                # Direct OpenAI response
                usage = response.usage.__dict__ if hasattr(response.usage, '__dict__') else response.usage
                model = getattr(response, 'model', 'unknown')
            else:
                # Try to extract from dict-like response
                usage = response.get('usage', {}) if isinstance(response, dict) else {}
                model = response.get('model', 'unknown') if isinstance(response, dict) else 'unknown'
            
            input_tokens = usage.get('prompt_tokens', 0)
            output_tokens = usage.get('completion_tokens', 0)
            
            if input_tokens > 0 or output_tokens > 0:
                self.add_tokens(input_tokens, output_tokens, model)
                return True
            return False
            
        except Exception as e:
            print(f"Error extracting token usage: {e}")
            return False
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of token usage."""
        return {
            "total_calls": self.call_count,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_tokens": self.total_tokens,
            "average_input_per_call": self.total_input_tokens / max(1, self.call_count),
            "average_output_per_call": self.total_output_tokens / max(1, self.call_count),
            "average_total_per_call": self.total_tokens / max(1, self.call_count)
        }
    
    def get_formatted_summary(self) -> str:
        """Get a formatted string summary of token usage."""
        summary = self.get_summary()
        return f"""
Token Usage Summary:
===================
Total API Calls: {summary['total_calls']}
Total Input Tokens: {summary['total_input_tokens']:,}
Total Output Tokens: {summary['total_output_tokens']:,}
Total Tokens: {summary['total_tokens']:,}
Average Input Tokens/Call: {summary['average_input_per_call']:.1f}
Average Output Tokens/Call: {summary['average_output_per_call']:.1f}
Average Total Tokens/Call: {summary['average_total_per_call']:.1f}
"""
    
    def get_detailed_history(self) -> str:
        """Get detailed call-by-call history."""
        if not self.call_history:
            return "No API calls recorded."
        
        history = ["Detailed Call History:", "=" * 50]
        for call in self.call_history:
            history.append(
                f"Call {call['call_number']}: {call['model']} - "
                f"Input: {call['input_tokens']}, Output: {call['output_tokens']}, "
                f"Total: {call['total_tokens']}"
            )
        return "\n".join(history)


# Global token tracker instance
token_tracker = TokenTracker()
