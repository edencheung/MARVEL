"""
Rate limit handling utility for OpenAI API calls.
Provides retry logic with exponential backoff for handling rate limits.
"""

import time
import random
from functools import wraps
from typing import Any, Callable, Optional
import openai
from langchain_core.exceptions import LangChainException

def exponential_backoff_retry(
    max_retries: int = 10,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True
):
    """
    Decorator that implements exponential backoff retry logic for OpenAI rate limits.
    
    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        exponential_base: Base for exponential backoff
        jitter: Whether to add random jitter to delay
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except (openai.RateLimitError, openai.APITimeoutError) as e:
                    last_exception = e
                    if attempt == max_retries:
                        print(f"Max retries ({max_retries}) reached for {func.__name__}. Giving up.")
                        raise e
                    
                    # Calculate delay with exponential backoff
                    delay = min(base_delay * (exponential_base ** attempt), max_delay)
                    
                    # Add jitter to prevent thundering herd
                    if jitter:
                        delay *= (0.5 + random.random() * 0.5)
                    
                    print(f"Rate limit hit for {func.__name__}. Retrying in {delay:.2f} seconds (attempt {attempt + 1}/{max_retries + 1})")
                    time.sleep(delay)
                    
                except LangChainException as e:
                    # Check if it's a rate limit error wrapped by LangChain
                    if "rate limit" in str(e).lower() or "429" in str(e):
                        last_exception = e
                        if attempt == max_retries:
                            print(f"Max retries ({max_retries}) reached for {func.__name__}. Giving up.")
                            raise e
                        
                        delay = min(base_delay * (exponential_base ** attempt), max_delay)
                        if jitter:
                            delay *= (0.5 + random.random() * 0.5)
                        
                        print(f"LangChain rate limit hit for {func.__name__}. Retrying in {delay:.2f} seconds (attempt {attempt + 1}/{max_retries + 1})")
                        time.sleep(delay)
                    else:
                        # Not a rate limit error, re-raise immediately
                        raise e
                except Exception as e:
                    # Check if the error message contains rate limit indicators
                    error_str = str(e).lower()
                    if any(indicator in error_str for indicator in ["rate limit", "429", "too many requests"]):
                        last_exception = e
                        if attempt == max_retries:
                            print(f"Max retries ({max_retries}) reached for {func.__name__}. Giving up.")
                            raise e
                        
                        delay = min(base_delay * (exponential_base ** attempt), max_delay)
                        if jitter:
                            delay *= (0.5 + random.random() * 0.5)
                        
                        print(f"Rate limit detected in error message for {func.__name__}. Retrying in {delay:.2f} seconds (attempt {attempt + 1}/{max_retries + 1})")
                        time.sleep(delay)
                    else:
                        # Not a rate limit error, re-raise immediately
                        raise e
            
            # This should never be reached, but just in case
            raise last_exception
            
        return wrapper
    return decorator

def safe_openai_call(func: Callable, *args, **kwargs) -> Any:
    """
    Wrapper function for making safe OpenAI API calls with rate limit handling.
    """
    @exponential_backoff_retry()
    def _wrapped_call():
        return func(*args, **kwargs)
    
    return _wrapped_call()
