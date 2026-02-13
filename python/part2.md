Part 2: Implement a Production-Ready Solution 
Scenario 
You need to implement a decorator-based rate limiter for API endpoints. Requirements: ● Limit requests per user per time window (e.g., 100 requests per minute) ● Thread-safe for concurrent requests (Flask with multiple workers) 
● Efficient memory usage (don't leak memory for inactive users) 
● Should return 429 status code when rate limit exceeded 
● Must handle high throughput (1000+ requests/second) 
● Clean up stale entries automatically 
Your Tasks 
1. Implement the rate limiter decorator: 
Python 
```python 
from functools import wraps 
from flask import request, jsonify 
from typing import Callable 
import time 
class RateLimiter: 
""" 
Rate limiter that can be used as a decorator for Flask routes 
""" 
def __init__(self, max_requests: int, window_seconds: int): 
 """
 Initialize rate limiter 
 Args: 
 max_requests: Maximum number of requests allowed in the time window 
 window_seconds: Time window in seconds 
 """ 
 # TODO: Implement initialization 
 pass 
def __call__(self, func: Callable) -> Callable: 
 """ 
 Decorator that enforces rate limiting 
 """ 
 @wraps(func) 
 def wrapper(*args, **kwargs): 
 # TODO: Implement rate limiting logic 
 # Get user ID from request 
 # Check if request is allowed 
 # If not allowed, return 429 with retry-after header  # If allowed, call the original function 
 pass 
 return wrapper 
def _cleanup_stale_entries(self): 
 """Remove entries older than the time window""" 
 # TODO: Implement cleanup to prevent memory leaks 
 pass 
# Usage example: 
rate_limiter = RateLimiter(max_requests=100, window_seconds=60) 
@app.route('/api/data') 
@rate_limiter 
def get_data(): 
return jsonify({'data': 'some data'}) 
``` 
Explain your approach: 
1. What data structure did you choose and why? 
2. How does your solution handle thread safety? (Consider: threading vs multiprocessing) 3. How do you prevent memory leaks for inactive users? 
4. What are the time and space complexity?
5. Would your solution work with multiple Flask workers (gunicorn with 4 workers)? If not, what would you need to change? 
3. Write a unit test that demonstrates correctness: 
Python 
```python 
import pytest 
import time 
from threading import Thread 
def test_rate_limiter(): 
"""Test that rate limiter correctly limits requests""" 
# TODO: Write test 
pass 
def test_rate_limiter_thread_safety(): 
"""Test that rate limiter works correctly with concurrent requests""" # TODO: Write test 
pass 
``` 
