Part 1: Code Review & Bug Identification 
Scenario 
Your team member submitted this code for a Flask API endpoint that processes customer verification requests. The endpoint occasionally fails in production with inconsistent behavior, especially under load. 
Python 

```python 
from flask import Flask, request, jsonify 
from datetime import datetime 
import threading 
app = Flask(__name__) 
# Global cache for verifications 
verification_cache = [] 
request_count = 0 
class VerificationService: 
def __init__(self): 
 self.db_connection = self._get_db_connection() 
def _get_db_connection(self): 
 import psycopg2 
 return psycopg2.connect( 
 host="localhost", 
 database="verifications", 
 user="admin", 
 password="admin123" 
 ) 
def save(self, verification): 
 cursor = self.db_connection.cursor() 
 cursor.execute( 
 "INSERT INTO verifications (customer_id, status, verified_date) VALUES (%s, %s, %s)", 
 (verification['customer_id'], verification['status'], verification['verified_date']) 
 ) 
 self.db_connection.commit() 
def find_by_id(self, customer_id):
 cursor = self.db_connection.cursor() 
 cursor.execute( 
 f"SELECT * FROM verifications WHERE customer_id = '{customer_id}'"  ) 
 return cursor.fetchone() 
verification_service = VerificationService() 
def process_verification(customer_id, data=[]): 
"""Process verification and store results""" 
result = { 
 'customer_id': customer_id, 
 'status': 'VERIFIED', 
 'verified_date': datetime.now() 
} 
data.append(result) 
return data 
@app.route('/api/v1/verify', methods=['POST']) 
def verify_customer(): 
global request_count 
request_count += 1 
data = request.get_json() 
customer_id = data['customerId'] 
# Check cache first 
for verification in verification_cache: 
 if verification['customer_id'] == customer_id: 
 return jsonify({'result': verification}) 
# Process verification 
verification = { 
 'customer_id': customer_id, 
 'status': 'VERIFIED', 
 'verified_date': str(datetime.now()) 
} 
# Save to database 
verification_service.save(verification) 
# Add to cache 
verification_cache.append(verification)
return jsonify({'result': verification}) 
@app.route('/api/v1/verify/<customer_id>', methods=['GET']) def get_verification(customer_id): 
verification = verification_service.find_by_id(customer_id) 
if not verification: 
 raise Exception("Verification not found") 
return jsonify({'result': verification}) 
@app.route('/api/v1/stats', methods=['GET']) 
def get_stats(): 
return jsonify({ 
 'total_requests': request_count, 
 'cached_verifications': len(verification_cache) }) 
if __name__ == '__main__': 
app.run(host='0.0.0.0', port=5000, threaded=True) 
```
Your Tasks 
1. Identify 3 specific bugs or issues that could cause production problems. For each issue: 
a. Describe the exact problem 
b. Explain when/how it would manifest 
c. Rate severity (Critical/High/Medium/Low) 
2. Provide corrected code for the two (2) most critical issues you identified. Show the specific fixes. 
