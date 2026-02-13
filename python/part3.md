Part 3: Real-World Scenario 
Situation 
You're debugging a production issue with your FastAPI microservice running in Kubernetes. The service processes verification requests and stores results in PostgreSQL. 
Symptoms: 
● Service becomes unresponsive after running for 6-8 hours 
● Memory usage steadily increases from 200MB to 2GB over this period ● CPU usage is normal (10-20%) 
● Database connections start getting refused 
● Pod gets OOMKilled and restarts 
● Application logs show no errors or exceptions 
● Happens consistently in production but not in local development
Your Tasks 
1. What are the top 3 most likely root causes? For each: ● Describe the specific issue 
● Explain how it matches the symptoms 
● What Python-specific behavior might cause this? 
2. What specific debugging steps would you take? 
● List at least 5 specific tools, commands, or techniques ● Explain what each would tell you 
● Include Python-specific debugging approaches 
3. Describe one time you debugged a challenging production issue: ● What was the problem? 
● What made it difficult to find? 
● How did you ultimately identify the root cause? 
● What was the fix?
