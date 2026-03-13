# Demo Flow

1. Start client

java -cp client/src/main/java com.pv204.client.Main help

2. Add a secret

java -cp client/src/main/java com.pv204.client.Main add gmail mypassword

3. List secrets

java -cp client/src/main/java com.pv204.client.Main list

4. Retrieve secret

java -cp client/src/main/java com.pv204.client.Main get gmail

5. Change PIN

java -cp client/src/main/java com.pv204.client.Main change-pin 1234 5678