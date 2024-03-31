# To launch type: **make up_build**
## **/get_tokens**: 
 **Method**: *POST*  
### **Body example**:  **{"guid": "\<exampleGUID\>"}**  
## **Output**:  
### ***In case of failure***:  **{"error_message : "\<error_message_description\>"}**  
### ***In case of success***:  **{"access_token : "\<access_token\>", "refresh_token" : "\<refresh_token\>"}**  

## **/reissue**  
 **Method**: *POST*  
### **Body example**:  **{"refresh_token": "\<refresh_token\>"}**  
## **Output**:  
### ***In case of failure***:  **{"error_message : "\<error_message_description\>"}**  
### ***In case of success***:  **{"refresh_token" : "\<new_refresh_token\>"}**  

