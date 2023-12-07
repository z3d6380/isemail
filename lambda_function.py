import json
from is_email import *

def lambda_handler(event, context):
    # Extract the email address from the event
    email_address = event['queryStringParameters']['email_address']

    # Validate the email address
    email_validity_code = is_email(email_address, True, True)
    
    # Get the literal name of the result code
    email_diagnosis = result_codes.get(email_validity_code, "Unknown result code")
    
    if email_validity_code == ISEMAIL_VALID:
        validation_result = "Success"
    elif email_validity_code < ISEMAIL_THRESHOLD:
        validation_result = "Warning"
    else:
        validation_result = "Error"

    # Return the result
    return {
        'statusCode': 200,
        'body': json.dumps({
            'email_validation_result': validation_result,
            'email_address': email_address,
            'email_validity_code': str(email_validity_code),
            'email_diagnosis': email_diagnosis
        })
    }
