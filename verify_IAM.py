import json
import sys
import re

def validate_IAM(data: dict) -> bool:

    #This function validates the JSON data if it is a IAM policy.
    #Raises ValueError if the data in not matching AWS IAM policy format.

    try:

        #PolicyDocument and PolicyName are both required, [\w+=,.@-]+ is the regex pattern od PolicyName
        #source: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html
        if ('PolicyDocument' not in data):
            raise ValueError('PolicyDocument not found in data')
        if ('PolicyName' not in data):
            raise ValueError('PolicyName not found in data')
        if re.match(r"[\w+=,.@-]+", data["PolicyName"]) is None:
            raise ValueError("Invalid PolicyName")

        #IAM supports the following Version element values: 2012-10-17, 2008-10-17
        #source: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html
        if ('Version' not in data['PolicyDocument']):
            raise ValueError('Version not found in data')
        if data["PolicyDocument"]["Version"] not in ["2012-10-17", "2008-10-17"]:
            raise ValueError("Invalid Version")

        #The Statement element is the main element for a policy. This element is required.
        #source: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_statement.html
        if ('Statement' not in data['PolicyDocument']):
            raise ValueError('Statement not found in data')
        
        #The Effect element is required and specifies whether the statement results in an allow or an explicit deny. Valid values for Effect are Allow and Deny. The Effect value is case sensitive.
        #source: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_effect.html
        if ('Effect' not in data['PolicyDocument']['Statement'][0]):
            raise ValueError('Effect not found in data')
        if data['PolicyDocument']['Statement'][0]['Effect'] != 'Allow' and data['PolicyDocument']['Statement'][0]['Effect'] != 'Deny':
            raise ValueError('Invalid Effect')
        
        #Statements must include either an Action or NotAction element.
        #source: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html
        if ('Action' not in data['PolicyDocument']['Statement'][0] and 'NotAction' not in data['PolicyDocument']['Statement'][0]):
            raise ValueError('Action or NotAction not found in data')

        # Statements must include either a Resource or a NotResource element.
        #source: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html
        if ('Resource' not in data['PolicyDocument']['Statement'][0] and 'NotResource' not in data['PolicyDocument']['Statement'][0]):
            raise ValueError('Resource or NotResource not found in data')

    except ValueError as e:
        print(e)
        return False

    return True

def verify_resource(data: dict) -> bool:
    
    #This function validates the JSON data if it is a IAM policy.
    #Returns True if the data is a valid IAM policy, if not returns False.
    
    if (data['PolicyDocument']['Statement'][0]['Resource'] == '*'):
        return False
    else:
        return True

def check(file: str) -> bool:
    #This function opens the file and then runs the two funtions above
    with open(file, 'r') as f:
        data = json.load(f)

    if validate_IAM(data) == True:
        return verify_resource(data)
    else:
        return True

if __name__ == '__main__':
    try:
        print(check(sys.argv[1]))
    except FileNotFoundError:
        print("Error while opening the file")
