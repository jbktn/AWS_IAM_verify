import unittest
from verify_IAM import validate_IAM, verify_resource

class test_iam_role_policy_json(unittest.TestCase):   
    def test1_asterisk(self):
        data = {"PolicyName": "root","PolicyDocument": {"Version": "2012-10-17","Statement": [{"Sid": "IamListAccess","Effect": "Allow","Action": ["iam:ListRoles","iam:ListUsers"],"Resource": "*"}]}}
        self.assertFalse(verify_resource(data))

    def test2_no_asterisk(self):
        data = {"PolicyName": "root","PolicyDocument": {"Version": "2012-10-17","Statement": [{"Sid": "IamListAccess","Effect": "Allow","Action": ["iam:ListRoles","iam:ListUsers"],"Resource": "#"}]}}
        self.assertTrue(verify_resource(data))

    def test3_version_not_correct(self):
        data = {"PolicyName": "root","PolicyDocument": {"Version": "2012-10-19","Statement": [ {"Sid": "IamListAccess","Effect": "Allow","Action": ["iam:ListRoles","iam:ListUsers"],"Resource": "*"}]}}
        self.assertFalse(validate_IAM(data))

    def test4_nothing(self):
        data = {}
        self.assertFalse(validate_IAM(data))

    def test5_no_statement(self):
        data = {"PolicyName": "root","PolicyDocument": {"Version": "2012-10-17"}}
        self.assertFalse(validate_IAM(data))

    def test6_no_version(self):
        data = {"PolicyName": "root","PolicyDocument": {"Statement": [{"Sid": "IamListAccess","Effect": "Allow","Action": ["iam:ListRoles","iam:ListUsers"],"Resource": "*"}]}}
        self.assertFalse(validate_IAM(data))
    
    def test7_no_effect(self):
        data = {"PolicyName": "root","PolicyDocument": {"Version": "2012-10-17","Statement": [{"Sid": "IamListAccess","Action": ["iam:ListRoles","iam:ListUsers"],"Resource": "*"}]}}
        self.assertFalse(validate_IAM(data))

    def test8_effect_not_valid(self):
        data = {"PolicyName": "root","PolicyDocument": {"Version": "2012-10-17","Statement": [{"Sid": "IamListAccess","Effect": "a","Action": ["iam:ListRoles","iam:ListUsers"],"Resource": "*"}]}}
        self.assertFalse(validate_IAM(data))
    
    def test9_no_action_or_notaction(self):
        data = {"PolicyName": "root","PolicyDocument": {"Version": "2012-10-17","Statement": [{"Sid": "IamListAccess","Effect": "Allow","Resource": "*"}]}}
        self.assertFalse(validate_IAM(data))    

    def test10_no_resource_or_notresource(self):
        data = {"PolicyName": "root","PolicyDocument": {"Version": "2012-10-17","Statement": [{"Sid": "IamListAccess","Effect": "Allow","Action": ["iam:ListRoles","iam:ListUsers"]}]}}
        self.assertFalse(validate_IAM(data))


if __name__ == "__main__":
    unittest.main()