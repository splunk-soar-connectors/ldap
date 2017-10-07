# --
# File: ldap_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Json keys
LDAP_JSON_GROUP = "group"
LDAP_JSON_TOTAL_GROUPS = "total_groups"
LDAP_JSON_OU = "ou"
LDAP_JSON_ATTRIB_NAME = "attribute_name"
LDAP_JSON_ATTRIB_VALUE = "attribute_value"
LDAP_JSON_FORCE_SSL = "force_ssl"
LDAP_JSON_OS = "OS"
LDAP_JSON_STATE = "state"
LDAP_JSON_BAD_PWD_COUNT = "bad_password_count"
LDAP_JSON_PWD_LAST_SET = "password_last_set"
LDAP_JSON_LAST_LOGON = "last_logon"
LDAP_JSON_NEW_PASSWORD = "new_password"
LDAP_JSON_ATTRIBUTE = "attribute"
LDAP_JSON_TOTAL_USERS = "total_users"
LDAP_JSON_OBJECT_NAME = "object_name"
LDAP_JSON_OBJECT_CLASS = "object_class"
LDAP_JSON_ALL_USERS = "all_users"

# Status messages for success or failure
LDAP_SUCC_AD_USER_STATE_SAME = "User state same as required"
LDAP_SUCC_USER_STATE_CHANGED = "User state changed"
LDAP_SUCC_PASSWORD_CHANGE_STATE_SAME = "User 'change password at next logon' state same as required"
LDAP_SUCC_PASSWORD_STATE_CHANGED = "User 'change password at next logon' enforced"
LDAP_SUCC_OU_CHANGED = "OU changed successfully"
LDAP_SUCC_OU_NOT_CHANGED = "OU same as required, not changed"

LDAP_ERR_BASE_DN_FAILED = "Query for the Base DN failed"
LDAP_ERR_BASE_DN_NOT_FOUND = "Base DN not found"
LDAP_ERR_BIND_FAILED = "Bind to AD server failed"
LDAP_ERR_USER_DN_FAILED = "Search on AD for User DN failed"
LDAP_ERR_USER_GROUP_SEARCH_FAILED = "Search on AD for User group failed"
LDAP_ERR_USER_GROUP_SEARCH_RETURNED_EMPTY = "Search on AD for User group came back empty"
LDAP_ERR_USER_ACC_SEARCH_FAILED = "Search on AD for User Account status failed"
LDAP_ERR_USER_ACC_SEARCH_EMPTY = "Search on AD for User Account status came back empty"
LDAP_ERR_USER_STATE_MODIFICATION_FAILED = "Attempt to modify user state failed"
LDAP_ERR_PASSWORD_CHANGE_STATE_MODIFICATION_FAILED = "Attempt to enforce 'change password at next logon' failed"
LDAP_ERR_DN_FAILED = "Search on AD for {dn_type} failed"
LDAP_ERR_OU_MODIFICATION_FAILED = "OU Modification failed"
LDAP_ERR_MULTIPLE_DN_GIVE_PATH = "Multiple DNs found for {dn_type} '{name}', please specify full DN to avoid ambiguity"
LDAP_ERR_SYSTEM_ATTRIBUTE_MODIFICATION_FAILED = "Failed to modify attribute"
LDAP_ERR_SYSTEM_ATTRIBUTE_ADDITION_FAILED = "Failed to add attribute"
LDAP_ERR_SYSTEM_ATTRIBUTE_SEARCH = "Search for system attributes failed"
LDAP_ERR_SYSTEM_ATTRIBUTE_SEARCH_EMPTY = "Search for system attributes returned empty results"
LDAP_ERR_USER_ATTRIBUTE_SEARCH = "Search for user attributes failed"
LDAP_ERR_INITIALIZATION_FAILED = "Python-ldap initialization failed"
LDAP_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
LDAP_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
LDAP_SUCC_SYSTEM_ATTRIBUTE_MODIFICATION = "System attribute modified"
LDAP_SUCC_SYSTEM_ATTRIBUTES_QUERY = "System attributes queried"
LDAP_SUCC_USER_ATTRIBUTES_QUERY = "User attributes queried"
LDAP_ERR_USER_PASSWD_CHANGE_FAILED = "User password change failed"
LDAP_SUCC_USER_PASSWD_CHANGED = "User password changed"
LDAP_ERR_USER_PASSWD_CHANGE_NEXT_LOGON_FAILED = "User 'change password at next logon' enforcement failed"
LDAP_SUCC_USER_PASSWD_CHANGE_NEXT_LOGON_CHANGED = "User 'change password at next logon' enforced"
LDAP_ERR_USER_PASSWD_CHANGE_POLICY = "Possible password policy criteria not met"
LDAP_ERR_ACTION_NOT_SUPPORTED_OVER_UNSECURED = "The server might not support this action over a non-ssl connection"
LDAP_ERR_ATTRIB_NOT_FOUND = "Unable to get the current value of the attribute. Attribute possibly not present."
LDAP_MSG_ATTRIB_VALUE_SAME = "Attribute value same as required, not changed"
LDAP_ERR_INVALID_RESPONSE_SEARCH = "Got invalid response to a search query"

# Progress messages
LDAP_PROG_GOT_BASE_DN = "Got Base DN =  '{}'"
LDAP_PROG_LDAP_INITIALIZED = "Ldap module initialized"
LDAP_PROG_GOT_USER_BASE_DN = "Got User Base DN {}"
LDAP_PROG_DISABLING_USER = "Disabling user"
LDAP_PROG_ENABLING_USER = "Enabling user"
LDAP_PROG_USER_STATUS_SAME_AS_REQUIRED = "User state same as required"
LDAP_PROG_PASSWORD_CHANGE_STATUS_SAME_AS_REQUIRED = "User 'change password at next logon' state same as required"
LDAP_PROG_GOT_DN = "Got {dn_type} DN: {dn}"
LDAP_PROG_SSL_FAILE_TRYING_NON_SSL = "SSL connection failed, trying non-ssl"

LDAP_MSG_NON_SSL_NOT_ALLOWED = "Configuration does not allow to try non-ssl connection"
