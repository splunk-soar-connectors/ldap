# --
# File: ldap_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# THIS Connector imports
from ldap_consts import *

import ldap
from datetime import datetime, timedelta
from struct import unpack
import codecs
import re

# The bitmask for setting the user as disabled
ACC_DISABLED_CTRL_FLAG = 0x0002
ACC_DONT_EXPIRE_PASSWORD = 0x10000


class LdapConnector(BaseConnector):

    # actions supported by this script
    ACTION_ID_DISABLE_USER = "disable_user"
    ACTION_ID_ENABLE_USER = "enable_user"
    ACTION_ID_USER_GROUPS = "get_user_groups"
    ACTION_ID_CHANGE_SYSTEM_OU = "change_system_ou"
    ACTION_ID_SET_SYSTEM_ATTRIBUTE = "set_system_attribute"
    ACTION_ID_GET_SYSTEM_ATTRIBUTES = "get_system_attributes"
    ACTION_ID_GET_USER_ATTRIBUTES = "get_user_attributes"
    ACTION_ID_SET_PASSWORD = "set_password"
    ACTION_ID_RESET_PASSWORD = "reset_password"
    ACTION_ID_LIST_USERS = "get_users"

    def __init__(self):

        # Call the BaseConnectors init first
        super(LdapConnector, self).__init__()

        self.__ldap_conn = None
        self.__base_dn = None
        self.__using_ssl = False
        self.__domain_slash_reg = re.compile(r'.*[\\\/]', re.IGNORECASE)

    def _get_base_dn(self):

        self.__base_dn = None

        # Now search
        try:
            r_data = self.__ldap_conn.search_s("", ldap.SCOPE_BASE, "cn=*", ['defaultNamingContext'])  # pylint: disable=E1101
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, LDAP_ERR_BASE_DN_FAILED, e)

        # Parse the result
        if not r_data:
            return self.set_status(phantom.APP_ERROR, LDAP_ERR_BASE_DN_FAILED)

        try:
            self.debug_print("r_data", r_data)
            self.__base_dn = r_data[0][1]['defaultNamingContext'][0]
            self.debug_print("base_dn", self.__base_dn)
            if (self.__base_dn is None):
                return self.set_status(phantom.APP_ERROR, LDAP_ERR_BASE_DN_NOT_FOUND)
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, LDAP_ERR_BASE_DN_NOT_FOUND, e)

        return phantom.APP_SUCCESS

    def _get_dn(self, dn_type, search_filter, action_result):

        self.debug_print("search_filter", search_filter)

        # The attribute that we are interested in
        attr_list = ['dn']

        # Now search
        try:
            r_data = self.__ldap_conn.search_s(self.__base_dn, ldap.SCOPE_SUBTREE, search_filter, attr_list)  # pylint: disable=E1101
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, LDAP_ERR_DN_FAILED, e, dn_type=dn_type)
            return None

        action_result.add_debug_data(r_data)

        # Parse the result
        if not r_data:
            action_result.set_status(phantom.APP_ERROR, LDAP_ERR_DN_FAILED, dn_type=dn_type)
            return None

        try:
            self.debug_print("r_data", r_data)
            dn_list = [x[0] for x in r_data if x[0]]
            self.debug_print("DN", "{0} dn: {1}".format(dn_type, dn_list))
            if (dn_list is not None) and (len(dn_list) > 0):
                action_result.set_status(phantom.APP_SUCCESS)
                return dn_list
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, LDAP_ERR_DN_FAILED, e, dn_type=dn_type)
            return None

        action_result.set_status(phantom.APP_ERROR, LDAP_ERR_DN_FAILED, dn_type=dn_type)

        return None

    def _get_ou_dn(self, ou_name, action_result):

        # The search filter to query on the user name
        search_filter = '(&(|(objectClass=organizationalUnit)(objectClass=container))(name={}))'.format(ou_name)

        dn_list = self._get_dn('ou', search_filter, action_result)

        if (dn_list is None):
            return None

        if (len(dn_list) > 1):
            action_result.set_status(phantom.APP_ERROR, LDAP_ERR_MULTIPLE_DN_GIVE_PATH,
                    dn_type='OU', name=ou_name)
            return None

        return dn_list[0]

    def _get_machine_dn(self, machine_name, action_result):

        # The search filter to query on, uses the machine_name that was given,
        # We currently support multiple formats
        # name, dNSHostName which is fqdn and DN which is distinguishedName i.e. CN=..., DC=...
        name_filter = '|(name={0})(dNSHostName={0})(distinguishedName={0})'.format(machine_name)
        search_filter = '(&(objectCategory=computer)(objectClass=computer)({}))'.format(name_filter)

        dn_list = self._get_dn('machine name', search_filter, action_result)

        if (dn_list is None):
            return None

        if (len(dn_list) > 1):
            action_result.set_status(phantom.APP_ERROR, LDAP_ERR_MULTIPLE_DN_GIVE_PATH,
                    dn_type='machine', name=machine_name)
            return None

        return dn_list[0]

    def _parse_user_dn_response(self, r_data, action_result):

        # Parse the result
        if not r_data:
            action_result.set_status(phantom.APP_ERROR, "Invalid or empty response received. " + LDAP_ERR_USER_DN_FAILED)
            return None

        try:
            user_dns = [x[0] for x in r_data if x and x[0]]
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, "Unable to parse response. " + LDAP_ERR_USER_DN_FAILED, e)
            return None

        if (not user_dns):
            action_result.set_status(phantom.APP_ERROR, "The server returned an empty user list. " + LDAP_ERR_USER_DN_FAILED)
            return None

        if (len(user_dns) > 1):
            action_result.set_status(phantom.APP_ERROR, "More that one user matched the query. " + LDAP_ERR_USER_DN_FAILED)
            return None

        return user_dns[0]

    def _get_user_dn_with_attribute(self, attribute, user, action_result):

        user_filter = '{0}={1}'.format(attribute, user)
        search_filter = '(&(objectCategory=person)(objectClass=user)({}))'.format(user_filter)

        # print "Search Filter: " + search_filter

        # The attribute that we are interested in
        attr_list = ['dn']

        # Now search
        try:
            r_data = self.__ldap_conn.search_s(self.__base_dn, ldap.SCOPE_SUBTREE, search_filter, attr_list)  # pylint: disable=E1101
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_DN_FAILED, e)
            return None

        action_result.add_debug_data(r_data)

        # parse the user response
        return self._parse_user_dn_response(r_data, action_result)

    def _get_user_dn(self, user, param, action_result):

        attribute = param.get(LDAP_JSON_ATTRIBUTE)
        if (attribute):
            return self._get_user_dn_with_attribute(attribute, user, action_result)

        # The search filter to query on, uses the user that was given,
        # We currently support multiple formats
        # sAMAccountName which is name, userPrincipalName which is email
        # and DN which is distinguishedName i.e. CN=..., DC=...
        # Also support Domain\username, since that's the format that is ingested into artifacts in some cases
        # However, we strip the domain name before querying for it
        user = self.__domain_slash_reg.sub('', user)

        user_filter = '|(sAMAccountName={0})(userPrincipalName={0})(distinguishedName={0})'.format(user)
        search_filter = '(&(objectCategory=person)(objectClass=user)({}))'.format(user_filter)

        # print "Search Filter: " + search_filter

        # The attribute that we are interested in
        attr_list = ['dn']

        # Now search
        try:
            r_data = self.__ldap_conn.search_s(self.__base_dn, ldap.SCOPE_SUBTREE, search_filter, attr_list)  # pylint: disable=E1101
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_DN_FAILED, e)
            return None

        action_result.add_debug_data(r_data)

        # parse the user response
        return self._parse_user_dn_response(r_data, action_result)

    def _convert_ad_timestamp(self, timestamp):
        epoch_start = datetime(year=1601, month=1, day=1)
        seconds_since_epoch = timestamp / 10 ** 7
        return epoch_start + timedelta(seconds=seconds_since_epoch)

    def _parse_sid_bytes(self, bin_str):

        try:
            # sid_str = "0105 000000000005 15000000 681defe1 d1b72c16 11a27a93 83040000"
            # sid_str = "S-1-5-21-3790544232-372029393-2474287633-1155"
            c1 = unpack('B', bin_str[0:1])[0]
            LL1 = unpack('>Q', '\x00\x00' + bin_str[2:8])[0]
            L1 = unpack('<L', bin_str[8:12])[0]
            L2 = unpack('<L', bin_str[12:16])[0]
            L3 = unpack('<L', bin_str[16:20])[0]
            L4 = unpack('<L', bin_str[20:24])[0]
            L5 = unpack('<L', bin_str[24:28])[0]

            sid_str = "S-{0}-{1}-{2}-{3}-{4}-{5}-{6}".format(c1, LL1, L1, L2, L3, L4, L5)

            return [sid_str]
        except Exception as e:

            self.debug_print("Exception in In _parse_sid_bytes", e)

            return [""]

    def _get_user_attributes(self, param):

        # Connect
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        # create an action_result to represent this item
        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param.get(phantom.APP_JSON_USERNAME)

        user_base_dn = None
        # Query the server for user_base_dn
        user_base_dn = self._get_user_dn(username, param, action_result)
        if (user_base_dn is None):
            return action_result.get_status()

        self.save_progress(LDAP_PROG_GOT_USER_BASE_DN, user_base_dn)

        self.debug_print("Working on User: ", username + "@" + user_base_dn)

        # The attribute list to query
        try:
            r_data = self.__ldap_conn.search_s(user_base_dn, ldap.SCOPE_BASE, "cn=*")  # pylint: disable=E1101
        except Exception as e:
            self.debug_print(LDAP_ERR_USER_ATTRIBUTE_SEARCH)
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_GROUP_SEARCH_FAILED, e)

        action_result.add_debug_data(r_data)

        # Get the result
        if not r_data:
            self.debug_print(LDAP_ERR_USER_ATTRIBUTE_SEARCH)
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_GROUP_SEARCH_FAILED)

        # Can't take all the attributes as is in the json, some of them could be binary strings
        # which when inputted to json.loads throws an exception
        # Also use this loop to convert the values which are lists into ';' seperated strings.
        # That's the output ldp.exe spits out and it looks good
        attributes = dict()
        valid_keys = ["displayname", "distinguishedname", "lastlogoff", "logoncount", "memberof",
        "accountexpires", "badpasswordtime", "countrycode", "objectcategory", "objectclass",
        "objectguid", "objectsid", "primarygroupid", "userprincipalname",
        "whenchanged", "whencreated", "cn", "codepage", "dscorepropagationdata", "givenname", "instancetype",
        "name", "samaccountname", "samaccounttype", "sn", "usnchanged", "usncreated", "logonhours", "telephonenumber",
        "manager", "title", "company", "department", "mail", "streetaddress", "l", "st", "co", "postalcode", "postofficebox"]

        required_keys = ["useraccountcontrol", "badpwdcount", "pwdlastset", "lastlogon"]

        user_specified_fields = param.get('fields')
        if user_specified_fields == 'all':
            valid_keys = []
        elif user_specified_fields:
            valid_keys = [x.strip() for x in str(user_specified_fields).lower().split(',')]
            valid_keys.extend(required_keys)
        else:
            valid_keys.extend(required_keys)

        bin_string_keys = ['logonhours', 'objectsid', 'objectguid']

        try:

            for k, v in r_data[0][1].iteritems():
                k = k.lower()
                if (valid_keys and k not in valid_keys):
                    continue
                values = [self.create_binary_string(x).strip() if (k in bin_string_keys) else x for x in v]
                if (k == 'objectsid'):
                    values = self._parse_sid_bytes(x)
                attributes[k] = ";".join(x for x in values)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Failed to parse the response", e)

        self.debug_print("Attributes: {0}".format(attributes))
        action_result.add_data(attributes)
        # Create the summary
        try:
            if ((int(attributes['useraccountcontrol']) & ACC_DISABLED_CTRL_FLAG) > 0):
                action_result.update_summary({LDAP_JSON_STATE: 'Disabled'})
            else:
                action_result.update_summary({LDAP_JSON_STATE: 'Enabled'})
        except:
            action_result.update_summary({LDAP_JSON_STATE: 'Data missing'})

        action_result.update_summary({LDAP_JSON_BAD_PWD_COUNT: attributes.get('badpwdcount', 'Unknown')})
        time_int = int(attributes.get('pwdlastset', -1))

        if (time_int == -1):
            action_result.update_summary({LDAP_JSON_PWD_LAST_SET: 'Unknown'})
        elif (time_int == 0):
            action_result.update_summary({LDAP_JSON_PWD_LAST_SET: 'Never'})
        else:
            action_result.update_summary({
                LDAP_JSON_PWD_LAST_SET: self._convert_ad_timestamp(time_int).strftime("%m/%d/%Y %I:%M:%S %p UTC")})

        time_int = int(attributes.get('lastlogon', -1))

        if (time_int == -1):
            action_result.update_summary({LDAP_JSON_LAST_LOGON: 'Unknown'})
        elif (time_int == 0):
            action_result.update_summary({LDAP_JSON_LAST_LOGON: 'Never'})
        else:
            action_result.update_summary({
                LDAP_JSON_LAST_LOGON: self._convert_ad_timestamp(time_int).strftime("%m/%d/%Y %I:%M:%S %p UTC")})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_object_base_dn(self, obj_name, obj_class, action_result):

        search_filter = '(&(objectClass={0})(name={1}))'.format(obj_class, obj_name)

        # print "Search Filter: " + search_filter

        # The attribute that we are interested in
        attr_list = ['dn']

        # Now search
        try:
            r_data = self.__ldap_conn.search_s(self.__base_dn, ldap.SCOPE_SUBTREE, search_filter, attr_list)  # pylint: disable=E1101
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR,
                    "Failed to get Base DN for {0} of class: {1}. Can't proceed".format(obj_name, obj_class), e)
            return (phantom.APP_ERROR, None)

        action_result.add_debug_data(r_data)

        # Parse the result
        if not r_data:
            action_result.set_status(phantom.APP_ERROR,
                    "Got empty result while querying the Base DN for {0} of class: {1}. Can't proceed".format(obj_name, obj_class))
            return (phantom.APP_ERROR, None)

        try:
            self.debug_print("r_data", r_data)
            users_base_dn = r_data[0][0]
            self.debug_print("users_base_dn", users_base_dn)
            if (users_base_dn is None):
                action_result.set_status(phantom.APP_ERROR, "Base DN not found, seems like there is no object named '{0}' of class '{1}'".format(obj_name, obj_class))
                return (phantom.APP_ERROR, None)
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR,
                    "Error parsing result while querying for Base DN for {0} of class: {1}. Can't proceed".format(obj_name, obj_class), e)
            return (phantom.APP_ERROR, None)

        return (phantom.APP_SUCCESS, users_base_dn)

    def _get_groups_of_users(self, param):

        # Connect
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        # create an action_result to represent this item
        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param.get(phantom.APP_JSON_USERNAME)

        user_base_dn = None
        # Query the server for user_base_dn
        user_base_dn = self._get_user_dn(username, param, action_result)
        if (user_base_dn is None):
            return action_result.get_status()

        self.save_progress(LDAP_PROG_GOT_USER_BASE_DN, user_base_dn)

        self.debug_print("Working on User: ", username + "@" + user_base_dn)

        # The attribute list to query
        attr_list = ['memberOf']
        try:
            r_data = self.__ldap_conn.search_s(user_base_dn, ldap.SCOPE_BASE, "cn=*", attr_list)  # pylint: disable=E1101
        except Exception as e:
            self.debug_print(LDAP_ERR_USER_GROUP_SEARCH_FAILED)
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_GROUP_SEARCH_FAILED, e)

        action_result.add_debug_data(r_data)

        message = ''
        # Get the result
        if not r_data:
            self.debug_print(LDAP_ERR_USER_GROUP_SEARCH_FAILED)
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_GROUP_SEARCH_FAILED)

        try:
            memberof_array = r_data[0][1]['memberOf']
            self.debug_print("memberof_array", memberof_array)
            if (memberof_array is None):
                self.debug_print(LDAP_ERR_USER_GROUP_SEARCH_RETURNED_EMPTY)
                return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_GROUP_SEARCH_RETURNED_EMPTY)

            action_result.update_summary({LDAP_JSON_TOTAL_GROUPS: len(memberof_array)})

            message = 'Member of ({0}):\r\n'.format(len(memberof_array))
            for group in memberof_array:
                curr_data = action_result.add_data({})
                curr_data[LDAP_JSON_GROUP] = group
                message += '{0}\n'.format(group)
        except:
            self.debug_print(LDAP_ERR_USER_GROUP_SEARCH_FAILED)
            action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_GROUP_SEARCH_FAILED)

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _add_system_attribute(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        machine_name = param.get(phantom.APP_JSON_HOSTNAME)

        machine_base_dn = None

        # Query the server for machine_base_dn
        machine_base_dn = self._get_machine_dn(machine_name, action_result)
        if (phantom.is_fail(action_result.get_status())):
            return action_result.get_status()

        self.save_progress(LDAP_PROG_GOT_DN, dn_type='machine', dn=machine_base_dn)

        self.debug_print("machine_base_dn", machine_base_dn)

        attrib_name = param[LDAP_JSON_ATTRIB_NAME]

        attrib_value = param[LDAP_JSON_ATTRIB_VALUE]

        # The modification list
        add_list = [(attrib_name, attrib_value)]

        # Now run the modify command on the base_dn
        try:
            self.__ldap_conn.add_s(machine_base_dn, add_list)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_SYSTEM_ATTRIBUTE_ADDITION_FAILED, e)

        return phantom.APP_SUCCESS

    def _parse_hex_string(self, in_string):

        # First check if it is a hex string
        cont_hex_string = in_string.replace(' ', '')

        self.debug_print('cont_hex_string', cont_hex_string)

        try:
            int(cont_hex_string, 16)
        except ValueError:
            return in_string

        # Need to convert it to an escaped binary string,
        # First create a list of 2 chars hex value, each of which gets converted to a int
        # the chr of which is added to a string
        bin_str = ''.join([chr(int(cont_hex_string[i:i + 2], 16)) for i in range(0, len(cont_hex_string), 2)])

        # This would dump bin chars, so don't dump
        # self.debug_print('bin_str', bin_str)

        return bin_str

    def _handle_bool_string(self, in_string):

        try:
            if ((in_string.lower() == 'false') or (in_string.lower() == 'true')):
                return in_string.upper()
        except Exception as e:
            self.debug_print("In _handle_bool_string", e)

        return in_string

    def _set_system_attribute(self, param):

        # Connect
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))
        machine_name = param[phantom.APP_JSON_HOSTNAME]

        machine_base_dn = None

        # Query the server for machine_base_dn
        machine_base_dn = self._get_machine_dn(machine_name, action_result)
        if (phantom.is_fail(action_result.get_status())):
            return action_result.get_status()

        self.save_progress(LDAP_PROG_GOT_DN, dn_type='machine', dn=machine_base_dn)

        self.debug_print("machine_base_dn", machine_base_dn)

        attrib_name = param[LDAP_JSON_ATTRIB_NAME]

        attrib_value = param[LDAP_JSON_ATTRIB_VALUE]

        # We could get the value as a hex string, that's what is expected for GUID like attributes
        attrib_value = self._parse_hex_string(attrib_value)

        attrib_value = self._handle_bool_string(attrib_value)

        # get the current value of the variable
        # The attribute list to query
        attr_list = [str(attrib_name)]
        curr_attrib_value = ''
        try:
            r_data = self.__ldap_conn.search_s(machine_base_dn, ldap.SCOPE_SUBTREE, "cn=*", attr_list)  # pylint: disable=E1101
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_ATTRIB_NOT_FOUND, e)

        action_result.add_debug_data(r_data)

        if not r_data:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_INVALID_RESPONSE_SEARCH)

        try:
            value_dict = r_data[0][1]
        except:
            # print "useAccountControl: 0x%x" % curr_attrib_value
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_INVALID_RESPONSE_SEARCH)

        new_dict = value_dict
        # Check if the key that was queried for is present in the result
        if (attrib_name not in value_dict):
            # Create a new dict with lowercase keys
            new_dict = {k.lower(): value_dict[k] for k, v in value_dict.iteritems()}

        if (attrib_name not in new_dict):
            # Could not find the key in the result, even after lowercasing all the keys
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_ATTRIB_NOT_FOUND)

        try:
            curr_attrib_value = str(new_dict[attrib_name][0])
        except:
            # print "useAccountControl: 0x%x" % curr_attrib_value
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_ATTRIB_NOT_FOUND)

        if (str(curr_attrib_value) == str(attrib_value)):
            return action_result.set_status(phantom.APP_SUCCESS, LDAP_MSG_ATTRIB_VALUE_SAME)

        # The modification list
        mod_list = [(ldap.MOD_REPLACE, str(attrib_name), str(attrib_value))]  # pylint: disable=E1101

        # Now run the modify command on the base_dn
        try:
            self.__ldap_conn.modify_s(machine_base_dn, mod_list)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_SYSTEM_ATTRIBUTE_MODIFICATION_FAILED, e)

        return action_result.set_status(phantom.APP_SUCCESS, LDAP_SUCC_SYSTEM_ATTRIBUTE_MODIFICATION)

    def is_binary_string(self, bytes):
        textchars = bytearray([7, 8, 9, 10, 12, 13, 27]) + bytearray(range(0x20, 0x100))
        return bool(bytes.translate(None, textchars))

    def create_binary_string(self, in_str):
        return "".join("%02x " % ord(c) for c in in_str)

    def _get_system_attributes(self, param):

        # Connect
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))
        machine_name = param[phantom.APP_JSON_HOSTNAME]

        machine_base_dn = None

        # Query the server for machine_base_dn
        machine_base_dn = self._get_machine_dn(machine_name, action_result)
        if (phantom.is_fail(action_result.get_status())):
            return action_result.get_status()

        self.save_progress(LDAP_PROG_GOT_DN, dn_type='machine', dn=machine_base_dn)

        self.debug_print("machine_base_dn", machine_base_dn)

        # The attribute list to query
        try:
            r_data = self.__ldap_conn.search_s(machine_base_dn, ldap.SCOPE_SUBTREE)  # pylint: disable=E1101
        except Exception as e:
            self.debug_print(LDAP_ERR_SYSTEM_ATTRIBUTE_SEARCH)
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_SYSTEM_ATTRIBUTE_SEARCH, e)

        action_result.add_debug_data(r_data)

        if not r_data:
            self.debug_print(LDAP_ERR_SYSTEM_ATTRIBUTE_SEARCH_EMPTY)
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_SYSTEM_ATTRIBUTE_SEARCH_EMPTY)

        # Can't take all the attributes as is in the json, some of them could be binary strings
        # which when inputted to json.loads throws an exception
        # Also use this loop to convert the values which are lists into ';' seperated strings.
        # That's the output ldp.exe spits out and it looks good
        attributes = dict()
        valid_keys = ["name", "dnshostname", "distinguishedname", "objectcategory", "objectclass", "objectguid", "countrycode",
        "lastlogoff", "lastlogon", "lastlogontimestamp", "localpolicyflags", "logoncount", "netbootguid", "netbootmirrordatafile",
        "objectsid", "primarygroupid", "displayname", "cn", "pwdlastset", "samaccountname", "samaccounttype", "accountexpires",
        "badpasswordtime", "badpwdcount", "codepage", "dscorepropagationdata", "instancetype", "iscriticalsystemobject", "ms-ds-creatorsid",
        "serviceprincipalname", "usnchanged", "usncreated", "useraccountcontrol", "whenchanged", "whencreated"]

        user_specified_fields = param.get('fields')

        required_keys = ["operatingsystem", "operatingsystemversion", "operatingsystemservicepack"]

        if user_specified_fields == 'all':
            valid_keys = []
        elif user_specified_fields:
            valid_keys = [x.strip() for x in str(user_specified_fields).lower().split(',')]
            valid_keys.extend(required_keys)
        else:
            valid_keys.extend(required_keys)

        try:
            for k, v in r_data[0][1].iteritems():
                k = k.lower()
                if (valid_keys and k not in valid_keys):
                    continue
                values = []
                for item in v:
                    if self.is_binary_string(item):
                        values.append(self.create_binary_string(item).strip())
                    else:
                        try:
                            values.append(codecs.encode(item, 'utf8', 'strict'))
                        except:
                            values.append(self.create_binary_string(item).strip())
                attributes[k] = ";".join(x for x in values)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse reply for system atrribute search", e)

        self.debug_print("Attributes", attributes)
        action_result.add_data(attributes)
        if ('operatingsystem' in attributes):
            os_string = '{0}'.format(attributes['operatingsystem'])
            if ('operatingsystemversion' in attributes):
                os_string += ' [{0}]'.format(attributes['operatingsystemversion'])
            if ('operatingsystemservicepack' in attributes):
                os_string += ' {0}'.format(attributes['operatingsystemservicepack'])
            action_result.update_summary({LDAP_JSON_OS: os_string})

        action_result.set_extra_data_size(0)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _change_system_ou(self, param):

        # Connect
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))
        machine_name = param[phantom.APP_JSON_HOSTNAME]

        machine_base_dn = None

        # Query the server for machine_base_dn
        machine_base_dn = self._get_machine_dn(machine_name, action_result)
        if (phantom.is_fail(action_result.get_status())):
            return action_result.get_status()

        self.save_progress(LDAP_PROG_GOT_DN, dn_type='machine', dn=machine_base_dn)

        self.debug_print("machine_base_dn", machine_base_dn)

        ou_name = param[LDAP_JSON_OU]

        ou_base_dn = ou_name

        # See if the name supplied is a dn name or not
        if (ou_name.lower().find('ou=') == -1):
            ou_base_dn = self._get_ou_dn(ou_name, action_result)
            if (phantom.is_fail(action_result.get_status())):
                return action_result.get_status()

        self.save_progress(LDAP_PROG_GOT_DN, dn_type='ou', dn=ou_base_dn)

        self.debug_print("ou_base_dn:", ou_base_dn)

        # create the newrdn from the machine_base_dn
        newrdn = machine_base_dn[:machine_base_dn.find(',')]

        self.debug_print("newrdn", newrdn)

        # Now check if the ou needs to be changed or not
        if (newrdn + ',' + ou_base_dn == machine_base_dn):
            return action_result.set_status(phantom.APP_SUCCESS, LDAP_SUCC_OU_NOT_CHANGED)

        # Now run the modify command on the machine_base_dn
        try:
            self.__ldap_conn.rename_s(dn=machine_base_dn, newrdn=newrdn, newsuperior=ou_base_dn, delold=1)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_OU_MODIFICATION_FAILED, e)

        return action_result.set_status(phantom.APP_SUCCESS, LDAP_SUCC_OU_CHANGED)

    def _set_password(self, param):

        # Connect
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        safe_params = dict(param)
        safe_params.pop('new_password')
        action_result = self.add_action_result(ActionResult(safe_params))
        username = param.get(phantom.APP_JSON_USERNAME)
        new_passwd = param.get(LDAP_JSON_NEW_PASSWORD)

        user_base_dn = None
        # Query the server for user_base_dn
        user_base_dn = self._get_user_dn(username, param, action_result)
        if (user_base_dn is None):
            return action_result.get_status()

        self.save_progress(LDAP_PROG_GOT_USER_BASE_DN, user_base_dn)

        self.debug_print("Working on User: ", username + "@" + user_base_dn)

        password_value = ('"{0}"'.format(new_passwd)).encode("utf-16-le")

        # The modification list
        mod_list = [((ldap.MOD_REPLACE, 'unicodePwd', [password_value]))]  # pylint: disable=E1101

        try:
            self.__ldap_conn.modify_s(user_base_dn, mod_list)
        except ldap.UNWILLING_TO_PERFORM as e:  # pylint: disable=E1101
            action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_PASSWD_CHANGE_FAILED, e)
            action_result.append_to_message("\n{0}".format(LDAP_ERR_USER_PASSWD_CHANGE_POLICY))
            if (not self.__using_ssl):
                action_result.append_to_message("\n{0}".format(LDAP_ERR_ACTION_NOT_SUPPORTED_OVER_UNSECURED))
            return action_result.get_status()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_PASSWD_CHANGE_FAILED, e)

        return action_result.set_status(phantom.APP_SUCCESS, LDAP_SUCC_USER_PASSWD_CHANGED)

    def _reset_password(self, param):

        # Connect
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))
        username = param[phantom.APP_JSON_USERNAME]

        user_base_dn = None
        # Query the server for user_base_dn
        user_base_dn = self._get_user_dn(username, param, action_result)
        if (user_base_dn is None):
            return action_result.get_status()

        self.save_progress(LDAP_PROG_GOT_USER_BASE_DN, user_base_dn)

        self.debug_print("Working on User: ", username + "@" + user_base_dn)

        self.save_progress("Getting user account properties")

        # The attribute list to query
        attr_list = ['userAccountControl']
        curr_acc_ctrl = 0
        try:
            r_data = self.__ldap_conn.search_s(user_base_dn, ldap.SCOPE_BASE, "cn=*", attr_list)  # pylint: disable=E1101
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_ACC_SEARCH_FAILED, e)

        action_result.add_debug_data(r_data)

        if not r_data:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_ACC_SEARCH_FAILED)

        try:
            curr_acc_ctrl = int(r_data[0][1]['userAccountControl'][0])
        except:
            # print "useAccountControl: 0x%x" % curr_acc_ctrl
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_ACC_SEARCH_EMPTY)

        if ((curr_acc_ctrl & ACC_DONT_EXPIRE_PASSWORD) > 0):
            return action_result.set_status(phantom.APP_ERROR, "Account has 'Dont Expire Password' property set, cannot set the password to change for next logon.")

        # The attribute list to query
        attr_list = ['pwdLastSet']
        curr_pwd_set = 0
        try:
            r_data = self.__ldap_conn.search_s(user_base_dn, ldap.SCOPE_BASE, "cn=*", attr_list)  # pylint: disable=E1101
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_ACC_SEARCH_FAILED, e)

        action_result.add_debug_data(r_data)

        # Get the result
        if not r_data:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_ACC_SEARCH_FAILED)

        try:
            curr_pwd_set = int(r_data[0][1]['pwdLastSet'][0])
        except:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_ACC_SEARCH_EMPTY)

        if (curr_pwd_set == 0):
            self.save_progress(LDAP_PROG_PASSWORD_CHANGE_STATUS_SAME_AS_REQUIRED, username)
            return action_result.set_status(phantom.APP_SUCCESS, LDAP_SUCC_PASSWORD_CHANGE_STATE_SAME)

        # The modification list
        mod_list = [(ldap.MOD_REPLACE, "pwdLastSet", str(0))]  # pylint: disable=E1101

        # Now run the modify command on the user_base_dn
        try:
            self.__ldap_conn.modify_s(user_base_dn, mod_list)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_PASSWD_CHANGE_NEXT_LOGON_FAILED, e)

        return action_result.set_status(phantom.APP_SUCCESS, LDAP_SUCC_USER_PASSWD_CHANGE_NEXT_LOGON_CHANGED)

    def _change_user_state(self, param):

        # Connect
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))
        username = param[phantom.APP_JSON_USERNAME]

        user_base_dn = None
        # Query the server for user_base_dn
        user_base_dn = self._get_user_dn(username, param, action_result)
        if (user_base_dn is None):
            return action_result.get_status()

        self.save_progress(LDAP_PROG_GOT_USER_BASE_DN, user_base_dn)

        self.debug_print("Working on User: ", username + "@" + user_base_dn)

        # The attribute list to query
        attr_list = ['userAccountControl']
        curr_acc_ctrl = 0
        mod_acc_ctrl = 0
        try:
            r_data = self.__ldap_conn.search_s(user_base_dn, ldap.SCOPE_BASE, "cn=*", attr_list)  # pylint: disable=E1101
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_ACC_SEARCH_FAILED, e)

        action_result.add_debug_data(r_data)

        # Get the result
        if not r_data:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_ACC_SEARCH_FAILED)

        try:
            curr_acc_ctrl = int(r_data[0][1]['userAccountControl'][0])
        except:
            # print "useAccountControl: 0x%x" % curr_acc_ctrl
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_ACC_SEARCH_EMPTY)

        action = self.get_action_identifier()
        if (action == self.ACTION_ID_DISABLE_USER) and ((curr_acc_ctrl & ACC_DISABLED_CTRL_FLAG) == 0):
            self.save_progress(LDAP_PROG_DISABLING_USER)

            # Set the resultant account control
            mod_acc_ctrl = curr_acc_ctrl | ACC_DISABLED_CTRL_FLAG

        elif (action == self.ACTION_ID_ENABLE_USER) and ((curr_acc_ctrl & ACC_DISABLED_CTRL_FLAG) != 0):
            self.save_progress(LDAP_PROG_ENABLING_USER)

            # Set the resultant account control
            mod_acc_ctrl = curr_acc_ctrl & ~(ACC_DISABLED_CTRL_FLAG)
        else:
            self.save_progress(LDAP_PROG_USER_STATUS_SAME_AS_REQUIRED, username)
            return action_result.set_status(phantom.APP_SUCCESS, LDAP_SUCC_AD_USER_STATE_SAME)

            # print "Set the userAccountControl to 0x%x" % (mod_acc_ctrl)

        # The modification list
        mod_list = [(ldap.MOD_REPLACE, "userAccountControl", str(mod_acc_ctrl))]  # pylint: disable=E1101

        # print mod_list

        # Now run the modify command on the user_base_dn
        try:
            self.__ldap_conn.modify_s(user_base_dn, mod_list)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, LDAP_ERR_USER_STATE_MODIFICATION_FAILED, e)

        return action_result.set_status(phantom.APP_SUCCESS, LDAP_SUCC_USER_STATE_CHANGED)

    def _connect_to_server(self, ldap_url, config):

        # Get the server
        ldap_server = config[phantom.APP_JSON_SERVER]

        # Intialize, the documentation is not that clear if the initialize
        # function will throw an exception or not, handling it
        try:
            self.__ldap_conn = ldap.initialize(ldap_url)  # pylint: disable=E1101
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, LDAP_ERR_INITIALIZATION_FAILED, e)

        # handle None return, the docs are not clear what happens in case of failure
        # supposedly the call will always return an object, since that's all
        # it does, create an object, no communication is actually carried out
        # with the ldap server
        if (self.__ldap_conn is None):
            return self.set_status(phantom.APP_ERROR, LDAP_ERR_INITIALIZATION_FAILED, e)

        # set few options, required
        self.__ldap_conn.set_option(ldap.OPT_REFERRALS, 0)  # pylint: disable=E1101

        self.save_progress(LDAP_PROG_LDAP_INITIALIZED)

        # Get the base dn, we don't need to be logged into the server to do
        # this query
        status = self._get_base_dn()
        if (phantom.is_fail(status)):
            # _get_base_dn must have set the status
            return status

        self.save_progress(LDAP_PROG_GOT_BASE_DN, self.__base_dn)

        # Get the username, we might have to modify the format a bit
        username = config[phantom.APP_JSON_USERNAME]

        # We could prefex the username with the domain name, but not too sure
        # how this will pan out, so for now keeping it as is. In case login
        # fails, the asset config will need to specify the username as
        # '<domain>/<username>'
        username = username.replace('/', '\\')

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, ldap_server)

        # Try binding to the server now
        try:
            self.__ldap_conn.simple_bind_s(username, config[phantom.APP_JSON_PASSWORD])
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, LDAP_ERR_BIND_FAILED, e)

        return phantom.APP_SUCCESS

    def _connect(self):

        config = self.get_config()

        # Set the ldap option to ignore the ca cert validation
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)  # pylint: disable=E1101

        # The server
        ldap_server = config[phantom.APP_JSON_SERVER]

        # First try with ssl
        self.__using_ssl = True
        ldap_url = 'ldaps://{}'.format(ldap_server)
        ret_val = self._connect_to_server(ldap_url, config)

        # Force SSL?
        force_ssl = bool(config[LDAP_JSON_FORCE_SSL])

        if (phantom.is_fail(ret_val)):
            self.__using_ssl = False
            if (not force_ssl):
                # Try with non ssl
                self.save_progress(LDAP_PROG_SSL_FAILE_TRYING_NON_SSL)
                ldap_url = 'ldap://{}'.format(ldap_server)
                ret_val = self._connect_to_server(ldap_url, config)
            else:
                self.append_to_message(LDAP_MSG_NON_SSL_NOT_ALLOWED)

        if (phantom.is_fail(ret_val)):
            return self.get_status()

        # send success, required else handle_action will not get called
        return phantom.APP_SUCCESS

    def _list_users(self, param):

        # Connect
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))
        action_result.update_summary({LDAP_JSON_TOTAL_USERS: 0})

        all_users = param[LDAP_JSON_ALL_USERS]

        if (all_users):
            dn_to_query = self.__base_dn
            search_filter = '(&(objectClass=User)(mail=*))'
        else:
            obj_name = param.get(LDAP_JSON_OBJECT_NAME)
            obj_class = param.get(LDAP_JSON_OBJECT_CLASS)

            if (not obj_name):
                return action_result.set_status(phantom.APP_ERROR,
                        "Parameter {0} not specified, it is required when all_users is set to False".format(LDAP_JSON_OBJECT_NAME))

            if (not obj_class):
                return action_result.set_status(phantom.APP_ERROR,
                        "Parameter {0} not specified, it is required when all_users is set to False".format(LDAP_JSON_OBJECT_CLASS))

            ret_val, dn_to_query = self._get_object_base_dn(obj_name, obj_class, action_result)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            # users are memberOf groups, not subclasses of groups, so if obj_class == group we need to add
            # memberOf=group_base_dn as a search filter and reset dn_to_query back to __base_dn
            if obj_class == 'group':
                group_base_dn = dn_to_query
                search_filter = '(&(objectClass=User)(mail=*)(memberOf={}))'.format(group_base_dn)
                dn_to_query = self.__base_dn
            # otherwise nothing is added to the search filter and the new dn_to_query is used as the base_dn
            else:
                search_filter = '(&(objectClass=User)(mail=*))'

        # The attribute that we are interested in
        attr_list = ['mail', 'displayname', 'samaccountname']

        # Now search
        try:
            r_data = self.__ldap_conn.search_s(dn_to_query, ldap.SCOPE_SUBTREE, search_filter, attr_list)  # pylint: disable=E1101
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Failed to get Users", e)

        action_result.add_debug_data(r_data)

        # Parse the result
        if not r_data:
            return self.set_status(phantom.APP_SUCCESS, "No Users found with email addresses")

        self.debug_print("r_data", r_data)

        for user_info in r_data:

            if (not user_info):
                continue

            if (len(user_info) != 2):
                continue

            user_dn = user_info[0]

            if (not user_dn):
                continue

            user_info = user_info[1]
            if (not user_info):
                continue

            user = action_result.add_data({'dn': user_dn})

            user['emails'] = user_info.get('mail', [])
            user['displayname'] = user_info.get('displayName', [])[0]
            user['samaccountname'] = user_info.get('sAMAccountName', [])[0]

        action_result.update_summary({LDAP_JSON_TOTAL_USERS: action_result.get_data_size()})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _test_asset_connectivity(self, param):

        if (phantom.is_fail(self._connect())):
            self.debug_print("connect failed")
            self.save_progress(LDAP_ERR_CONNECTIVITY_TEST)
            return self.append_to_message(LDAP_ERR_CONNECTIVITY_TEST)

        self.debug_print("connect passed")
        return self.set_status_save_progress(phantom.APP_SUCCESS, LDAP_SUCC_CONNECTIVITY_TEST)

    def handle_action(self, param):
        """"""
        action = self.get_action_identifier()

        # Process it
        if (action == self.ACTION_ID_USER_GROUPS):
            self._get_groups_of_users(param)
        elif (action == self.ACTION_ID_DISABLE_USER) or (action == self.ACTION_ID_ENABLE_USER):
            self._change_user_state(param)
        elif (action == self.ACTION_ID_CHANGE_SYSTEM_OU):
            self._change_system_ou(param)
        elif (action == self.ACTION_ID_SET_SYSTEM_ATTRIBUTE):
            self._set_system_attribute(param)
        elif (action == self.ACTION_ID_GET_SYSTEM_ATTRIBUTES):
            self._get_system_attributes(param)
        elif (action == self.ACTION_ID_GET_USER_ATTRIBUTES):
            self._get_user_attributes(param)
        elif (action == self.ACTION_ID_SET_PASSWORD):
            self._set_password(param)
        elif (action == self.ACTION_ID_RESET_PASSWORD):
            self._reset_password(param)
        elif (action == self.ACTION_ID_LIST_USERS):
            self._list_users(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            self._test_asset_connectivity(param)

        return self.get_status()

    def finalize(self):

        if (self.__ldap_conn is not None):
            # Unbind
            self.__ldap_conn.unbind_s()
            self.__ldap_conn = None

    def handle_exception(self, exception):
        """
        """

        # exception occured
        if (self.__ldap_conn is not None):
            # Unbind
            self.__ldap_conn.unbind_s()
            self.__ldap_conn = None

if __name__ == '__main__':

    import sys
    import simplejson as json
    import pudb
    pudb.set_trace()

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        connector = LdapConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print ret_val

    exit(0)
