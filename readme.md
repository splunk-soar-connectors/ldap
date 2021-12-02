[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2020 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Setting up the Environment

-   Login to the LDAP Server using Remote Desktop Connection.

-   Using the LDAP Server (Remote Desktop), create a new user or login with the existing user.

-   By default, the new user is a member of "Domain Users".

-   For accessing the "Member Of " property of the user follow the below steps:

      

    -   Navigate to the user for which you want to access the "Member Of " property.
    -   Now, right-click on the user and select the "Properties".
    -   In Properties, select the "Member Of " option.
    -   Now, you can add or remove the groups based on your requirements.

-   To run any action, you should have Remote Access Rights that need to be updated by changing the
    remote settings in system properties.

-   For acquiring Remote Access Rights, the user should follow the below steps:

      

    -   Navigate to the Control Panel from the Start Menu.
    -   Navigate to the Advanced System Settings which can be found under System Properties.
    -   Move to the Remote Tab section to select or add users.
    -   After adding them, you will receive Remote Desktop Access Rights which can be verified by
        accessing the "Member Of " property of the user.

-   You can check the test connectivity and run actions that do not update the schema definition of
    the application.

-   For running actions such as "set system attribute" which updates the LDAP database the user
    should be a member of "Organizational Manager" and "Schema Admins" which can be added by
    altering the "Member Of " property of the user.

## LDAP Ports Requirements (Based on Standard Guidelines of [IANA ORG](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) )

-   LDAP(service) TCP(transport protocol) - 389
-   LDAP(service) UDP(transport protocol) - 389
-   LDAP(service) TCP(transport protocol) over TLS/SSL (was sldap) - 636
-   LDAP(service) UDP(transport protocol) over TLS/SSL (was sldap) - 636

<span id="changepagesize"></span>

## Steps to Change Page Size

-   Login to the LDAP Server using Remote Desktop Connection.
-   Navigate to the "Start" menu. Then, click or tap the "Run" search result. In the text box, enter
    "ntdsutil".
-   Now, in the Ntdsutil.exe command prompt, type "LDAP policies" and press "Enter".
-   In the LDAP policy command prompt, type "connections" and press "Enter".
-   In the Server Connection command prompt, enter the "DNS Name of the server" which you want to
    connect with.
-   Now, in the Server Connection command prompt, enter "q" to return to the previous menu.
-   In the LDAP policy command prompt, type "Set MaxPageSize to x". For example, "Set MaxPageSize to
    8".
-   To save the changes, type "Commit Changes" and press "Enter".
-   When you finish, type "q" and then press "Enter".

**Note:** Here " " are used to denote keywords. They should not be entered with the text. <span
id="viewpagesize"></span>

## Steps to View Page Size

-   Login to the LDAP Server using Remote Desktop Connection.
-   Navigate to the "Start" menu. Then, click or tap the "Run" search result. In the text box, enter
    "ntdsutil".
-   Now, in the Ntdsutil.exe command prompt, type "LDAP policies" and then press "Enter".
-   In the LDAP policy command prompt, type "connections" and then press "Enter".
-   In the Server Connection command prompt, enter the "DNS Name of the server" which you want to
    connect with.
-   Now, in the Server Connection command prompt, enter "q" to return to the previous menu.
-   In the LDAP policy command prompt, type "Show Values".

**Note:** Here " " are used to denote keywords. They should not be entered with the text.

## Asset Configuration Parameters

The asset configuration parameters affect "Test Connectivity" and all the other actions of the
application. Below are the explanation and usage of all those parameters.

-   **Server IP/Hostname -** The user can provide the LDAP server's IP address or hostname for
    establishing the connection. The application supports the following formats as input for
    hostname:
    -   DNS hostname (e.g. Win10Entx64.corp.contoso.com)
    -   Distinguished name format (e.g. CN=WIN10ENTX64,CN=Computers,DC=corp,DC=contoso,DC=com)
-   **Administrator username -** This parameter states the username required for authentication.
    This authentication ensures that User A only has access to the information they need and can’t
    see the sensitive information of User B unless User A has Administrator privileges.
-   **Administrator password -** This parameter states the password required for authentication. The
    credentials entered are sent to the LDAP server and compared with the user's details stored on
    the LDAP server.
-   **Force use of SSL -** This parameter states whether to forcefully use SSL to establish a
    connection with the LDAP server. If not provided, the app will first try to connect to the
    server using SSL. If a secure connection cannot be made, then a non-SSL connection will be
    tried, if the config allows.

## LDAP Action Parameters

-   Test Connectivity

      

    -   This action will test the connectivity of the Phantom server to the LDAP server by logging
        into the device using the provided asset configuration parameters.
    -   The action validates the provided asset configuration parameters. Based on the response from
        the LDAP Server, an appropriate success or failure message will be displayed when the action
        gets executed.

      

-   Disable User

      

    -   This action disables the specified user.

          
          

    -   **<u>Action Parameters</u>** ​

        1.  **Username**
            -   This parameter specifies the username to disable. It is a mandatory action
                parameter.
            -   **Examples**
                -   Simple user name format, for example, test_user ( *sAMAccountName* in AD
                    nomenclature)
                -   Email address, for example, test_user@corp.contoso.com ( *userPrincipalName* )
                -   Distinguished name format, for example, CN=Test
                    User,CN=Users,DC=corp,DC=contoso,DC=com ( *distinguishedName* )
                -   Domain\\\\user_name, for example, Corp\\\\test_user

          
          

    -   For detailed workflow, refer to the documentation for this action.

          
          

-   Enable User

      

    -   This action enables the specified user.

          
          

    -   **<u>Action Parameters</u>** ​

        1.  **Username**
            -   This parameter specifies the username to enable. It is a mandatory action parameter.
            -   **Examples**
                -   Simple user name format, for example, test_user ( *sAMAccountName* in AD
                    nomenclature)
                -   Email address, for example, test_user@corp.contoso.com ( *userPrincipalName* )
                -   Distinguished name format, for example, CN=Test
                    User,CN=Users,DC=corp,DC=contoso,DC=com ( *distinguishedName* )
                -   Domain\\\\user_name, for example, Corp\\\\test_user

          
          

    -   For detailed workflow, refer to the documentation for this action.

          
          

-   List User Groups

      

    -   This action lists the groups that the user is a member of.

          
          

    -   **<u>Action Parameters</u>** ​

        1.  **Username**
            -   This parameter specifies the username to fetch the groups it belongs to. It is a
                mandatory action parameter.
            -   **Examples**
                -   Simple user name format, for example, test_user ( *sAMAccountName* in AD
                    nomenclature)
                -   Email address, for example, test_user@corp.contoso.com ( *userPrincipalName* )
                -   Distinguished name format, for example, CN=Test
                    User,CN=Users,DC=corp,DC=contoso,DC=com ( *distinguishedName* )
                -   Domain\\\\user_name, for example, Corp\\\\test_user

          
          

-   Change System OU

      

    -   This action changes the organizational unit of the system.

          
          

    -   **<u>Action Parameters</u>** ​

        1.  **Hostname**
            -   This parameter specifies the hostname. It is a mandatory action parameter.
            -   **Example**
                -   Hostname format (e.g. test_computerdata1 ( *name* in AD nomenclature))
        2.  **OU**
            -   This parameter is used to change the organizational unit(OU) of the system. It is a
                mandatory action parameter.
            -   **Example**
                -   Distinguished name format, for example,
                    OU=ShawOU2,OU=ShawOU,DC=corp,DC=contoso,DC=com ( *distinguishedName* )

          
          

-   Set System Attribute

      

    -   This action sets the value of an attribute of a computer/system.

          
          

    -   **<u>Action Parameters</u>** ​

        1.  **Hostname**
            -   This parameter specifies the hostname for which we need to set the attribute. It is
                a mandatory action parameter.
            -   **Example**
                -   Hostname format (e.g. test_computerdata1 ( *name* in AD nomenclature))
        2.  **Attribute Name and Attribute Value**
            -   These are the required parameters. Attribute Name specifies the name of the
                attribute which needs to be modified. Attribute Value specifies the value which
                needs to be set.

                  
                  

            -   **Example**
                -   To set the country code: Attribute Name: "countrycode" and Attribute Value: 79

          
          

-   Get User Attributes

      

    -   This action lists the attributes for the specified user.

          
          

    -   **<u>Action Parameters</u>** ​

        1.  **Username**
            -   This parameter specifies the username or attribute value which needs to be matched.
                It is a mandatory action parameter.
            -   **Examples**
                -   Simple user name format, for example, test_user ( *sAMAccountName* in AD
                    nomenclature)
                -   Email address, for example, test_user@corp.contoso.com ( *userPrincipalName* )
                -   Distinguished name format, for example, CN=Test
                    User,CN=Users,DC=corp,DC=contoso,DC=com ( *distinguishedName* )
                -   Domain\\\\user_name, for example, Corp\\\\test_user
        2.  **Attribute**
            -   This parameter specifies the attribute name to match.
            -   **Example**
                -   If we want to match a user with an *employeeID* of 10001, set the **attribute**
                    parameter as **employeeID** and the **username** parameter as **10001** . An
                    error is reported if the attribute (employeeID in this example) is not found on
                    the LDAP server. More than one user matching is also reported as an error.
        3.  **Fields**
            -   This parameter fetches the fields specified. It supports a comma-separated list of
                fields. By default, "useraccountcontrol", "badpwdcount", "pwdlastset", and
                "lastlogon" fields are fetched along with the mentioned fields. If one or more or
                all the mentioned fields are invalid, the action will still pass and will display
                the default fields' values.
            -   **Example**
                -   For fetching only specific fields: "samaccountname,useraccountcontrol"

          
          

    -   **<u>Scenarios</u>**

        -   **Valid keys -** "displayname", "distinguishedname", "lastlogoff", "logoncount",
            "memberof", "accountexpires", "badpasswordtime", "countrycode", "objectcategory",
            "objectclass", "objectguid", "objectsid", "primarygroupid", "userprincipalname",
            "whenchanged", "whencreated", "cn", "codepage", "dscorepropagationdata", "givenname",
            "instancetype", "name", "samaccountname", "samaccounttype", "sn", "usnchanged",
            "usncreated", "logonhours", "telephonenumber", "manager", "title", "company",
            "department", "mail", "streetaddress", "l", "st", "co", "postalcode", "postofficebox"
        -   **Required Keys -** "useraccountcontrol", "badpwdcount", "pwdlastset", "lastlogon"
        -   If the user has provided "all" in fields parameter, LDAP will fetch all the fields for
            the provided hostname.
        -   If the user has provided comma-separated values for fields parameter, LDAP will fetch
            the required keys and provided fields after validating it from valid keys.
        -   If the user has not provided any value in the fields parameter, then by default LDAP
            will fetch the values of valid keys and the required keys.

          
          

-   Get System Attributes

      

    -   This action lists the attributes of a computer/system.

          
          

    -   **<u>Action Parameters</u>** ​

        1.  **Hostname**
            -   This parameter specifies the hostname for which we need to get the attributes. It is
                a mandatory action parameter.
            -   **Example**
                -   Hostname format (e.g. test_computerdata1 ( *name* in AD nomenclature))
        2.  **Fields**
            -   This parameter fetches the fields specified. It supports a comma-separated list of
                fields. By default, "operatingsystem", "operatingsystemversion",
                "operatingsystemservicepack", "useraccountcontrol", "badpwdcount", "pwdlastset", and
                "lastlogon" fields are fetched along with the mentioned fields. If one or more or
                all the mentioned fields are invalid, the action will still pass and will display
                the default fields' values.
            -   **Examples**
                -   To fetch all the fields: Fields = "all"
                -   For fetching only specific fields: Fields = "samaccountname,displayname"

          
          

    -   **<u>Scenarios</u>**

        -   **Valid keys -** "name", "dnshostname", "distinguishedname", "objectcategory",
            "objectclass", "objectguid", "countrycode", "lastlogoff", "lastlogon",
            "lastlogontimestamp", "localpolicyflags", "logoncount", "netbootguid",
            "netbootmirrordatafile", "objectsid", "primarygroupid", "displayname", "cn",
            "pwdlastset", "samaccountname", "samaccounttype", "accountexpires", "badpasswordtime",
            "badpwdcount", "codepage", "dscorepropagationdata", "instancetype",
            "iscriticalsystemobject", "ms-ds-creatorsid", "serviceprincipalname", "usnchanged",
            "usncreated", "useraccountcontrol", "whenchanged", "whencreated"
        -   **Required Keys -** "operatingsystem", "operatingsystemversion",
            "operatingsystemservicepack", "useraccountcontrol", "badpwdcount", "pwdlastset",
            "lastlogon"
        -   If the user has provided "all" in fields parameter, LDAP will fetch all the fields for
            the provided hostname.
        -   If the user has provided comma-separated values for fields parameter, LDAP will fetch
            the required keys and provided fields after validating it from valid keys.
        -   If the user has not provided any value in the fields parameter, then by default LDAP
            will fetch the values of valid keys and the required keys.

          
          

    -   For detailed workflow, refer to the documentation for this action.

          
          

-   Set Password

      

    -   This action sets the password provided by the user.

          
          

    -   **<u>Action Parameters</u>** ​

        1.  **Username**
            -   This parameter specifies the username for which we need to change the password. It
                is a mandatory action parameter.
            -   **Examples**
                -   Simple user name format, for example, test_user ( *sAMAccountName* in AD
                    nomenclature)
                -   Email address, for example, test_user@corp.contoso.com ( *userPrincipalName* )
                -   Distinguished name format, for example, CN=Test
                    User,CN=Users,DC=corp,DC=contoso,DC=com ( *distinguishedName* )
                -   Domain\\\\user_name, for example, Corp\\\\test_user
        2.  **New Password**
            -   This parameter is used to set the new password. It is a mandatory action parameter.
            -   **Example**
                -   New Password: abc@123

          
          

-   Reset Password

      

    -   This action forces the user to change the password on the next login.

          
          

    -   **<u>Action Parameters</u>** ​
        1.  **Username**
            -   This parameter specifies the username for which we need to enforce change password
                on next login. It is a mandatory action parameter.
            -   **Examples**
                -   Simple user name format, for example, test_user ( *sAMAccountName* in AD
                    nomenclature)
                -   Email address, for example, test_user@corp.contoso.com ( *userPrincipalName* )
                -   Distinguished name format, for example, CN=Test
                    User,CN=Users,DC=corp,DC=contoso,DC=com ( *distinguishedName* )
                -   Domain\\\\user_name, for example, Corp\\\\test_user

          

    -   Once the password is reset, the user is required to log in and enters the new password
        interactively. Therefore, Auto Login (from Application) will fail.

          
          

-   Get Users

      

    -   This action lists the users based on the parameters provided.

    -   The default value of page size in action and LDAP server is 1000. If you want to check the
        page size on the LDAP server follow [these](#steps-to-view-page-size) steps.

    -   LDAP will throw an error if the page-size in the LDAP server is less than the total users.
        If you want to change the page size on the LDAP server follow
        [these](#steps-to-change-page-size) steps.

          
          

    -   **<u>Action Parameters</u>** ​

        1.  **Object Name**
            -   This parameter specifies the object name for which we need to list the users. If the
                object name is not provided, it will set the object name as Users.
        2.  **Object Class**
            -   This parameter specifies the object class for which we need to list the users. If
                the object class is not provided, it will set the object class as the container.
            -   **Example**
                -   Object Class is a value list. Hence, the user has to choose from "container",
                    "organizational unit", or "group".
        3.  **All Users**
            -   This parameter is used to list all the users while ignoring all the other
                parameters.

          
          
