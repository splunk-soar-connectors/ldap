[comment]: # "Auto-generated SOAR connector documentation"
# LDAP

Publisher: Splunk  
Connector Version: 1\.2\.48  
Product Vendor: Microsoft  
Product Name: Windows Server  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.6\.19142  

This app implements various investigative, contain, correct, and generic actions that can be carried out on an AD server

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

          
          


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Windows Server asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**username** |  required  | string | Administrator username
**password** |  required  | password | Administrator password
**force\_ssl** |  optional  | boolean | Force use of SSL
**server** |  required  | string | Server IP/Hostname

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity\. This action logs into the device to check the connection and credentials  
[disable user](#action-disable-user) - Disables the specified user  
[enable user](#action-enable-user) - Enables the specified user  
[list user groups](#action-list-user-groups) - Get the groups that the user is a member of  
[change system ou](#action-change-system-ou) - Change the OU of a computer/system  
[set system attribute](#action-set-system-attribute) - Set the value of an attribute of a computer/system  
[get user attributes](#action-get-user-attributes) - Gets the attributes of a user  
[get system attributes](#action-get-system-attributes) - Gets the attributes of a computer/system  
[set password](#action-set-password) - Set the password of a user  
[reset password](#action-reset-password) - Force the user to change the password at the next logon  
[get users](#action-get-users) - Get the list of users  

## action: 'test connectivity'
Validate the asset configuration for connectivity\. This action logs into the device to check the connection and credentials

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'disable user'
Disables the specified user

Type: **contain**  
Read only: **False**

The action supports the following formats as input for <b>username</b>\: <ul> <li>Simple user name format, for example, test\_user \(<i>sAMAccountName</i> in AD nomenclature\)</li> <li>Email address, for example, test\_user\@corp\.contoso\.com \(<i>userPrincipalName</i>\)</li> <li>Distinguished name format, for example, CN=Test User,CN=Users,DC=corp,DC=contoso,DC=com \(<i>distinguishedName</i>\)</li> <li>Domain\\user\_name, for example, Corp\\test\_user</li> </ul><b>Action functional workflow</b><ul><li>This action will first find the user DN\(distinguish name\) using a filter of Hostname which is provided by the user as a parameter</li> <li>Now it will search for the userAccountControl parameter for provided DN\.</li> <li>If the userAccountControl parameter is not none and action identifier is disable\_user then it will modify the user state to disable mode</li> </ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**username** |  required  | Username to disable | string |  `user name`  `ldap distinguished name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.username | string |  `user name`  `ldap distinguished name` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'enable user'
Enables the specified user

Type: **correct**  
Read only: **False**

The action supports the following formats as input for <b>username</b>\: <ul> <li>Simple user name format, for example, test\_user \(<i>sAMAccountName</i> in AD nomenclature\)</li> <li>Email address, for example, test\_user\@corp\.contoso\.com \(<i>userPrincipalName</i>\)</li> <li>Distinguished name format, for example, CN=Test User,CN=Users,DC=corp,DC=contoso,DC=com \(<i>distinguishedName</i>\)</li> <li>Domain\\user\_name, for example, Corp\\test\_user</li> </ul><b>Action functional workflow</b><ul><li>This action will first find the user DN\(distinguish name\) using a filter of Hostname which is provided by the user as a parameter</li> <li>Now it will search for the userAccountControl parameter for provided DN\.</li> <li>If the userAccountControl parameter is not none and action identifier is enable\_user then it will modify the user state to enable mode</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**username** |  required  | Username to enable | string |  `user name`  `ldap distinguished name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.username | string |  `user name`  `ldap distinguished name` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list user groups'
Get the groups that the user is a member of

Type: **investigate**  
Read only: **True**

The action supports the following formats as input for <b>username</b>\: <ul> <li>Simple user name format, for example, test\_user \(<i>sAMAccountName</i> in AD nomenclature\)</li> <li>Email address, for example, test\_user\@corp\.contoso\.com \(<i>userPrincipalName</i>\)</li> <li>Distinguished name format, for example, CN=Test User,CN=Users,DC=corp,DC=contoso,DC=com \(<i>distinguishedName</i>\)</li> <li>Domain\\user\_name, for example, Corp\\test\_user</li> </ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**username** |  required  | Username \(to get groups it belongs to\) | string |  `user name`  `ldap distinguished name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.username | string |  `user name`  `ldap distinguished name` 
action\_result\.data\.\*\.group | string | 
action\_result\.summary\.total\_groups | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'change system ou'
Change the OU of a computer/system

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ou** |  required  | OU to change to | string | 
**hostname** |  required  | Hostname | string |  `host name`  `ldap distinguished name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hostname | string |  `host name`  `ldap distinguished name` 
action\_result\.parameter\.ou | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'set system attribute'
Set the value of an attribute of a computer/system

Type: **generic**  
Read only: **False**

<b>Action Functional workflow</b><ul><li>This action will first find the machine DN\(distinguish name\) using a filter of Hostname which is provided by the user as a parameter\.</li> <li>After that, it will search for the current value of a given attribute name provided as a parameter in action\.</li> <li>If a provided attribute value is the same as the current attribute value then attribute value remains as it is\. But if the attribute value is different then modify the value of the attribute\. </li> </ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**attribute\_value** |  required  | Attribute value to set | string | 
**hostname** |  required  | Hostname \(to set the attribute of\) | string |  `host name`  `ldap distinguished name` 
**attribute\_name** |  required  | Attribute name to modify | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.attribute\_name | string | 
action\_result\.parameter\.attribute\_value | string | 
action\_result\.parameter\.hostname | string |  `host name`  `ldap distinguished name` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get user attributes'
Gets the attributes of a user

Type: **investigate**  
Read only: **True**

By default, useraccountcontrol, badpwdcount, pwdlastset, and lastlogon fields are fetched along with the mentioned fields or the internally pre\-defined fields based on the scenario\. If one or more or all the mentioned fields are invalid, the action will still pass and will display the default fields' values\.<br/> The action supports the following formats as input for <b>username</b>\: <ul> <li>Simple user name format, for example, test\_user \(<i>sAMAccountName</i> in AD nomenclature\)</li> <li>Email address, for example, test\_user\@corp\.contoso\.com \(<i>userPrincipalName</i>\)</li> <li>Distinguished name format, for example, CN=Test User,CN=Users,DC=corp,DC=contoso,DC=com \(<i>distinguishedName</i>\)</li> <li>Domain\\user\_name, for example, Corp\\test\_user</li> </ul>In addition to the above formats and attributes that are matched against, the action also supports matching against an arbitrary attribute, the name of which can be specified in the <b>attribute</b> parameter\. For example, to match a user with an <i>employeeID</i> of 10001, set the <b>attribute</b> parameter as <b>employeeID</b> and the <b>username</b> parameter as <b>10001</b>\. An error is reported if the attribute \(employeeID in this example\) is not found on the LDAP server\. More than one user matching is also reported as an error\. Please see the ldap\_app playbook in the community repo for example\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**username** |  required  | Username or Attribute value to match | string |  `user name`  `ldap distinguished name` 
**attribute** |  optional  | Attribute name to match | string | 
**fields** |  optional  | Get fields \(comma\-separated\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.attribute | string | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.username | string |  `user name`  `ldap distinguished name` 
action\_result\.data\.\*\.accountexpires | string | 
action\_result\.data\.\*\.badpasswordtime | string | 
action\_result\.data\.\*\.badpwdcount | string | 
action\_result\.data\.\*\.cn | string | 
action\_result\.data\.\*\.co | string | 
action\_result\.data\.\*\.codepage | string | 
action\_result\.data\.\*\.company | string | 
action\_result\.data\.\*\.countrycode | string | 
action\_result\.data\.\*\.department | string | 
action\_result\.data\.\*\.displayname | string | 
action\_result\.data\.\*\.distinguishedname | string |  `ldap distinguished name` 
action\_result\.data\.\*\.dscorepropagationdata | string | 
action\_result\.data\.\*\.givenname | string | 
action\_result\.data\.\*\.instancetype | string | 
action\_result\.data\.\*\.l | string | 
action\_result\.data\.\*\.lastlogoff | string | 
action\_result\.data\.\*\.lastlogon | string | 
action\_result\.data\.\*\.logoncount | string | 
action\_result\.data\.\*\.mail | string |  `email` 
action\_result\.data\.\*\.manager | string | 
action\_result\.data\.\*\.memberof | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.objectcategory | string | 
action\_result\.data\.\*\.objectclass | string | 
action\_result\.data\.\*\.objectguid | string | 
action\_result\.data\.\*\.objectsid | string | 
action\_result\.data\.\*\.postOfficeBox | string | 
action\_result\.data\.\*\.postalcode | string | 
action\_result\.data\.\*\.primarygroupid | string | 
action\_result\.data\.\*\.pwdlastset | string | 
action\_result\.data\.\*\.samaccountname | string |  `user name` 
action\_result\.data\.\*\.samaccounttype | string | 
action\_result\.data\.\*\.sn | string | 
action\_result\.data\.\*\.st | string | 
action\_result\.data\.\*\.streetaddress | string | 
action\_result\.data\.\*\.telephoneNumber | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.useraccountcontrol | string | 
action\_result\.data\.\*\.userprincipalname | string |  `email` 
action\_result\.data\.\*\.usnchanged | string | 
action\_result\.data\.\*\.usncreated | string | 
action\_result\.data\.\*\.whenchanged | string | 
action\_result\.data\.\*\.whencreated | string | 
action\_result\.summary\.bad\_password\_count | string | 
action\_result\.summary\.last\_logon | string | 
action\_result\.summary\.password\_last\_set | string | 
action\_result\.summary\.state | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get system attributes'
Gets the attributes of a computer/system

Type: **investigate**  
Read only: **True**

By default, operatingsystem, operatingsystemversion, operatingsystemservicepack, useraccountcontrol, badpwdcount, pwdlastset, and lastlogon fields are fetched along with the mentioned fields or the internally pre\-defined fields based on the scenario\. If one or more or all the mentioned fields are invalid, the action will still pass and will display the default fields' values\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**fields** |  optional  | Get fields \(comma\-separated\) | string | 
**hostname** |  required  | Hostname to query the attributes of | string |  `host name`  `ldap distinguished name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.hostname | string |  `host name`  `ldap distinguished name` 
action\_result\.data\.\*\.accountexpires | string | 
action\_result\.data\.\*\.badpasswordtime | string | 
action\_result\.data\.\*\.badpwdcount | string | 
action\_result\.data\.\*\.cn | string | 
action\_result\.data\.\*\.codepage | string | 
action\_result\.data\.\*\.countrycode | string | 
action\_result\.data\.\*\.displayname | string | 
action\_result\.data\.\*\.distinguishedname | string |  `ldap distinguished name` 
action\_result\.data\.\*\.dnshostname | string |  `host name` 
action\_result\.data\.\*\.dscorepropagationdata | string | 
action\_result\.data\.\*\.instancetype | string | 
action\_result\.data\.\*\.iscriticalsystemobject | string | 
action\_result\.data\.\*\.lastlogoff | string | 
action\_result\.data\.\*\.lastlogon | string | 
action\_result\.data\.\*\.lastlogontimestamp | string | 
action\_result\.data\.\*\.localpolicyflags | string | 
action\_result\.data\.\*\.logoncount | string | 
action\_result\.data\.\*\.ms\-ds\-creatorsid | string | 
action\_result\.data\.\*\.name | string |  `host name` 
action\_result\.data\.\*\.netbootguid | string | 
action\_result\.data\.\*\.netbootmirrordatafile | string | 
action\_result\.data\.\*\.objectcategory | string | 
action\_result\.data\.\*\.objectclass | string | 
action\_result\.data\.\*\.objectguid | string | 
action\_result\.data\.\*\.objectsid | string | 
action\_result\.data\.\*\.operatingsystem | string | 
action\_result\.data\.\*\.operatingsystemservicepack | string | 
action\_result\.data\.\*\.operatingsystemversion | string | 
action\_result\.data\.\*\.primarygroupid | string | 
action\_result\.data\.\*\.pwdlastset | string | 
action\_result\.data\.\*\.samaccountname | string | 
action\_result\.data\.\*\.samaccounttype | string | 
action\_result\.data\.\*\.serviceprincipalname | string | 
action\_result\.data\.\*\.useraccountcontrol | string | 
action\_result\.data\.\*\.usnchanged | string | 
action\_result\.data\.\*\.usncreated | string | 
action\_result\.data\.\*\.whenchanged | string | 
action\_result\.data\.\*\.whencreated | string | 
action\_result\.summary\.bad\_password\_count | string | 
action\_result\.summary\.last\_logon | string | 
action\_result\.summary\.os | string | 
action\_result\.summary\.password\_last\_set | string | 
action\_result\.summary\.state | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'set password'
Set the password of a user

Type: **contain**  
Read only: **False**

Note that a user currently logged in will stay logged in\. The LDAP server may refuse to accept the password unless the connection is over SSL\. <p class="warn">Exercise caution when using this Action\. The password may be kept and logged in cleartext\.</p>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**username** |  required  | Username to change password of | string |  `user name`  `ldap distinguished name` 
**new\_password** |  required  | Password string to set | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.new\_password | string | 
action\_result\.parameter\.username | string |  `user name`  `ldap distinguished name` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'reset password'
Force the user to change the password at the next logon

Type: **contain**  
Read only: **False**

Once the password is reset, the user is required to log in and enters the new password interactively\. Therefore auto logins \(from applications\) will fail\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**username** |  required  | Username to enforce 'change password at next logon' | string |  `user name`  `ldap distinguished name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.username | string |  `user name`  `ldap distinguished name` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get users'
Get the list of users

Type: **investigate**  
Read only: **True**

Use this action to get a list of users\. Only users that have email addresses will be returned\. If the <b>all\_users</b> parameter is set to <b>True</b>, the action will list all users in the enterprise and ignore the <b>object\_name</b> and <b>object\_class</b> parameters\. To list users that belong to a specific <i>group</i>, <i>organizationalUnit</i> or <i>container</i> \(known as objects\), set the <b>all\_users</b> parameter to <b>False</b> and the <b>object\_name</b> and <b>object\_class</b> \(both required in this case\) parameters to the required values\.<br>A list of object classes is supplied, one of which the user may choose as the value for the <b>object\_class</b> parameter, these are\:<br><ul><li>container</li><li>organizationalUnit</li><li>group</li></ul>When executing the action from a playbook, the author can look up arbitrary object classes by supplying the desired class as a string for the <b>object\_class</b> parameter\.<br>The action will first query the system for the <i>dn</i> of the object \(using the name and class\)\. The action will fail if an object with the specified <b>object\_name</b> belonging to the specified <b>object\_class</b> is not found\. If the <b>object\_class</b> equals "group" then the returned group will be used to populate a query filter that returns all users with a <i>memberOf</i> attribute equal to the full <i>dn</i> of the group with that name\. If the <b>object\_class</b> is any string other than "group" \(such as "container" or "organizationalUnit"\) then the <i>dn</i> returned from the first query will be used as the <i>base\_dn</i> of the User query\.<br>Some examples\:<br><ul><li>To find all users in an Organizational Unit\(OU\) named <i>UsersOU</i><br><b>all\_users</b>\: False<br><b>object\_name</b>\: UsersOu<br><b>object\_class</b>\: organizationalUnit<br></li><li>To find all users in a Container named <i>Users</i> \(Default container found in most AD installations\)<br><b>all\_users</b>\: False<br><b>object\_name</b>\: Users<br><b>object\_class</b>\: container<br></li><li>To find all users in the group named <i>Enterprise Admins</i> \(one of the most powerful default AD groups\)<br><b>all\_users</b>\: False<br><b>object\_name</b>\: Enterprise Admins<br><b>object\_class</b>\: group<br></li><li>To find all users in the complete enterprise<br><b>all\_users</b>\: True<br></li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**object\_name** |  optional  | Object name to query the users of | string | 
**object\_class** |  optional  | Object class to query the users of | string | 
**all\_users** |  optional  | Get All Users \(other params are ignored if set\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.all\_users | boolean | 
action\_result\.parameter\.object\_class | string | 
action\_result\.parameter\.object\_name | string | 
action\_result\.data\.\*\.displayname | string | 
action\_result\.data\.\*\.dn | string |  `ldap distinguished name` 
action\_result\.data\.\*\.emails | string |  `email` 
action\_result\.data\.\*\.emails\.0 | string |  `email` 
action\_result\.data\.\*\.samaccountname | string | 
action\_result\.summary\.total\_users | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 