import os, traceback, sys
import hashlib
import logging
from logging.handlers import SysLogHandler
import ldap, ldap.sasl
from v3logic import host_credentials
import v3logic.shared.base_classes

import datetime

import struct

from collections import namedtuple

class DirectoryServices(v3logic.shared.base_classes.shell_command_base):
""" This assumes that you have python-ldap and the krb 5 libraries installed
python ldap can be installed by: apt-get install python-ldap
the mit-kerberos libs can be installed using : apt-get install  libsasl2-modules-gssapi-mit.
It is also assumed that you have krb5 configured in /etc/krb5.conf"""

    host = None
    logger = None
    connection = None
    user_hash = None
    COMMAND = "kinit -p %s"
    ENV_VAR = 'KRB5CCNAME'
    CONFIG_FILE = '/etc/v3sys/v3sys.conf'
    DATE_PARSE_STR = '%m/%d/%y %H:%M:%S'

    def __init__(self, host):
        self.host = host
        self._init_logging()

    def _init_logging(self):
        """Initialize logging"""
        self.logger = logging.getLogger('ad_auth')
        if len(self.logger.handlers) == 0:
            self.logger.setLevel(logging.WARNING)
            syslog = SysLogHandler(address='/dev/log')
            formatter = logging.Formatter('%(name)s: %(filename)s:%(funcName)s:%(lineno)d %(levelname)s %(message)s')
            syslog.setFormatter(formatter)
            self.logger.addHandler(syslog)

    def __set_environment(self, user_hash):
        if user_hash:
            path = '/tmp/%s' % user_hash
        elif self.user_hash:
            path = '/tmp/%s' % self.user_hash
        else:
            raise ValueError('No hash for kerberos cache file: %s ' % user_hash)
        os.environ[self.ENV_VAR] = path

    def connect(self, user_hash=None):
        self.__set_environment(user_hash)
        self.connection = ldap.initialize(self.host)
        self.connection.set_option(ldap.OPT_REFERRALS,0)
        sasl = ldap.sasl.sasl({}, 'GSSAPI')
        self.connection.sasl_interactive_bind_s('',sasl)

    def authenticate(self, username, password):
        command = self.COMMAND % username
        self.user_hash = hashlib.md5(username).hexdigest()
        self.logger.debug("Setting environment to %s" % self.user_hash)
        try:
            os.environ[self.ENV_VAR] = '/tmp/%s' % self.user_hash
            self.execute_command_with_args(command, password)
            return self.user_hash
        except Exception as err:
            self.logger.error("Error logging in %s: %s ",
                              username,err)
            self.logger.warn(traceback.format_tb(sys.exc_info()[2]))
            raise err

    def logout(self, user_hash = None):
        try:
            self.connection.unbind()
        except:
            self.logger.info("There was no connection")
        self.__set_environment(user_hash)
        command = 'kdestroy'
        self.execute_command(command)

        try:
            os.remove(path)
        except:
            self.logger.info("The file did not exist")

        os.unsetenv(self.ENV_VAR)

    def search(self, search_string, scope, filterstr='(objectClass=*)',
               attrlist=None):
        return self.connection.search_ext_s(search_string, scope, filterstr,
                                            attrlist)

    def __remove_none_items(self, collection):
        return [item for item in collection if item[0] is not None]

    def get_root_naming_context(self):
        result = self.search('',ldap.SCOPE_BASE)
        if len(result) > 0:
            return result[0][1]['rootDomainNamingContext'][0]

    def get_user_base(self):
        return 'CN=Users,%s' % self.get_root_naming_context()

    def is_ticket_valid(self, user_hash = None):
        self.__set_environment(user_hash)
        command = "klist"
        raw_str = self.execute_command(command)
        raw_line = raw_str.split("\n")[4]
        date_str = raw_line.split('  ')[1]
        exp_date = datetime.datetime.strptime(date_str,
                                              self.DATE_PARSE_STR)
        return exp_date > datetime.datetime.now()

    def _package_value(self, result, attr_list):
        cleaned_dict = dict()
        for key in attr_list:
            if key in result:
                if key == 'objectSid' or key == 'objectGUID':
                    cleaned_dict[key] = self._parse_sid(result[key][0])
                elif key == 'memberOf':
                    cleaned_dict[key] = result[key]
                elif len(result[key]) > 1:
                    cleaned_dict[key] = result[key]
                else:
                    cleaned_dict[key] = result[key][0]
            else:
                cleaned_dict[key] = None
        return cleaned_dict

    def _package_values(self, results, object_name, attr_list):
        results = self.__remove_none_items(results)
        results = [result[1] for result in results]
        values = list()
        value_tuple = namedtuple(object_name, attr_list)
        for result in results:
            value_dict = self._package_value(result, attr_list)
            val = value_tuple(**value_dict)
            values.append(val)
        return values

    def list_groups(self):
        base = self.get_root_naming_context()
        attrlist =['distinguishedName','sAMAccountName',
                   'objectSid','cn','name']
        results = self.search(base, ldap.SCOPE_SUBTREE, '(objectCategory=group)',
                           attrlist = attrlist)
        return self._package_values(results, 'groups', attrlist)

    def _get_user_dn(self, username):
        base =self.get_root_naming_context()
        group = self.search(base, ldap.SCOPE_SUBTREE,
                            '(&(objectCategory=User)(sAMAccountName=%s))' %
                            username, attrlist=['distinguishedName'])
        return group[0][1]['distinguishedName'][0]

    def _get_group_dn(self, group_name):
        base =self.get_root_naming_context()
        group = self.search(base, ldap.SCOPE_SUBTREE,
                            '(&(objectCategory=group)(name=%s))' % group_name,
                            attrlist = ['distinguishedName'])
        return group[0][1]['distinguishedName'][0]

    def is_user_in_group(self, username, group_name):
        group_dn = self._get_group_dn(group_name)
        base = self.get_root_naming_context()
        results = self.search(base, ldap.SCOPE_SUBTREE,
                    '(&(memberOf:1.2.840.113556.1.4.1941:=%s)(sAMAccountName=%s))' % (group_dn, username),
                              attrlist = ['distinguishedName'])
        result = self.__remove_none_items(results)
        return len(result) > 0

    def list_users_groups(self, username):
        base = self.get_root_naming_context()
        user_dn = self._get_user_dn(username)
        attrlist =['distinguishedName','sAMAccountName',
           'objectSid','cn','name']
        result = self.search(base, ldap.SCOPE_SUBTREE,
                             '(&(objectCategory=group)(member=%s))' % user_dn,
                             attrlist = attrlist)
        return self._package_values(result, 'groups', attrlist)

    def list_ous(self):
        base = self.get_root_naming_context()
        return self.__remove_none_items(self.search(base, ldap.SCOPE_ONELEVEL,
                                                    '(OU=*)'))
    def find_users(self, search_str):
        base = self.get_user_base()
        attrlist =['distinguishedName','sAMAccountName',
           'objectSid','cn','name', 'memberOf','objectClass']
        query = '(&(objectClass=user)(|(sAMAccountName=%s*)(name=%s*)(sn=%s*)))'
        results = self.search(base,ldap.SCOPE_SUBTREE,
                             query % (search_str, search_str, search_str),
                             attrlist = attrlist)
        return self._package_values(results, 'user' ,attrlist)

    def find_users_and_groups(self, search_str):
        base = self.get_user_base()
        attrlist =['distinguishedName','sAMAccountName',
           'objectSid','cn','name', 'memberOf','objectClass']
        query = '(&(|(objectClass=user)(objectClass=group))(|(sAMAccountName=%s*)(name=%s*)(sn=%s*)))'
        results = self.search(base,ldap.SCOPE_SUBTREE,
                             query % (search_str, search_str, search_str),
                             attrlist = attrlist)
        return self._package_values(results, 'principal' ,attrlist)

    def find_groups(self, search_str):
        base = self.get_user_base()
        attrlist =['distinguishedName','sAMAccountName',
           'objectSid','cn','name', 'memberOf','objectClass']
        query = '(&(objectClass=group)(|(sAMAccountName=%s*)(name=%s*)(sn=%s*)))'
        results = self.search(base,ldap.SCOPE_SUBTREE,
                             query % (search_str, search_str, search_str),
                             attrlist = attrlist)
        return self._package_values(results, 'group' ,attrlist)


    def list_group_users(self, group_dn):
        attrlist =['distinguishedName','sAMAccountName',
           'objectSid','cn','name', 'memberOf']
        result = self.search(self.get_root_naming_context(),
                           ldap.SCOPE_SUBTREE,
                           '(&(objectCategory=user)(memberOf:1.2.840.113556.1.4.1941:=%s))' % group_dn,
                           attrlist)
        result = self.__remove_none_items(result)
        return self._package_values(result, 'users', attrlist)

    def _parse_sid(self, guid):
        # more on the structure of the guid can be found at
        # http://en.wikipedia.org/wiki/Security_Identifier
        revision_level = ord(guid[0])
        number_sid_ids = ord(guid[1])
        id_auth_value = struct.unpack('!Q','\x00\x00%s' % guid[2:8])[0]
        identifiers = [str(struct.unpack('<I',guid[8+4*i:12+4*i])[0]) for i in range(number_sid_ids)]
        domain_identifier = '-'.join(identifiers)
        return 'S-%d-%d-%s' % (revision_level, id_auth_value, domain_identifier)
