#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import json
import re

from enum import Enum

import ics

from .base import Item, Storage
from .. import exceptions
from ..utils import expand_path
from ..utils.http import request

USERAGENT = 'vdirsyncer'

CAL_URL = """{baseurl}/mail/{calendar}.nsf/iNotes/Proxy/?OpenDocument&\
Form=s_ReadViewEntries_JSON&Count=-1&KeyType=time&TZType=UTC&\
StartKey={StartKey}&UntilKey={UntilKey}&\
PresetFields=DBQuotaInfo;1,DBQuotaInfo;1,FolderName;(%24Calendar),hc;\
%24151|%24152|%24153|%24154|%24160|%24UserData|%24Cal"""


def prepare_auth(auth, username, password):
    if username and password:
        if auth == 'basic' or auth is None:
            return (username, password)
        elif auth == 'digest':
            from requests.auth import HTTPDigestAuth
            return HTTPDigestAuth(username, password)
        elif auth == 'guess':
            try:
                from requests_toolbelt.auth.guess import GuessAuth
            except ImportError:
                raise exceptions.UserError(
                    'Your version of requests_toolbelt is too '
                    'old for `guess` authentication. At least '
                    'version 0.4.0 is required.'
                )
            else:
                return GuessAuth(username, password)
        else:
            raise exceptions.UserError('Unknown authentication method: {}'
                                       .format(auth))
    elif auth:
        raise exceptions.UserError('You need to specify username and password '
                                   'for {} authentication.'.format(auth))
    else:
        return None


def prepare_verify(verify, verify_fingerprint):
    if isinstance(verify, (str, bytes)):
        verify = expand_path(verify)
    elif not isinstance(verify, bool):
        raise exceptions.UserError('Invalid value for verify ({}), '
                                   'must be a path to a PEM-file or boolean.'
                                   .format(verify))

    if verify_fingerprint is not None:
        if not isinstance(verify_fingerprint, (bytes, str)):
            raise exceptions.UserError('Invalid value for verify_fingerprint '
                                       '({}), must be a string or null.'
                                       .format(verify_fingerprint))
    elif not verify:
        raise exceptions.UserError(
            'Disabling all SSL validation is forbidden. Consider setting '
            'verify_fingerprint if you have a broken or self-signed cert.'
        )

    return {
        'verify': verify,
        'verify_fingerprint': verify_fingerprint,
    }


def prepare_client_cert(cert):
    if isinstance(cert, (str, bytes)):
        cert = expand_path(cert)
    elif isinstance(cert, list):
        cert = tuple(map(prepare_client_cert, cert))
    return cert


LOTUSNOTESWEB_STORAGE_PARAMETERS = '''
    :param username: Username for authentication.
    :param password: Password for authentication.
    :param verify: Verify SSL certificate, default True. This can also be a
        local path to a self-signed SSL certificate. See :ref:`ssl-tutorial`
        for more information.
    :param verify_fingerprint: Optional. SHA1 or MD5 fingerprint of the
        expected server certificate. See :ref:`ssl-tutorial` for more
        information.
    :param auth: Optional. Either ``basic``, ``digest`` or ``guess``. The
        default is preemptive Basic auth, sending credentials even if server
        didn't request them. This saves from an additional roundtrip per
        request. Consider setting ``guess`` if this causes issues with your
        server.
    :param auth_cert: Optional. Either a path to a certificate with a client
        certificate and the key or a list of paths to the files with them.
    :param useragent: Default ``vdirsyncer``.
    :param calendars: which calendars to query. Default ``username``.
    :param freebusy: whether to include subject and location. Default ``username``.
'''


class CalEntryType(Enum):
    APPOINTMENT = 0, "Appointment"
    ANNIVERSARY = 1, "ANNIVERSARY"
    ALL_DAY_EVENT = 2, "ALL_DAY_EVENT"
    MEETING = 3, "MEETING"
    REMINDER = 4, "REMINDER"

    def __new__(cls, value, name):
        member = object.__new__(cls)
        member._value_ = value
        member.fullname = name
        return member

    def __int__(self):
        return self.value


class CalEntryColumn(Enum):
    TYPE = 8, "Type"

    def __new__(cls, value, name):
        member = object.__new__(cls)
        member._value_ = value
        member.fullname = name
        return member

    def __int__(self):
        return self.value


class LotusCalEntry(object):

    """Lotus Notes Calendar Entry Abstraction"""

    DATEFORMAT = "%Y%m%dT%H%M%S,00Z"

    def __init__(self, data):
        """wraps the json data from lotus notes calendar entry and provides nice
        accessors

        :data: TODO

        """
        self._data = data

    @property
    def entrydata(self):
        return self._data.get('entrydata', list())

    @property
    def type(self):
        v = int(self.entrydata[int(CalEntryColumn.TYPE)]['text']['0'])
        return CalEntryType(v)

    @property
    def position(self):
        return self._data.get('@position', None)

    @property
    def noteid(self):
        return self._data.get('@noteid', None)

    @property
    def siblings(self):
        return self._data.get('@siblings', None)

    @property
    def unid(self):
        return self._data.get('@unid', None)

    def _from_date(self):
        if 'datetimelist' in self.entrydata[0]:
            if len(self.entrydata[0]['datetimelist']['datetime']) == 1:
                v = self.entrydata[0]['datetimelist']['datetime'][0]['0']
                return datetime.datetime.strptime(v, self.DATEFORMAT)
        elif 'datetime' in self.entrydata[0]:
            v = self.entrydata[0]['datetime']['0']
            return datetime.datetime.strptime(v, self.DATEFORMAT)
        # for line in self.entrydata:
            # print(line)
        raise KeyError("Entry misses from_date or not parseable")

    @property
    def from_date(self):
        v = self._from_date()
        v = v.replace(tzinfo=pytz.utc)
        if self.all_day_event:
            return v.replace(hour=0, minute=0, second=0, microsecond=0)
        return v

    @property
    def all_day_event(self):
        return self.type in (CalEntryType.ALL_DAY_EVENT,
                             CalEntryType.ANNIVERSARY)

    def _to_date(self):
        if 'datetimelist' in self.entrydata[5]:
            if len(self.entrydata[5]['datetimelist']['datetime']) == 1:
                v = self.entrydata[5]['datetimelist']['datetime'][0]['0']
                return datetime.datetime.strptime(v, self.DATEFORMAT)
        elif 'datetime' in self.entrydata[5]:
            v = self.entrydata[5]['datetime']['0']
            return datetime.datetime.strptime(v, self.DATEFORMAT)
        elif self.all_day_event:
            fd = self.from_date
            # fd = fd.replace(hour=0, minute=0, second=0, microsecond=0)
            return fd + datetime.timedelta(days=1)
        # for line in self.entrydata:
            # print(line)
        raise KeyError("Entry misses from_date or not parseable")

    @property
    def to_date(self):
        v = self._to_date()
        v = v.replace(tzinfo=pytz.utc)
        if self.all_day_event:
            return v.replace(hour=0, minute=0, second=0, microsecond=0)
        return v

    @property
    def subject(self):
        if 'textlist' in self.entrydata[7]:
            return self.entrydata[7]['textlist']['text'][0]['0']
        else:
            return self.entrydata[7]['text']['0']
        # TODO raise

    @property
    def location(self):
        if 'textlist' in self.entrydata[7]:
            if self.type == CalEntryType.MEETING:
                if len(self.entrydata[7]['textlist']['text']) > 2:
                    return self.entrydata[7]['textlist']['text'][1]['0']
            elif self.type == CalEntryType.APPOINTMENT:
                if len(self.entrydata[7]['textlist']['text']) > 1:
                    return self.entrydata[7]['textlist']['text'][1]['0']
            return None
        else:
            return None
        # TODO raise

    @property
    def created_by(self):
        return self.entrydata[9]['text']['0']

    @property
    def status(self):
        return self.entrydata[11]['text']['0']

    def to_ics_event(self, freebusy=False):
        event = ics.Event(
            uid='{}@{}.ibm'.format(self.unid, self.position)
        )
        if freebusy:
            event.name = "busy"
        else:
            event.name = self.subject
        event.begin = self.from_date
        if self.all_day_event:
            event.make_all_day()
        else:
            event.end = self.to_date
        if not freebusy and self.location:
            event.location = self.location
        return event

    def dump(self):
        print("Position:", self.position)
        print("\tentrydata:")
        for line in self.entrydata:
            print("\t\t", line)
        print("\tType:", self.type)
        print("\tAll-Day:", self.all_day_event)
        print("\tNoteid:", self.noteid)
        print("\tuid:", self.unid)
        print('\tFrom:', self.from_date)
        print('\tUntil:', self.to_date)
        print('\tSubject:', self.subject)
        print('\tLocation:', self.location)
        print('\tCreated By:', self.created_by)
        print('\tStatus:', self.status)


class LotusNotesWebStorage(Storage):
    __doc__ = '''
    Use a simple ``.ics`` file (or similar) from the web.

    :param url: URL to the ``.ics`` file.
    ''' + LOTUSNOTESWEB_STORAGE_PARAMETERS + '''

    A simple example::

        [pair holidays]
        a = company_local
        b = company_remote
        collections = null

        [storage company_local]
        type = filesystem
        path = ~/.config/vdir/calendars/company/
        fileext = .ics

        [storage company_remote]
        type = lotusnotesweb
        url = https://domino.example.com
        username = loginname
        calendars = [ "loginname", "coworker" ]
        freebusy = false
        password = password
    '''

    storage_name = 'lotusnotesweb'
    read_only = True
    _repr_attributes = ('username', 'url', 'calendars', 'freebusy')
    _items = None

    def __init__(self, url, username='', password='', verify=True, auth=None,
                 useragent=USERAGENT, verify_fingerprint=None, auth_cert=None,
                 calendars=None, freebusy=None,
                 **kwargs):
        super(LotusNotesWebStorage, self).__init__(**kwargs)

        self._settings = {
            'auth': prepare_auth(auth, username, password),
            'cert': prepare_client_cert(auth_cert),
            'latin1_fallback': False,
        }
        self._settings.update(prepare_verify(verify, verify_fingerprint))

        self.username, self.password = username, password
        self.useragent = useragent

        if calendars is None:
            self.calendars = (username,)
        else:
            self.calendars = calendars
        self.freebusy = freebusy

        self.baseurl = url

    def _calendar_url(self, calendar, start=None, until=None):
        if until is None:
            until = datetime.date.today()
            until += datetime.timedelta(weeks=8)
        if start is None:
            start = until - datetime.timedelta(weeks=8)

        url = CAL_URL.format(
            baseurl=self.baseurl,
            calendar=calendar,
            StartKey=start.strftime(LotusCalEntry.DATEFORMAT),
            UntilKey=until.strftime(LotusCalEntry.DATEFORMAT)
        )
        return url

    def _default_headers(self):
        return {'User-Agent': self.useragent}

    def list(self):
        self._items = {}
        for calendar in self.calendars:
            url = self._calendar_url(calendar)
            req_data = request('GET', url, headers=self._default_headers(),
                               **self._settings)
            # recoding
            content = req_data.content.decode('utf-8').replace('\n', '')
            # remove the comment
            content = re.sub("/[*][^*]*[*]/", "", content)
            # fix the json string
            content = re.sub("{entries:", "{\"entries\":", content)
            content = re.sub(r",[ ]*dbQuotaInfo:{[^}]*}", "", content)
            # parse the json string
            content = json.loads(content)

            # navigate to the real content
            if 'entries' not in content:
                raise "no entries"
            content = content['entries']
            if 'viewentry' not in content:
                raise "no viewentries"
            content = content['viewentry']

            # parse each item json -> ICS -> vdir.Item
            for entry in content:
                entry = LotusCalEntry(entry)
                item = Item(str(entry.to_ics_event(self.freebusy)))
                etag = item.hash
                self._items[item.ident] = item, etag

        return ((href, etag) for href, (item, etag) in self._items.items())

    def get(self, href):
        if self._items is None:
            self.list()

        try:
            return self._items[href]
        except KeyError:
            raise exceptions.NotFoundError(href)
