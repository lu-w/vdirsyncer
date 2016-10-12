#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import json
import logging
import re

from enum import Enum

import pytz
import icalendar

from .base import Item, Storage
from .. import exceptions
from ..utils import expand_path
from ..utils.http import request

lotus_logger = logging.getLogger(__name__)

USERAGENT = 'vdirsyncer'

CAL_URL = """{baseurl}/mail/{calendar}.nsf/iNotes/Proxy/?OpenDocument&\
Form=s_ReadViewEntries_JSON&Count=-1&KeyType=time&TZType=UTC&\
StartKey={StartKey}&UntilKey={UntilKey}&\
PresetFields=DBQuotaInfo;1,DBQuotaInfo;1,FolderName;(%24Calendar),hc;\
%24151|%24152|%24153|%24154|%24160|%24UserData|%24Cal"""
DETAIL_URL = """{baseurl}/mail/{calendar}.nsf/($Calendar)/{uid}/\
?OpenDocument&Form=l_JSVars&PresetFields=s_HandleAttachmentNames;\
1,s_HandleMime;1,s_OpenUI;1,s_HideRemoteImage;1,ThisStartDate;\
{ThisStartDate},s_ProcessRR;1"""
LOGIN_FAILED_PATTERN = "<!DOCTYPE HTML PUBLIC.*Please identify yourself.*"


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

    You can set a timerange to synchronize with the parameters ``start_date``
    and ``end_date``. Inside those parameters, you can use any Python
    expression to return a valid :py:class:`datetime.datetime` object. For
    example, the following would synchronize the timerange from one year in the
    past to one year in the future::

        start_date = datetime.now() - timedelta(days=365)
        end_date = datetime.now() + timedelta(days=365)

    Either both or none have to be specified. The default is to synchronize
    from 8 weeks in past to 8 weeks in future.

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
    :param start_date: Start date of timerange to show, default -inf.
    :param end_date: End date of timerange to show, default +inf.
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
        event = icalendar.Event()
        event.add('uid', '{}@{}.ibm'.format(self.unid, self.position))

        if freebusy:
            event.add('summary', 'busy')
        else:
            event.add('summary', self.subject)
            if self.type == CalEntryType.MEETING:
                event.add('categories', 'Meeting')
            elif self.type == CalEntryType.ANNIVERSARY:
                event.add('categories', 'Anniversary')

        if self.all_day_event:
            # all day events have a date only
            event.add('dtstart', self.from_date.date())
            event.add('dtend', self.to_date.date())
        else:
            event.add('dtstart', self.from_date)
            event.add('dtend', self.to_date)

        if not freebusy and self.created_by:
            event.add('organzier', self.created_by)

		# event.add('dtstamp', datetime(2005,4,4,0,10,0,tzinfo=pytz.utc))
        if not freebusy and self.location:
            event.add('location', self.location)

        if self.status.lower() in ("angenommen", "confirmed"):
            event.add('status', 'confirmed')
        elif self.status.lower() in ("ghosts", "tentative",):
            event.add('status', 'tentative')
        elif self.status.lower() in ("cancled",):
            event.add('status', 'cancled')

        calendar = icalendar.Calendar()
        calendar.add_component(event)
        return calendar

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

    start_date = None
    end_date = None

    storage_name = 'lotusnotesweb'
    read_only = True
    _repr_attributes = ('username', 'url', 'calendars', 'freebusy')
    _items = None

    def __init__(self, url, username='', password='', verify=True, auth=None,
                 useragent=USERAGENT, verify_fingerprint=None, auth_cert=None,
                 start_date=None, end_date=None,
                 calendars=None, freebusy=None,
                 **kwargs):
        super(LotusNotesWebStorage, self).__init__(**kwargs)

        self._settings = {
            'auth': prepare_auth(auth, username, password),
            'cert': prepare_client_cert(auth_cert),
            'latin1_fallback': False,
        }
        self._settings.update(prepare_verify(verify, verify_fingerprint))

        if (start_date is None) != (end_date is None):
            raise exceptions.UserError('If start_date is given, '
                                       'end_date has to be given too.')
        elif start_date is not None and end_date is not None:
            namespace = dict(datetime.__dict__)
            namespace['start_date'] = self.start_date = \
                (eval(start_date, namespace)
                 if isinstance(start_date, (bytes, str))
                 else start_date)
            self.end_date = \
                (eval(end_date, namespace)
                 if isinstance(end_date, (bytes, str))
                 else end_date)
        else:
            self.start_date = datetime.date.today()
            self.start_date -= datetime.timedelta(weeks=8)
            self.end_date = datetime.date.today()
            self.end_date += datetime.timedelta(weeks=8)

        self.username, self.password = username, password
        self.useragent = useragent

        if calendars is None:
            self.calendars = (username,)
        else:
            self.calendars = calendars
        self.freebusy = freebusy

        self.baseurl = url
        self.verbose = False

    def _calendar_url(self, calendar):
        url = CAL_URL.format(
            baseurl=self.baseurl,
            calendar=calendar,
            StartKey=self.start_date.strftime(LotusCalEntry.DATEFORMAT),
            UntilKey=self.end_date.strftime(LotusCalEntry.DATEFORMAT)
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
            if re.match(LOGIN_FAILED_PATTERN, content) is not None:
                lotus_logger.debug("Login failed")
                raise exceptions.UserError("login failed.")

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
                if self.verbose:
                    entry.dump()
                item = Item(
                    # entry.to_ics_event(self.freebusy).to_ical().decode("utf-8").replace('\r\n', '\n').strip()
                    entry.to_ics_event(self.freebusy).to_ical().decode("utf-8").strip()
                )
                if self.verbose:
                    print(item.raw)
                etag = item.hash
                self._items[item.ident] = item, etag

        lotus_logger.debug("got {} items".format(len(self._items.items())))
        return ((href, etag) for href, (item, etag) in self._items.items())

    def get(self, href):
        if self._items is None:
            self.list()

        try:
            return self._items[href]
        except KeyError:
            raise exceptions.NotFoundError(href)
