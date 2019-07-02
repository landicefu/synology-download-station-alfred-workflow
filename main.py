#!/usr/bin/python
# encoding: utf-8

import os
import sys
import datetime

from workflow import Workflow3, PasswordNotFound
from SynologyQuickConnect import (resolve, ping, Host, requests)

PASSWORD_KEY = 'synology_nas'
ERROR_LOG_PATH = os.getcwd() + '/error.log'
SUCCESS_LOG_PATH = os.getcwd() + '/success.log'

TASK_LIST_URL = '%s/webapi/DownloadStation/task.cgi?api=SYNO.DownloadStation.Task&version=1&method=list'
DOWNLOAD_URL = '%s/webapi/DownloadStation/task.cgi'
AUTHORIZE_URL = '%s/webapi/auth.cgi?api=SYNO.API.Auth&version=2&method=login&session=DownloadStation&format=cookie'


def get_datetime_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def append_file(path, content):
    with open(path, 'a+') as f:
        f.write("\n" + content)


def get_host_url():  # type: () -> str
    host = resolve(os.getenv('qcid'), True)
    if host is None:
        return None
    else:
        return 'https://%s:%d' % (host.address, host.port)


def download(wf, url):  # type: (Workflow3, str) -> None
    log(wf, 'start download from: %s' % url)
    username = os.getenv('username')
    password = wf.get_password(PASSWORD_KEY)
    host_url = wf.cached_data('host_url', lambda: None, 900)  # type: str
    if host_url is None:
        host_url = get_host_url()
    else:
        path = host_url.split(':')
        is_https = path[0] == 'https'
        address = path[1].replace('//', '')
        port = path[2]
        log(wf, 'found cached host: ' + host_url)
        result = ping(Host(address, int(port)), is_https, 30)
        if result is None:
            host_url = get_host_url()

    if host_url is None:
        append_file(ERROR_LOG_PATH, '[cannot find host]\n' + url)
        log(wf, 'cannot find host')
        return
    else:
        wf.cache_data('host_url', host_url)
    log(wf, 'host is resolved: ' + host_url)

    sid = wf.cached_data('sid', lambda: None, 900)
    if sid is not None:
        result = requests.get(TASK_LIST_URL % host_url, params={'_sid': sid}, verify=False).json()
        if not result['success']:
            sid = None
    if sid is None:
        result = requests.get(AUTHORIZE_URL % host_url, params={
            'account': username,
            'passwd': password
        }, verify=False, timeout=60).json()
        if result['success']:
            sid = result['data']['sid']
            wf.cache_data('sid', sid)
        else:
            log(wf, 'not authorized')
            append_file(ERROR_LOG_PATH, '[%s][fail to download] %s\n%s' % (get_datetime_str(), result, url))
            return

    payload = {
        'api': 'SYNO.DownloadStation.Task',
        'version': 1,
        'method': 'create',
        'uri': url,
        '_sid': sid,
        'session': 'DownloadStation',
    }
    result = requests.post(DOWNLOAD_URL % host_url, data=payload, verify=False, timeout=60)
    result_json = result.json()
    if result_json['success']:
        log(wf, 'Download added')
        append_file(SUCCESS_LOG_PATH, '[%s] %s' % (get_datetime_str(), url))
    else:
        log(wf, SUCCESS_LOG_PATH)
        log(wf, ERROR_LOG_PATH)
        log(wf, "Error downloading:\n%s\n%s" % (url, result.text))
        append_file(ERROR_LOG_PATH, '[%s][fail to download] %s\n%s' % (get_datetime_str(), result.text, url))


def log(wf, _str):  # type: (Workflow3, str) -> None
    wf.logger.debug(_str)


def main(wf):  # type: (Workflow3) -> None

    args = wf.args

    # execution
    if len(args) > 1 and args[0] == 'exec':
        log(wf, "args = %s" % args)
        if args[1] == 'reset':
            wf.setvar('qcid', '', True)
            wf.setvar('username', '', True)
            wf.clear_cache()
            wf.delete_password(PASSWORD_KEY)
        elif args[1] == 'save_account':
            qcid = os.getenv('qcid') or ''
            username = os.getenv('username') or ''
            password = os.getenv('password') or ''
            if qcid != '' and username != '' and password != '':
                log(wf, 'Save Account Info - %s/%s' % (qcid, username))
                wf.setvar('qcid', qcid, True)
                wf.setvar('username', username, True)
                wf.save_password(PASSWORD_KEY, password)
        elif args[1] == 'download':
            url = args[2]
            qcid = os.getenv('qcid')
            username = os.getenv('username')
            password = wf.get_password(PASSWORD_KEY)
            if qcid != '' and username != '' and password != '':
                try:
                    download(wf, url)
                except Exception as e:
                    append_file(ERROR_LOG_PATH, '[%s][fail to download] %s\n%s' % (get_datetime_str(), e, url))
                    raise e
        elif args[1] == 'clear_log':
            os.remove(SUCCESS_LOG_PATH)
            os.remove(ERROR_LOG_PATH)
        elif args[1] == 'open_err_log':
            os.system('open \"%s\"' % ERROR_LOG_PATH)
        elif args[1] == 'open_success_log':
            os.system('open \"%s\"' % SUCCESS_LOG_PATH)
        return None

    try:
        wf.get_password(PASSWORD_KEY)
        if len(args) == 0 or (len(args) == 1 and args[0] == ''):
            wf.add_item(title=u'Download', subtitle=u'Please enter the url or magnet link to be download')
            wf.add_item(title=u'Reset', subtitle=u'Reset Your NAS Connection', valid=True, arg='exec reset')
            if os.path.isfile(ERROR_LOG_PATH):
                wf.add_item(title=u'Open Error Log', valid=True, arg='exec open_err_log')
            if os.path.isfile(SUCCESS_LOG_PATH):
                wf.add_item(title=u'Open Success Log', valid=True, arg='exec open_success_log')
            if os.path.isfile(ERROR_LOG_PATH) or os.path.isfile(SUCCESS_LOG_PATH):
                wf.add_item(title=u'Clear Logs', subtitle=u'Remove error logs and success logs', valid=True,
                            arg='exec clear_log')

        else:
            wf.add_item(title=u'Download', subtitle=u'Download Magnet Link', valid=True,
                        arg='exec download %s' % ' '.join(args))
    except PasswordNotFound:
        wf.add_item(title=u'Setup', subtitle=u'Setup Connection to Your NAS', valid=True, arg='setup')
    wf.send_feedback()


if __name__ == '__main__':
    sys.exit(Workflow3().run(main))
